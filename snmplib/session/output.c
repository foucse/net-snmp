/*******************************
 *
 *      session/session.c
 *
 *      Net-SNMP library - SNMP Session interface
 *
 *	Routines for sending outgoing requests
*
 *******************************/

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>

#include "transport/snmp_transport.h"	/* Early to avoid double defn of c64 */

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/error.h>
#include <net-snmp/protocol_api.h>

#include "session/session.h"

#include "snmp_debug.h"
#include "snmp_logging.h"
#include "default_store.h"


int _session_send(netsnmp_session *sess, netsnmp_pdu *pdu);
void xdump (const u_char *, size_t, const char *);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/session_api.h>)
                 *
                 **************************************/
                /** @package session_api */


   /**
    */
int
session_send(netsnmp_session         *sess,
             netsnmp_pdu     *pdu,
             NetSnmpCallback  callback,
             void            *cb_data)
{
    int          requestID;

    if (NULL == sess) {
        return 0;
    }
    session_clear_errors(sess);

    if (0 > _session_send(sess, pdu)) {
        return 0;	/* FAILED */
    }

    requestID = pdu->request;

    /*
     * If we expect a response, then add this
     *   to the list of pending requests.
     * Otherwise free successful(?) unacknowledged requests
     * Then return the request ID.
     */
    if (UCD_MSG_FLAG_EXPECT_RESPONSE & pdu->flags) {
        return session_save_request(sess, pdu, callback, cb_data);
    } else {
        if (0 != requestID) {	/* XXX - or regardless ? */
            pdu_free(pdu);
        }
    }
    return requestID;
}


#ifdef NOT_HERE
int
session_synch_send(netsnmp_session *sess,
             netsnmp_pdu     *pdu,
             NetSnmpCallback  callback,
             void            *cb_data)
{
    int waiting = 0;
    int reqID, numfds, block, count;
    fd_set fdset;
    struct timeval timeout, *tvp;

    if (NULL == sess) {
        return -1;
    }

    reqID = session_send(sess, pdu, callback, cb_data);
    if (0 == reqID) {
        return -1;	/* Send failed */
    }


    waiting = 1;
    while( waiting ) {

        /*
         * determine what's waiting to be read
         */
	numfds = 0;
	FD_ZERO(&fdset);
	block = SNMPBLOCK;
	tvp = &timeout;
	timerclear(tvp);
	session_select(sess, &numfds, &fdset, tvp, &block);
        if (1 == block) {
            tvp = NULL;
        }
        count = select(numfds, &fdset, 0, 0, tvp);

        if (0 < count) {
            session_read(sess, &fdset);
        } else if (0 == count) {
            session_timeout(sess);
        } else {
            /*
             * Handle errors
             */
            waiting = 0;	/* XXX - ??? */
        }

    }
    return 0;
}
#endif


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package session_internals */


int
session_save_request(netsnmp_session *sess,
		     netsnmp_pdu     *pdu,
		     NetSnmpCallback *callback,
		     void            *cb_data)
{
    netsnmp_request *rp;
    int timeout;

    if ((NULL == sess) ||
        (NULL == pdu)) {
        session_set_errors(sess, SNMPERR_BAD_SENDTO, errno, "");
        return 0;
    }

    if (UCD_MSG_FLAG_PDU_TIMEOUT & pdu->flags) {
      timeout = pdu->timeout * 1000000L;	/* XXX - or use direct? */
    } else {
      timeout = sess->timeout;
    }
    rp = request_new(sess, pdu, callback, cb_data, timeout);
    if (NULL == rp) {
        session_set_errors(sess, SNMPERR_GENERR, 0, "");
        return 0;
    }

    request_add_to_list(sess, rp);
    return pdu->request;		/* to indicate success */
}


int
_session_send(netsnmp_session *sess,
             netsnmp_pdu      *pdu)
{
    netsnmp_buf *buf;
    netsnmp_transport *transport;
    int          result;
    int          save_flag;
    char        *addrtxt;

    if (NULL == sess) {
        return -1;
    }
    transport = sess->transport;
    if (NULL == transport) {
        DEBUGMSGTL(("session_send","send fail: no transport...\n"));
        return -1;
    }
    if (NULL == pdu) {
        DEBUGMSGTL(("session_send","send fail: no PDU...\n"));
        session_set_errors(sess, SNMPERR_NULL_PDU, 0, "");
        return -1;
    }

    buf = buffer_new(NULL, 2048, NETSNMP_BUFFER_RESIZE|NETSNMP_BUFFER_REVERSE);

    if (sess->hooks && sess->hooks->hook_build) {
        result = sess->hooks->hook_build(sess, pdu, buf);
    } else {
        result = snmp_build_pdu(sess, pdu, buf);
    }
    if (0 > result) {
        DEBUGMSGTL(("session_send","encoding failure\n"));
        buffer_free(buf);
        return -1;
    }

   
    /*
     * Make sure we don't send anything that is larger than the
     * msgMaxSize specified in a PDU received on this session...
     */
    if ((0 != sess->sndMsgMaxSize) &&
        (buf->cur_len > sess->sndMsgMaxSize)) {

        DEBUGMSGTL(("session_send",
		"length of packet (%lu) exceeds session maximum (%lu)\n",
		buf->cur_len, sess->sndMsgMaxSize));
        session_set_errors(sess, SNMPERR_TOO_LONG, 0, "");
        buffer_free(buf);
        return -1;
    }

    /*
     * ... or than the underlying transport can handle.
     */
    if ((0 != transport->msgMaxSize) &&
        (buf->cur_len > transport->msgMaxSize)) {

        DEBUGMSGTL(("session_send",
		"length of packet (%lu) exceeds transport maximum (%lu)\n",
		buf->cur_len, transport->msgMaxSize));
        session_set_errors(sess, SNMPERR_TOO_LONG, 0, "");
        buffer_free(buf);
        return -1;
    }


    save_flag = buf->flags;
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_DUMP_PACKET)) {
        if (transport->f_fmtaddr != NULL) {
            addrtxt = transport->f_fmtaddr(transport,
                                           pdu->transport_data, pdu->transport_data_length);
            if (addrtxt != NULL) {
                snmp_log(LOG_DEBUG, "\nSending %d bytes to %s\n", buf->cur_len, addrtxt);
                free(addrtxt);
            } else {
                snmp_log(LOG_DEBUG, "\nSending %d bytes to <UNKNOWN>\n", buf->cur_len);
            }
        }
        xdump(buffer_string(buf), buf->cur_len, "");
    }

    /*
     * Send the message
     */
    result = transport->f_send(transport, buffer_string(buf), buf->cur_len,
			     &(pdu->transport_data),
			     &(pdu->transport_data_length));

    buf->flags = save_flag;
    buffer_free(buf);
    if (0 > result) {
        session_set_errors(sess, SNMPERR_BAD_SENDTO, errno, "");
        return -1;
    }

    return 0;

}
