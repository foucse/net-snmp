/*******************************
 *
 *      session/input.c
 *
 *      Net-SNMP library - SNMP Session interface
 *
 *	Routines for reading and processing incoming requests
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

#include "ucd/ucd_api.h"		/* Early to avoid double defn of oid */
#include "transport/snmp_transport.h"	/* Early to avoid double defn of c64 */

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/error.h>
#include <net-snmp/protocol_api.h>

#include "session/session.h"
#include "snmpv3/snmpv3.h"
#include "protocol/asn1_parse.h"

#include "snmp_debug.h"
#include "snmp_logging.h"
#include "default_store.h"

int session_accept(netsnmp_session *sp, netsnmp_transport *transport);
int session_process_packet(netsnmp_session   *sp,
                              netsnmp_transport *transport,
                              void *opaque, int olength,
                              netsnmp_buf    *rxbuf,
                              int length);
int session_process_stream_packet(netsnmp_session   *sp,
                              netsnmp_transport *transport,
                              void *opaque, int olength,
                              netsnmp_buf    *rxbuf,
                              int length);

void xdump (const u_char *, size_t, const char *);
int _buffer_extend(netsnmp_buf * buf, int increase);

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
session_read(netsnmp_session *sess, fd_set *fdset)
{
#define NETSNMP_RXBUFFER_LEN	65536

    netsnmp_transport *transport;
    netsnmp_buf    *rxbuf;
    int length;
    int olength = 0, rc = 0;
    void *opaque = NULL;
  
    if (NULL == sess) {
        return 0;
    }
    transport = sess->transport;
    if (NULL == transport) {
        return 0;
    }

    if ((NULL == fdset) ||
       !(FD_ISSET(transport->sock, fdset))) {
            DEBUGMSGTL(("sess_read", "not reading %d (fdset %p set %d)\n",
		        transport->sock, fdset,
		        fdset?FD_ISSET(transport->sock, fdset):-9));
        return 0;
    }

    session_clear_errors(sess);

    /*
     * Accept a new connection on a (stream-oriented) listening socket
     */
    if (transport->flags & SNMP_TRANSPORT_FLAG_LISTEN) {
        return session_accept(sess, transport);
    }


    /*
     * Ensure we have a full-size buffer to receive into,
     * and read in the incoming data.
     */
    if (NULL != sess->rxbuf) {
        rxbuf = sess->rxbuf;
        (void)_buffer_extend(rxbuf, NETSNMP_RXBUFFER_LEN - rxbuf->max_len);
    } else {
        rxbuf = buffer_new(NULL, NETSNMP_RXBUFFER_LEN, NETSNMP_BUFFER_RESIZE);
    }


    length = transport->f_recv(transport, rxbuf->string  + rxbuf->cur_len,
                                          rxbuf->max_len - rxbuf->cur_len,
                                          &opaque, &olength);

    if (length == -1) {
        session_set_errors(sess, SNMPERR_BAD_RECVFROM, errno, strerror(errno));
        free(rxbuf);
        if (opaque != NULL) {
            free(opaque);
        }
        return -1;
    }
    rxbuf->cur_len += length;


    /*
     * Process the data we've just read in
     */
    if (transport->flags & SNMP_TRANSPORT_FLAG_STREAM) {
        rc = session_process_stream_packet(sess, transport, opaque, olength, rxbuf, length);
    } else {
        rc = session_process_packet(sess, transport, opaque, olength, rxbuf, length);
    }
    buffer_free(rxbuf);
    return rc;
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package session_internals */


int
session_accept(netsnmp_session *sess, snmp_transport *transport)
{
    int data_sock;
    snmp_transport  *new_transport;
    netsnmp_session *new_session;

    if (NULL == transport) {
        return -1;
    }
      
    data_sock = transport->f_accept(transport);
    if (0 > data_sock) {
        session_set_errors(sess, SNMPERR_BAD_RECVFROM, errno, strerror(errno));
        return -1;
    }


      /*  We've successfully accepted a new stream-based connection.  It's not 
	  too clear what should happen here if we are using the single-session 
	  API at this point.  Basically a "session accepted" callback is
	  probably needed to hand the new session over to the application.

	  However, for now, as in the original snmp_api, we will ASSUME that
	  we're using the traditional API, and simply add the new session to
	  the list.  Note we don't have to get the Session list lock here,
	  because under that assumption we already hold it (this is also why
	  we don't just use snmp_add).

	  The moral of the story is: don't use listening stream-based
	  transports in a multi-threaded environment because something will go 
	  HORRIBLY wrong (and also that SNMP/TCP is not trivial).

	  Another open issue: what should happen to sockets that have been
	  accept()ed from a listening socket when that original socket is
	  closed?  If they are left open, then attempting to re-open the
	  listening socket will fail, which is semantically confusing.
	  Perhaps there should be some kind of chaining in the transport
	  structure so that they can all be closed.  Discuss.  ;-)  */

    new_transport = snmp_transport_copy(transport);
    if (NULL == new_transport) {
        session_set_errors(sess, SNMPERR_MALLOC, errno, strerror(errno));
        return -1;
    }


    new_transport->sock   = data_sock;
    new_transport->flags &= ~SNMP_TRANSPORT_FLAG_LISTEN;

    new_session = session_new( sess->version, new_transport );
    if (NULL == new_session) {
        new_transport->f_close(new_transport);
        snmp_transport_free(new_transport);
        return 0;	/* XXX - or throw an error? */
    }
        
    new_session->hooks = hooks_copy( sess->hooks );
    session_link( sess, new_session );	/* XXX -  Whatever that means! */
    return 0;
}



int
session_process_stream_packet(netsnmp_session   *sess,
                              netsnmp_transport *transport,
                              void *opaque, int olength,
                              netsnmp_buf    *rxbuf,
                              int length)
{
    netsnmp_buf *pdubuf;
    int pdulen;
    int rc = 0;

    if ((NULL == sess) ||
        (NULL == transport)) {
        return -1;
    }

    if (!(transport->flags & SNMP_TRANSPORT_FLAG_STREAM)) {
        return -1;
    }

    /*
     * Remote end closed connection
     */
    if (0 == length) {
        /*
         * Alert the application if possible.
         */
        if (sess->hooks && sess->hooks->callback) {
            DEBUGMSGTL(("sess_read", "perform callback with op=DISCONNECT\n"));
            (void)sess->hooks->callback(SNMP_CALLBACK_OP_DISCONNECT,
                                        sess, 0, NULL, sess->hooks->callback_magic);
        }

        /*
         * Close socket and mark session for deletion
         */
        DEBUGMSGTL(("sess_read", "fd %d closed\n", transport->sock));    
        transport->f_close(transport);
        buffer_free(rxbuf);
        if (opaque) {
            free(opaque);
        }
        sess->rxbuf = NULL;
        return -1;
    }

    if (NULL == rxbuf) {
        return -1;
    }
    rxbuf->cur_len += length;
    pdubuf = buffer_new(rxbuf->string, rxbuf->cur_len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);

    /*
     * Process the packet(s) currently read in
     */
    while (0 < pdubuf->cur_len) {
        /*
         * Get the expected data length of the first packet
         */
        if (sess->hooks && sess->hooks->check_packet) {
            pdulen = sess->hooks->check_packet(pdubuf->string, pdubuf->cur_len);
        } else {
            pdulen = asn_check_packet(pdubuf->string, pdubuf->cur_len);
        }
      
        DEBUGMSGTL(("sess_read", "  loop packet_len %d, PDU length %d\n",
		  pdubuf->cur_len, pdulen));

        /*
         * Illegal length, drop the connection
         */
        if (NETSNMP_MAX_PACKET_LEN < pdulen) {
            snmp_log(LOG_ERR, "Maximum packet size exceeded in a request.\n");
            transport->f_close(transport);
            if (opaque != NULL) {
                free(opaque);
            }
            return -1;
        }


        /*
         * Do we have the complete packet yet?
         * If not, return and wait for more data to arrive.
         */
        if (pdubuf->cur_len < pdulen) {
            DEBUGMSGTL(("sess_read", "pkt not complete (need %d got %d so far)\n",
	               pdulen, pdubuf->cur_len));
            if (opaque != NULL) {
                free(opaque);
            }
            return 0;		/* XXX - or break out of the loop ??? */
        }


        /*
         * We have at least one complete packet in the buffer now,
         *  (maybe more than one) so let's process it.
         */
        rc = session_process_packet(sess, transport, opaque, olength, pdubuf, length);
				/* XXX - what if this fails ? */
        pdubuf->string  += length;
        pdubuf->cur_len -= length;
        pdubuf->max_len -= length;
    }


    if (0 < pdubuf->cur_len) {
        /*
         * Negative packet lengths should never happen!
         */
        snmp_log(LOG_ERR, "-ve packet_len %d, dropping connection %d\n",
	         pdubuf->cur_len, transport->sock);
        transport->f_close(transport);
        return -1;

    } else if (0 == pdubuf->cur_len) {
        /*
         * This is good.
         * It means that the packet buffer contained one or more
         * complete PDUs.  We don't have to save any data for next time.
         * (The buffer we've been working will be freed when we return).
         */
        sess->rxbuf = NULL;

    } else {
        /*
         * If we get here, then there is a partial PDU left in the buffer.
         * Save this, so that it can be included in the processing when
         * the next incoming request arrives.
         */
        sess->rxbuf = buffer_new(pdubuf->string, pdubuf->cur_len, 0);
    }
    return rc;
}


int
session_process_packet(netsnmp_session   *sess,
                              netsnmp_transport *transport,
                              void *opaque, int olength,
                              netsnmp_buf    *rxbuf,
                              int length)
{
    netsnmp_pdu *pdu;
    int          save_flag;
    char *addrtxt;
    NetSnmpCallback *callback = NULL;
    void *magic = NULL;
    netsnmp_request *rp = NULL;
    int ret = 0;

/*
  struct netsnmp_session *slp = (struct netsnmp_session *)sessp;
  struct request_list *rp, *orp = NULL;
  struct snmp_secmod_def *sptr;
  int ret = 0;
 */
    if ((NULL == sess) ||
        (NULL == transport)) {
        return -1;
    }
  
    save_flag = rxbuf->flags;
    DEBUGMSGTL(("sess_process_packet", "session %p, pkt %p length %d\n",
	      sess, buffer_string(rxbuf), length));

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_DUMP_PACKET)) {
        if (NULL != transport->f_fmtaddr) {
            addrtxt = transport->f_fmtaddr(transport, opaque, olength);
            if (NULL != addrtxt) {
	        snmp_log(LOG_DEBUG, "\nReceived %d bytes from %s\n", length, addrtxt);
	        free(addrtxt);
            } else {
	        snmp_log(LOG_DEBUG, "\nReceived %d bytes from <UNKNOWN>\n", length);
            }
        }
        xdump(buffer_string(rxbuf), rxbuf->cur_len, "");
    }
    rxbuf->flags = save_flag;

    /*
     * Four-stage processing:
     *    pre-parse for transport-level filtering (e.g. IP-address based allow/deny)
     *    parse the incoming data stream into a PDU structure
     *    post-parse to check the validity of this PDU
     *    callback to actually process this PDU
     */
    if (sess->hooks && sess->hooks->hook_pre) {
        if (0 == sess->hooks->hook_pre(sess, transport, opaque, olength)) {
            DEBUGMSGTL(("sess_process_packet", "pre-parse fail\n"));
            return -1;
        }
    }

    if (sess->hooks && sess->hooks->hook_parse) {
        pdu = sess->hooks->hook_parse(rxbuf);
    } else {
        pdu = pdu_parse(rxbuf);
    }
    if (NULL == pdu) {
        DEBUGMSGTL(("sess_process_packet", "parse fail\n"));
        return -1;
    }

    if (sess->hooks && sess->hooks->hook_post) {
        if (0 == sess->hooks->hook_post(sess, pdu)) {
            DEBUGMSGTL(("sess_process_packet", "post-parse fail\n"));
            pdu_free(pdu);
            return -1;
        }
    }


    if (sess->hooks) {
        callback = sess->hooks->callback;
        magic    = sess->hooks->callback_magic;
    }
    if (pdu->flags & UCD_MSG_FLAG_RESPONSE_PDU) {
        rp = session_find_request(sess, pdu);
        if (rp && rp->callback) {
            callback = rp->callback;
            magic    = rp->cb_data;
        }
    }
    if (callback) {
        ret = callback(SNMP_CALLBACK_OP_RECEIVED_MESSAGE,
		       sess, pdu->request, pdu, magic);
		/* XXX - what if this fails ? */
    }
    if (pdu->flags & UCD_MSG_FLAG_RESPONSE_PDU) {
        request_release(sess, pdu, rp);
    }
    pdu_free(pdu);
    return 0;		/* XXX - or ret */
}



netsnmp_request *
session_find_request(netsnmp_session *sess, netsnmp_pdu *pdu)
{
    netsnmp_request *rp;

    if ((NULL == sess)  ||
        (NULL == pdu)) {
        return NULL;
    }

    for (rp = sess->request_head; rp; rp = rp->next) {

      if (pdu->version == SNMP_VERSION_3) {
	/*  msgId must match for v3 messages.  */
	/* XXX - what if v3info == NULL ?? */
	if (rp->message_id != pdu->v3info->msgID) {
	  continue;
	}

	/*  Check that message fields match original, if not, no further
	    processing.  */ 
	if (!snmpv3_verify_msg(rp,pdu)) {
	  break;
	}
      } else {
	if (rp->request_id != pdu->request) {
	  continue;
	}
      }
    }
    return rp;
}


	/* XXX - should this belong in snmpv3/xxx.c ?? */
#include <net-snmp/snmpv3.h>
void
session_handle_report(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_request *rp)
{

    if ((NULL == sess)  ||
        (NULL == rp)  ||
        (NULL == pdu)) {
        return;
    }

    if (SNMP_MSG_REPORT != pdu->command) {
        return;		/* Not interested in this PDU */
    }

    /*
     * Trigger immediate retry on recoverable Reports
     */
    if (SNMPERR_NOT_IN_TIME_WINDOW == sess->snmp_errno) {
        if (rp->retries <= sess->retries) {
            /*
             * increment retry count, to prevent infinite resend
             */
            request_resend(sess, rp, TRUE);
            return;
        }
    } else if (snmpv3_ignore_unauth_reports) {
        return;
    }


    /*
     * Handle engineID discovery
     */
    if ((NULL == sess->userinfo)  ||
        (NULL == sess->v3info)    ||
        (NULL == pdu->userinfo)) {
        return;		/* XXX - is this right? */
    }

    if (NULL == sess->userinfo->sec_engine) {
        sess->userinfo->sec_engine = engine_copy(pdu->userinfo->sec_engine);
        if (NULL == sess->v3info->context_engine) {
            sess->v3info->context_engine = engine_copy(pdu->userinfo->sec_engine);
        }
    }
}


#ifdef NOT_NEEDED
void
pdu_release_security(netsnmp_pdu *pdu)
{
    if ((NULL == pdu) ||
        (NULL == pdu->securityStateRef)) {
        return;
    }

    if ((UCD_MSG_FLAG_RESPONSE_PDU & pdu->flags) ||
        (SNMP_MSG_TRAP2 == pdu->command)) {

        sptr = find_sec_mod(pdu->securityModel);
        if (sptr) {
            if (sptr->pdu_free_state_ref) {
                (*sptr->pdu_free_state_ref)(pdu->securityStateRef);
            } else {
                snmp_log(LOG_ERR, "Security Model %d can't free state references\n",
                         pdu->securityModel);
            }
        } else {
              snmp_log(LOG_ERR, "Can't find security model to free ptr: %d\n",
                       pdu->securityModel);
        }
        pdu->securityStateRef = NULL;
    }
}
#endif
