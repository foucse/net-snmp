/*******************************
 *
 *      session/synch.c
 *
 *      Net-SNMP library - SNMP Session interface
 *
 *	Routines for handling synchronous requests
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


#define STAT_SUCCESS 0
#define STAT_TIMEOUT 1
#define STAT_ERROR   2
typedef struct netsnmp_synch_state_s {
    int          waiting;
    int          status;
    int          reqid;
    netsnmp_pdu *pdu;
} netsnmp_synch_state;

int
synch_input(int op,
            netsnmp_session *session,
            int reqid,
            void *pdu,
            void *magic);


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/session_api.h>)
                 *
                 **************************************/
                /** @package session_api */


netsnmp_pdu *
synch_send(netsnmp_session *sess,
           netsnmp_pdu     *pdu,
           NetSnmpCallback *callback)
{
    netsnmp_synch_state lstate, *state;
    NetSnmpCallback *saved_callback = NULL;
    void            *saved_magic    = NULL;
    int reqID, numfds, block, count;
    fd_set fdset;
    struct timeval timeout, *tvp;


    if (NULL == sess) {
        return NULL;
    }

    state = &lstate;
    memset((void*)state, 0, sizeof(netsnmp_synch_state));

    /*
     * Replace any original callback handlers with our own
     *   'synchronous request' handler.
     * Save the original callback information, so we can
     *   restore it again afterwards.
     */

    if (NULL == sess->hooks) {
        sess->hooks = hooks_new(NULL, NULL, NULL, NULL, NULL, 
                                callback, (void*)state);
    } else {
        saved_callback = sess->hooks->callback;
        saved_magic    = sess->hooks->callback_magic;
        sess->hooks->callback       = callback;
        sess->hooks->callback_magic = (void*)state;
    }

    reqID = session_send(sess, pdu, callback, (void*)state);
    if (0 == reqID) {
        return NULL;	/* Send failed */
    }


    state->waiting = 1;
    state->reqid   = reqID;
    while( state->waiting ) {

        /*
         * determine what's waiting to be read
         */
	numfds = 0;
	FD_ZERO(&fdset);
	block = SNMPBLOCK;
	tvp = &timeout;
	tvp->tv_sec  = 0;
	tvp->tv_usec = 0;
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
            state->waiting = 0;		/* XXX - ??? */
        }

    }

    
    sess->hooks->callback       = saved_callback;
    sess->hooks->callback_magic = saved_magic;
    return state->pdu;
}


netsnmp_pdu *
synch_response(netsnmp_session *sess,
               netsnmp_pdu *pdu)
{
    return synch_send(sess, pdu, synch_input);
}


#ifdef OLD_STYLE
int
synch_response(netsnmp_session *sess,
               netsnmp_pdu *pdu,
               netsnmp_pdu **response)
{

    netsnmp_pdu *resp;

    resp = synch_send(sess, pdu, synch_input);
    if (NULL != response ) {
        *response = resp;
    }

    if (NULL == resp) {
        return -1;
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
synch_input(int op,
            netsnmp_session *session,
            int reqid,
            void *void_pdu,
            void *magic)
{
    netsnmp_pdu *pdu = (netsnmp_pdu*)void_pdu;
    netsnmp_synch_state *state = (netsnmp_synch_state *)magic;


    /*
     * Handle incoming REPORTs separately.
     */
/* XXX - ToDo
    if (pdu && (SNMP_MSG_REPORT == pdu->command)) {
        return synch_report_input(op, session, reqid, pdu, magic);
    }
 */

    /*
     * Is this what we were expecting?
     */
    if (reqid != state->reqid) {
        return 0;	/* No! */
    }

    state->waiting = 0;

    switch(op) {
    case SNMP_CALLBACK_OP_RECEIVED_MESSAGE:
        if ((SNMP_MSG_RESPONSE == pdu->command) ||
            (SNMP_MSG_REPORT   == pdu->command)) {	/* XXX - ??? */
            state->pdu    = pdu_copy(pdu);
            state->status = STAT_SUCCESS;
            session_clear_errors(session);
        }
        break;

    case SNMP_CALLBACK_OP_TIMED_OUT:
        state->pdu = NULL;
        state->status = STAT_TIMEOUT;
        session_set_errors(session, SNMPERR_TIMEOUT, 0, "");
        break;

    case SNMP_CALLBACK_OP_DISCONNECT:
        state->pdu = NULL;
	state->status = STAT_ERROR;
        session_set_errors(session, SNMPERR_ABORT, 0, "");
        break;

    default:
        state->pdu = NULL;
	state->status = STAT_ERROR;
        session_set_errors(session, SNMPERR_GENERR, 0, "");
        break;

    }
    return 1;
}
