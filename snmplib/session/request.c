/*******************************
 *
 *      session/session.c
 *
 *      Net-SNMP library - SNMP Session interface
 *
 *	Routines for handling lists of outstanding requests
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

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/error.h>
#include <net-snmp/protocol_api.h>

#include "session/session.h"

int _session_send(netsnmp_session *sess, netsnmp_pdu *pdu);

struct timeval *timeval_difference(struct timeval *first, struct timeval *second);
struct timeval * timeval_min(      struct timeval *first, struct timeval *second);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/session_api.h>)
                 *
                 **************************************/
                /** @package session_api */


netsnmp_request*
request_new(netsnmp_session *sess,
            netsnmp_pdu     *pdu,
            NetSnmpCallback *callback,
            void            *cb_data,
            int              timeout)
{
    netsnmp_request *rp;

    if ((NULL == sess) ||
        (NULL == pdu)) {
        session_set_errors(sess, SNMPERR_BAD_SENDTO, errno, "");
        return NULL;
    }

    rp = (netsnmp_request *)calloc(1, sizeof(netsnmp_request));
    if (NULL == rp) {
        session_set_errors(sess, SNMPERR_BAD_SENDTO, errno, "");
        return NULL;
    }

    /*
     * Set up the request information
     */
    rp->pdu        = pdu;
    rp->request_id = pdu->request;
    if (NULL != pdu->v3info) {
        rp->message_id = pdu->v3info->msgID;
    }
    rp->callback   = callback;
    rp->cb_data    = cb_data;
    rp->retries    = 0;
    (void)request_set_timeout(rp, timeout);

    return rp;
}


int
request_set_timeout(netsnmp_request *rp, int timeout)
{
    struct timeval tv;

    if (NULL == rp) {
        return -1;
    }

    /*
     * Determine when this request should time out
     */
    gettimeofday(&tv, (struct timezone *)0);
    rp->timeout = timeout;
    rp->time    = tv;
    tv.tv_usec += timeout;
    tv.tv_sec  += tv.tv_usec / 1000000L;
    tv.tv_usec %= 1000000L;
    rp->expire  = tv;

    return 0;
}

	/*
	 * XXX - not at all convinced!!!!
	 */

	/* 'timeout' is a relative time, 'expire' is an absolute time. */

/*
 * Currently working on:
 *	Input:	requested timeout
 *		recent "earliest"
 *	Output:	new "earliest"
 *
 * XXX - do we want to query the alarm list here?
 *	Tentative answer:	No.
 *		Do it:
 *			a) in session_select_list
 *			b) in session_select (if !timeout)		
 */
struct timeval *
request_check_timeout(struct timeval *expire, struct timeval *timeout)
{
    struct timeval now, *delta;

    if (NULL ==  expire) {
        return timeout;
    }

    /*
     *  The current idea of the next timeout ('timeout') is a delta time.
     *  The requested timeout ('expire') is an absolute time.
     *  Turn this into a delta, so that we can compare the two.
     */
    gettimeofday(&now, NULL);
    delta = timeval_difference(expire, &now);

    /*
     * Return whichever is the most imminent value
     */
    if (NULL == timeout) {
        return delta;
    }
    return timeval_min(timeout, delta);
}


int
request_resend(netsnmp_session *sess,
               netsnmp_request *rp,
               int inc_retries)
{
    if ((NULL == sess) ||
        (NULL == rp)   ||
        (NULL == rp->pdu)) {
        return -1;
    }

    if (inc_retries) {
        rp->retries++;
    }
    rp->message_id = snmp_get_next_msgid();
    if (rp->pdu->v3info) {
        rp->pdu->v3info->msgID = rp->message_id;
    }

    if (0 > _session_send(sess, rp->pdu)) {
        return -1;	/* FAILED */
    }

    (void)request_set_timeout(rp, rp->timeout);
    return 0;
}


void
request_release(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_request *rp)
{

    if ((NULL == sess)||
        (NULL == rp)  ||
        (NULL == pdu)) {
        return;
    }


    /*
     * Unlink this request from the list....
     */
    if (NULL != rp->prev) {
        rp->prev->next   = rp->next;
    }
    if (NULL != rp->next) {
        rp->next->prev   = rp->prev;
    }
    if (rp == sess->request_head) {
        sess->request_head = rp->next;
    }
    if (rp == sess->request_tail) {
        sess->request_tail = rp->prev;
    }

    /*
     *  ... and free the request
     */
    pdu_free(rp->pdu);
    free((char *)rp);
    return;
}


void
request_add_to_list(netsnmp_session *sess,
                    netsnmp_request *rp)
{

    if ((NULL == sess) ||
        (NULL == rp))  {
        return;
    }

#ifdef WILL_NEED_TO_HANDLE_LOCKING
    /*
     * XXX - Lock should be per-session, rather than global
     */
    snmp_res_lock(MT_LIBRARY_ID, MT_LIB_SESSION);
#endif

    if (NULL == sess->request_head) {
        sess->request_head = rp;
    }
    if (NULL != sess->request_tail) {
        sess->request_tail->next = rp;
    }
    rp->prev = sess->request_tail;
    sess->request_tail = rp;

#ifdef WILL_NEED_TO_HANDLE_LOCKING
    snmp_res_unlock(MT_LIBRARY_ID, MT_LIB_SESSION);
#endif
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package session_internals */


struct timeval *
timeval_difference(struct timeval *first, struct timeval *second)
{
    static struct timeval delta;

    delta.tv_sec  = first->tv_sec  - second->tv_sec;
    delta.tv_usec = first->tv_usec - second->tv_usec;

    if (0 > delta.tv_usec) {
        delta.tv_usec += 1000000;
        delta.tv_sec  -= 1;
    }

	/*
	 *  Are we happy with assuming first < second?
	 *    (and returning a negative result otherwise)
	 *  Or do we want the following....
	 */
/*
    if (0 > delta.tv_sec) {
        delta.tv_sec  = 0;
        delta.tv_usec = 100;	// 'almost' now
    }
*/

    return &delta;		/* XXX - scope/multi-thread problems.... */
}


struct timeval *
timeval_min(struct timeval *first, struct timeval *second)
{
    if (NULL == first) {
         return second;
    }
    if (NULL == second) {
         return first;
    }

    if (first->tv_sec  < second->tv_sec) {
        return first;
    }
    if (second->tv_sec < first->tv_sec) {
        return second;
    }
    if (first->tv_usec < second->tv_usec) {
        return first;
    }
    return second;
}
