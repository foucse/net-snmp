/*******************************
 *
 *      session/session.c
 *
 *      Net-SNMP library - SNMP Session interface
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
#include <net-snmp/snmpv3.h>
#include <net-snmp/community_api.h>

#include "session/session.h"

#include "snmp_debug.h"
#include "snmp_logging.h"


extern snmp_transport	*_snmp_transport_parse	(char* peername, int local_port, 
                                                 struct snmp_session* session);
struct timeval *alarm_get_next_delay(void);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/session_api.h>)
                 *
                 **************************************/
                /** @package session_api */


   /**
    *  Create a new session structure with the given version,
    *    and endpoint transport.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_session *
session_new(int version, netsnmp_transport *transport)
{
    netsnmp_session  *sess;
    int ret;

    if (NULL == transport) {
        /* return NULL; */		/* XXX - are we bothered? */
    }

    sess = (netsnmp_session*) calloc(1, sizeof(netsnmp_session));
    if (NULL != sess) {
	sess->version   = version;
	sess->transport = transport;
    }

    /*
     * If this is (or could be) an SNMPv3 session,
     *   then we need to probe to determine the
     *   appropriate engineID to use.
     */
    if ((SNMP_VERSION_3   == version) ||
        (SNMP_VERSION_ANY == version)) {

        ret = engine_probe(sess);
        if (0 > ret) {
           /* XXX - release transport/close session ??? */
            return NULL;
        }
    }

    return sess;
}


   /**
    *  Create a new session structure with the given version,
    *    and named endpoint.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_session *
session_open(int version, char *peername, int local)
{
    netsnmp_session   *session;
    netsnmp_transport *transport;

    transport = _snmp_transport_parse(peername, local, NULL);
    session   = session_new(version, transport);

    if (NULL == session) {
        /* XXX - release transport? */
        return NULL;
    }

	/* XXX - what administration info do we need to set up? */

    return session;
}


   /**
    *  Free a session structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
session_free(netsnmp_session *sess)
{
    if (NULL == sess) {
        return;
    }

    if (sess->read_community) {
	comminfo_free(sess->read_community);
	sess->read_community = NULL;
    }
    if (sess->write_community) {
	comminfo_free(sess->write_community);
	sess->write_community = NULL;
    }

    if (sess->v3info) {
	v3info_free(sess->v3info);
	sess->v3info = NULL;
    }
    if (sess->userinfo) {
	user_free(sess->userinfo);
	sess->userinfo = NULL;
    }

	/*
	 * XXX
	 * ToDo:
	 *	 Free:	transport
	 *		hook structures
	 *		outstanding requests
	 */

    free( sess );
    return;
}

void
session_close(netsnmp_session *sess)
{
    session_free(sess);		/* XXX - what else ?? */
}

void
session_link(netsnmp_session *old_sess, netsnmp_session *new_sess)
{
    if ((NULL == old_sess ) ||
        (NULL == new_sess )) {
        return;
    }

    new_sess->next = old_sess->next;
    if (new_sess->next) {
        new_sess->next->prev = new_sess;
    }
    old_sess->next = new_sess;
    new_sess->prev = old_sess;
}

void
session_timeout(netsnmp_session *sess)
{
    				/* XXX - what needs doing ?? */
    return;
}


void
session_select(netsnmp_session *sess,
                 int *numfds,
		 fd_set *fdset,
		 struct timeval *timeout,
		 int *block)
{
    struct timeval *tv = NULL;
    netsnmp_request *rp;

    if (NULL == sess) {
        return;
    }

    if (NULL == timeout) {
        tv = alarm_get_next_delay();	/* XXX - Or pass the structure in ??? */
    } else {
        tv = timeout;
    }

    /*
     * If the session is in the process of being closed,
     *   then skip it.
     */
    if (NULL == sess->transport) {
        DEBUGMSG(("session_select", "skipping"));
        return;
    }


    /*
     * If the session is marked for being closed,
     *   then do so.
     */
    if (-1 == sess->transport->sock) {
        DEBUGMSG(("session_select", "delete"));
        session_close(sess);
        return;
    }

    /*
     * Otherwise add this session's socket to the list
     *  to be handled by 'select'
     */
    if (sess->transport->sock+1 > *numfds) {
        *numfds = (sess->transport->sock+1);
    }
    FD_SET(sess->transport->sock, fdset);


    /*
     * Determine when the first of any
     *    outstanding requests will time out
     */
    for (rp = sess->request_head; NULL != rp; rp=rp->next ) {
        tv = request_check_timeout(rp->expire, tv);
    }

    if (NULL != tv) {
        if (NULL != timeout) {
            timeout->tv_usec = tv->tv_usec;
            timeout->tv_sec  = tv->tv_sec;
        } else {
            free(tv);		/* XXX ??? */
        }
    }
    return;
}


int
session_list_select(netsnmp_session *sess,
                 int *numfds,
		 fd_set *fdset,
		 struct timeval *timeout,
		 int *block)
{
    netsnmp_session *slp;
    struct timeval *tv = NULL;

    if (NULL == sess) {
        return 0;
    }

    /*
     * Find the first entry in "this" list of sessions
     * and start from there.
     */
    slp = sess;
    while (NULL != slp->prev) {
        slp = slp->prev;
    }

    /*
     * Invoke 'session_select' on each entry in turn,
     * adding it to the set of fds to be processed,
     */
    tv = alarm_get_next_delay();	/* XXX - Or pass the structure in ??? */
    while (NULL != slp) {
        session_select(slp, numfds, fdset, tv, block);   
        slp = slp->next;
    }

    if ((NULL != timeout) &&
        (NULL != tv )){
        timeout->tv_usec = tv->tv_usec;
        timeout->tv_sec  = tv->tv_sec;
    }
    free(tv);

    return 1;	/* XXX - number of active sessions */
}


   /**
    *
    *  Print a session structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
session_bprint(netsnmp_buf *buf, netsnmp_session *sess)
{
    if (NULL == buf ) {
	return -1;
    }
    if (NULL == sess ) {
	return 0;
    }

    /*
     * Print the common session header fields....
     */
    __B(buffer_append_string(buf, "Session:\n Version = "))
    __B(buffer_append_int(   buf, sess->version))
    __B(buffer_append_string(buf, "\n Flags = "))
    __B(buffer_append_int(   buf, sess->flags))
    __B(buffer_append_string(buf, "\n Retries = "))
    __B(buffer_append_int(   buf, sess->retries))
    __B(buffer_append_string(buf, "\n Timeout = "))
    __B(buffer_append_int(   buf, sess->timeout))
    __B(buffer_append_string(buf, "\n ErrNo = "))
    __B(buffer_append_int(   buf, sess->snmp_errno))
/*  __B(buffer_append_string(buf, "\n ErrMsg = "))	*/
/*  __B(buffer_append_string(buf, sess->errmsg))	*/
    __B(buffer_append_char(  buf, '\n'))

    /*
     *  ... and the version-specific header information
     */
    if (sess->read_community) {
        __B(comminfo_bprint(buf, sess->read_community))
    }
    if (sess->write_community) {
        __B(comminfo_bprint(buf, sess->write_community))
    }

    if (sess->v3info) {
        __B(v3info_bprint(buf, sess->v3info))
    }
    if (sess->userinfo) {
        __B(user_bprint(buf, sess->userinfo))
    }
 
    return 0;
}


   /**
    *
    *  Print a session structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
session_sprint(char *str_buf, int len, netsnmp_session *sess)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == session_bprint(buf, sess)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a session structure to the specified file.
    *
    */
void
session_fprint(FILE *fp, netsnmp_session *sess)
{
    netsnmp_buf    *buf;

    if (NULL == sess) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == session_bprint(buf, sess)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a session structure to standard output. 
    *
    */
void
session_print(netsnmp_session *sess)
{
    session_fprint(stdout, sess);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package session_internals */


void
session_clear_errors(netsnmp_session *sess)
{
    if (NULL == sess) {
        return;
    }

    sess->snmp_errno = 0;
    sess->sys_errno  = 0;
    if (NULL != sess->err_detail) {
        free(sess->err_detail);
        sess->err_detail = NULL;
    }
}


void
session_set_errors(netsnmp_session *sess, int snmp_err, int sys_err, const char* detail)
{
    if (NULL == sess) {
        return;
    }

    sess->snmp_errno = snmp_err;
    sess->sys_errno  = sys_err;
    if (NULL != detail) {
        sess->err_detail = strdup(detail);
    }
}



struct timeval *
alarm_get_next_delay(void)
{
    static struct timeval delay;

    if (0 != get_next_alarm_delay_time(&delay)) {
        return &delay;
    }
    return NULL;
}
