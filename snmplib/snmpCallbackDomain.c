#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#include <ctype.h>
#include <errno.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#if HAVE_SYS_UN_H
#include <sys/un.h>
#endif

#include "asn1.h"
#include "snmp.h"
#include "snmp_debug.h"
#include "default_store.h"
#include "snmp_transport.h"
#include "snmpUnixDomain.h"
#include "snmp_impl.h"
#include "snmp_api.h"
#include "snmp_client.h"
#include "tools.h"
#include "snmpCallbackDomain.h"

#ifndef SNMP_STREAM_QUEUE_LEN
#define SNMP_STREAM_QUEUE_LEN  5
#endif

typedef struct callback_hack_s {
   void *orig_transport_data;
   struct snmp_pdu *pdu;
} callback_hack;

static int callback_count = 0;

typedef struct callback_queue_s {
   int callback_num;
   callback_pass *item;
   struct callback_queue_s *next, *prev;
} callback_queue;

callback_queue *thequeue;

void
callback_push_queue(int num, callback_pass *item) 
{
    callback_queue *newitem = SNMP_MALLOC_TYPEDEF(callback_queue);
    callback_queue *ptr;
    
    newitem->callback_num = num;
    newitem->item = item;
    if (thequeue) {
        for(ptr = thequeue; ptr && ptr->next; ptr = ptr->next) {
        }
        ptr->next = newitem;
        newitem->prev = ptr;
    } else {
        thequeue = newitem;
    }
}

callback_pass *
callback_pop_queue(int num) 
{
    callback_pass *cp;
    callback_queue *ptr;
    
    for(ptr = thequeue; ptr; ptr = ptr->next) {
        if (ptr->callback_num == num) {
            if (ptr->prev) {
                ptr->prev->next = ptr->next;
            } else {
                thequeue = ptr->next;
            }
            if (ptr->next) {
                ptr->next->prev = ptr->prev;
            }
            cp = ptr->item;
            free(ptr);
            return cp;
        }
    }
    return NULL;
}

/*  Return a string representing the address in data, or else the "far end"
    address if data is NULL.  */

char	       *snmp_callback_fmtaddr	(snmp_transport *t,
					 void *data, int len)
{
    char buf[SPRINT_MAX_LEN];
    callback_info *mystuff;

    if (!t)
        return strdup("callback: unknown");
    
    mystuff = (callback_info *) t->data;

    if (!mystuff)
        return strdup("callback: unknown");

    snprintf(buf, SPRINT_MAX_LEN, "callback: %d", mystuff->callback_num);
    return strdup(buf);
}



/*  You can write something into opaque that will subsequently get passed back 
    to your send function if you like.  For instance, you might want to
    remember where a PDU came from, so that you can send a reply there...  */

int		snmp_callback_recv	(snmp_transport *t, void *buf, int size,
                                         void **opaque, int *olength) 
{
    int rc;
    char newbuf[1];
    callback_info *mystuff = (callback_info *) t->data;

    DEBUGMSGTL(("transport_callback","hook_recv enter\n"));

    t->data = mystuff->parent_data;

    rc = snmp_unix_recv(t, newbuf, 1, opaque, olength);
    t->data = mystuff;

    if (mystuff->linkedto) {
        /* we're the client */
    } else {
        int *returnnum = (int *) calloc(1,sizeof(int));
        *opaque = returnnum;
        *olength = sizeof(int);
    }
    DEBUGMSGTL(("transport_callback","hook_recv exit\n"));
    return rc;
}



int		snmp_callback_send	(snmp_transport *t, void *buf, int size,
                                         void **opaque, int *olength)
{
    int rc;
    callback_info *mystuff = (callback_info *) t->data;
    callback_pass *cp;
  
    /* extract the pdu from the hacked buffer */
    callback_hack *ch = (callback_hack *) *opaque;
    struct snmp_pdu *pdu = ch->pdu;
    *opaque = ch->orig_transport_data;

    DEBUGMSGTL(("transport_callback","hook_send enter\n"));

    /* send it through the requested transport (XXX: only unix) */
    t->data = mystuff->parent_data;
    rc = snmp_unix_send(t, " ", 1, opaque, olength);
    t->data = mystuff;

    /* push the sent pdu onto the stack */
    cp  = SNMP_MALLOC_TYPEDEF(callback_pass);
    cp->pdu = snmp_clone_pdu(pdu);
    if (cp->pdu->flags & UCD_MSG_FLAG_EXPECT_RESPONSE)
        cp->pdu->flags ^= UCD_MSG_FLAG_EXPECT_RESPONSE;
    if (mystuff->linkedto) {
        cp->return_transport_num = mystuff->callback_num;
        callback_push_queue(mystuff->linkedto, cp);
    } else {
        callback_push_queue(**((int **) opaque), cp);
        /* we're the server */
    }

    DEBUGMSGTL(("transport_callback","hook_send exit\n"));
    return rc;
}



int		snmp_callback_close	(snmp_transport *t)
{
    int rc;
    callback_info *mystuff = (callback_info *) t->data;
    DEBUGMSGTL(("transport_callback","hook_close enter\n"));
    t->data = mystuff->parent_data;

    rc = snmp_unix_close(t);

    t->data = mystuff;

    DEBUGMSGTL(("transport_callback","hook_close exit\n"));
    return rc;
}



int		snmp_callback_accept	(snmp_transport *t)
{
    int rc;
    callback_info *mystuff = (callback_info *) t->data;
    DEBUGMSGTL(("transport_callback","hook_accept enter\n"));
    t->data = mystuff->parent_data;

    rc = snmp_unix_accept(t);

    t->data = mystuff;

    DEBUGMSGTL(("transport_callback","hook_accept exit\n"));
    return rc;
}



/*  Open a Callback-domain transport for SNMP.  Local is TRUE if addr
    is the local address to bind to (i.e. this is a server-type
    session); otherwise addr is the remote address to send things to
    (and we make up a temporary name for the local end of the
    connection).  */

snmp_transport		*snmp_callback_transport   (int to)
{
    
    snmp_transport *t = NULL;
    struct sockaddr_un addr;
    callback_info *mydata;

    addr.sun_family = AF_UNIX;
    sprintf(addr.sun_path, "%s/callback", "/tmp");
  
    t = snmp_unix_transport(&addr, ((to)?0:1));
    if (NULL == t)
        return t;

    /* our stuff */
    mydata = SNMP_MALLOC_TYPEDEF(callback_info);
    mydata->parent_data = t->data;
    mydata->linkedto = to;
    mydata->callback_num = ++callback_count;
    mydata->data = NULL;
    t->data = mydata;

    t->f_recv      = snmp_callback_recv;
    t->f_send      = snmp_callback_send;
    t->f_close     = snmp_callback_close;
    t->f_accept    = snmp_callback_accept;
    t->f_fmtaddr   = snmp_callback_fmtaddr;

    if (to)
        DEBUGMSGTL(("transport_callback","initialized %d linked to %d\n",
                    mydata->callback_num, to));
    else
        DEBUGMSGTL(("transport_callback","initialized master listening on %d\n",
                    mydata->callback_num));
    return t;
}

int
snmp_callback_hook_parse(struct snmp_session *sp,
                         struct snmp_pdu *pdu,
                         u_char *packetptr,
                         size_t len) 
{
    return SNMP_ERR_NOERROR;
}

int
snmp_callback_hook_build(struct snmp_session *sp,
                         struct snmp_pdu *pdu,
                         u_char *ptk, size_t *len) 
{
    /* very gross hack, as this is passed later to the transport_send
       function */
    callback_hack *ch = SNMP_MALLOC_TYPEDEF(callback_hack);
    DEBUGMSGTL(("transport_callback","hook_build enter\n"));
    ch->pdu = pdu;
    ch->orig_transport_data = pdu->transport_data;
    pdu->transport_data = ch;
    *len = 1;
    DEBUGMSGTL(("transport_callback","hook_build exit\n"));
    return 1;
}

int
snmp_callback_check_packet(u_char *pkt, size_t len)
{
    return 1;
}

struct snmp_pdu *
snmp_callback_create_pdu(snmp_transport *transport,
                         void *opaque, size_t olength) 
{
    struct snmp_pdu *pdu;
    callback_pass *cp =
        callback_pop_queue(((callback_info *) transport->data)->callback_num);
    if (!cp)
        return NULL;
    pdu = cp->pdu;
    pdu->transport_data        = opaque;
    pdu->transport_data_length = olength;
    if (opaque) /* if created, we're the server */
        *((int *) opaque) = cp->return_transport_num;
    free(cp);
    return pdu;
}

struct snmp_session *
snmp_callback_open(int attach_to,
                   int (*return_func)(int op, struct snmp_session *session,
                                      int reqid, struct snmp_pdu *pdu,
                                      void *magic),
                   int (*fpre_parse) (struct snmp_session *,
                                      struct _snmp_transport *,
                                      void *, int),
                   int (*fpost_parse)(struct snmp_session *,
                                      struct snmp_pdu *, int))
{
    struct snmp_session callback_sess, *callback_ss;
    snmp_transport *callback_tr;

    callback_tr = snmp_callback_transport(attach_to);
    snmp_sess_init(&callback_sess);
    callback_sess.callback = return_func;
    if (attach_to) {
        /* client */
        callback_sess.flags  |= SNMP_FLAGS_STREAM_SOCKET;
        /* trysess.community = (u_char *) callback_ss; */
    } else {
        callback_sess.isAuthoritative = SNMP_SESS_AUTHORITATIVE;
    }
    callback_sess.remote_port = 0;
    callback_sess.retries = 0;
    callback_sess.timeout = 30000000;
    callback_sess.version         = SNMP_VERSION_1; /* bogus */
    callback_ss = snmp_add_full(&callback_sess, callback_tr,
                                fpre_parse,
                                snmp_callback_hook_parse, fpost_parse,
                                snmp_callback_hook_build,
                                snmp_callback_check_packet,
                                snmp_callback_create_pdu);
    callback_ss->local_port =
        ((callback_info *) callback_tr->data)->callback_num;
    return callback_ss;
}

