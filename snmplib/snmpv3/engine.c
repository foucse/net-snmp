/*******************************
 *
 *      snmpv3/engine.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      SNMP ENGINE handling routines
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


#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/protocol_api.h>
#include <net-snmp/snmpv3.h>

#include "session/session.h"
#include "protocol/encode.h"
#include "protocol/decode.h"

static netsnmp_engine *engine_head = NULL;
static netsnmp_engine *engine_tail = NULL;

netsnmp_engine *engine_find(char *id, int len);
int engine_compare(netsnmp_engine *one, netsnmp_engine *two);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/snmpv3_api.h>)
                 *
                 **************************************/
                /** @package snmpv3_api */


   /**
    *  Create a new engine structure,
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_engine *
engine_new(char *id, int len)
{
    netsnmp_engine *engine;

    if ((NULL == id) || (0 == len)) {
        return NULL;
    }

    /*
     * If we already know about this engineID,
     *   then use the same structure.
     */
    engine = engine_find(id, len);
    if (NULL != engine) {
        engine->ref_count++;
        return engine;
    }

    /*
     * Otherwise, create a new structure....
     */
    engine = (netsnmp_engine*) calloc(1, sizeof(netsnmp_engine));
    if (NULL == engine) {
        return NULL;
    }

    engine->ID = buffer_new(id, len, 0);
    if (NULL == engine->ID) {
        free( engine );
        return NULL;
    }
    engine->ref_count++;

    /*
     *  .... and add it to the internal list.
     */
    if (NULL != engine_tail) {
        engine_tail->next = engine;
        engine->prev      = engine_tail;
        engine_tail       = engine;
    } else {
        engine_head       = engine;
        engine_tail       = engine;
    }
    return engine;
}


   /**
    *  Create a copy of an engine structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  (via 'engine_free') when it is no longer required.
    */
netsnmp_engine *
engine_copy(netsnmp_engine *engine)
{
    if (NULL == engine) {
        return NULL;
    }
    engine->ref_count++;
    return engine;
}


   /**
    *  Free an engine structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
engine_free(netsnmp_engine *engine)
{
    if (NULL == engine) {
	return;
    }
    /*
     * Is someone else still using this engine structure?
     */
    if (0 < --(engine->ref_count)) {
	return;
    }

    /*
     * If not, then unlink it from the list....
     */
    if (engine->prev) {
        engine->prev->next = engine->next;
    } else {
        engine_head        = engine->next;
    }
    if (engine->next) {
        engine->next->prev = engine->prev;
    } else {
        engine_tail        = engine->prev;
    }
    /*
     * .... and release the memory.
     */
    buffer_free(engine->ID);
    free( engine );
    return;
}


   /**
    *
    *  Print an engine structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
engine_bprint(netsnmp_buf *buf, netsnmp_engine *engine)
{
    if (NULL == buf) {
	return -1;
    }
    if (NULL == engine) {
	return 0;
    }

    __B(buffer_append_string(buf, " EngineID = "))
    __B(buffer_append_bufstr(buf, engine->ID))
    __B(buffer_append_string(buf, "\n EngineBoots = "))
    __B(buffer_append_int(   buf, engine->boots))
    __B(buffer_append_string(buf, "\n EngineTime = "))
    __B(buffer_append_int(   buf, engine->time))
    __B(buffer_append_string(buf, "\n"))
    return 0;
}


   /**
    *
    *  Print an engine structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
engine_sprint(char *str_buf, int len, netsnmp_engine *engine)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == engine_bprint(buf, engine)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print an engine structure to the specified file.
    *
    */
void
engine_fprint(FILE * fp, netsnmp_engine *engine)
{
    netsnmp_buf    *buf;

    if (NULL == engine) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == engine_bprint(buf, engine)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print an engine structure to standard output. 
    *
    */
void
engine_print(netsnmp_engine *engine)
{
    engine_fprint(stdout, engine);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package snmpv3_internals */

   /**
    *  ASN.1-encode an engine structure.
    *  Returns 0 if successful, -ve otherwise
    */
int
engine_encode(netsnmp_buf *buf, netsnmp_engine *engine)
{
    if (NULL == buf ) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }


    if (NULL != engine ) {
        __B(encode_integer(buf, ASN_INTEGER, engine->time))
        __B(encode_integer(buf, ASN_INTEGER, engine->boots))
        __B(encode_bufstr( buf, engine->ID))
    } else {
        __B(encode_integer(buf, ASN_INTEGER, 0))
        __B(encode_integer(buf, ASN_INTEGER, 0))
        __B(encode_bufstr( buf, NULL))
    }
    return 0;
}


   /**
    *  Decode an engine ID.
    *  Returns a pointer to the engine structure if successful,
    *    NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_engine*
engine_decode_ID(netsnmp_buf *buf, netsnmp_engine *e)
{
    netsnmp_engine *engine;
    netsnmp_buf    *id;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    id = decode_string(buf, NULL);
    if (NULL == id) {
        return NULL;
    }
    engine = engine_new(id->string, id->cur_len);

    return engine;
}


   /**
    *  Decode an engine structure.
    *  Returns a pointer to this if successful,
    *    NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_engine*
engine_decode(netsnmp_buf *buf, netsnmp_engine *e)
{
    netsnmp_engine *engine;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    engine = engine_decode_ID(buf, e);
    (void) decode_integer(buf, &(engine->boots));
    (void) decode_integer(buf, &(engine->time));
    return engine;
}


   /**
    *  Search the internal list for the given engine ID,
    *  Returns a pointer to the relevant structure if found, NULL otherwise.
    */
netsnmp_engine *
engine_find(char *id, int len)
{
    netsnmp_engine *engine;

    if ((NULL == id) || (0 == len)) {
        return NULL;
    }
    for (engine = engine_head; NULL != engine; engine = engine->next ) {
        if (NULL == engine->ID) {
            continue;			/* Shouldn't happen! */
        }
        if ((len == engine->ID->cur_len) &&
            (0 == memcmp(id, engine->ID->string, len))) {
            return engine;
        }
    }

    /*
     * Not found.
     */
    return NULL;
}


int
engine_compare(netsnmp_engine *one, netsnmp_engine *two)
{
    if ((NULL == one) || (NULL == two)) {
        return 0;	/* Not really, but.... */
    }

    return buffer_compare(one->ID, two->ID);
}


netsnmp_pdu *
engine_probe_build(void)
{
    netsnmp_pdu *pdu;

    pdu = snmpv3_create_pdu(SNMP_MSG_GET);
    if (NULL == pdu) {
        return NULL;
    }

    pdu->v3info   = v3info_create();
    pdu->userinfo = user_create("", 0, NULL);
    return pdu;
}

int
engine_probe(netsnmp_session *sess)
{
    netsnmp_pdu *probe, *response;

    if (NULL == sess) {
        return -1;
    }

    /*
     * We're only interested in probing SNMPv3 sessions
     */
    if (SNMP_VERSION_3 != sess->version) {
	/* XXX - what about VERSION_ANY ? */
        return 0;
    }
    if (NULL != sess->v3info) {		/* XXX - ???? */
        return 0;
    }


    /*
     * Build and send a probe request,
     *   and extract the remote engine ID from the response
     */
    probe = engine_probe_build();
    if (NULL == probe) {
        return -1;
    }
    response = synch_response(sess, probe);
    if (NULL == response) {
        pdu_free(probe);	/* XXX ??? */
        return -1;
    }

	/* XXX - what else to check ?? */

    sess->v3info = v3info_copy(response->v3info);

 /* pdu_free(probe); 	XXX - this causes a core dump - why!?? */
    pdu_free(response);
    return 0;
}

