/*******************************
 *
 *      snmpv3/v3info.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      SNMPv3-header information handling routines
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
#include <net-snmp/snmpv3.h>

#include "protocol/encode.h"
#include "protocol/decode.h"


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/snmpv3_api.h>)
                 *
                 **************************************/
                /** @package snmpv3_api */


   /**
    *
    *  Create a new v3 info structure,
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_v3info *
v3info_create( void )
{
    netsnmp_v3info *info;

    info = (netsnmp_v3info*) calloc(1, sizeof(netsnmp_v3info));

    if (NULL == info) {
        return NULL;
    }
    return info;
}


   /**
    *
    *  Create a copy of a v3 info structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_v3info *
v3info_copy(netsnmp_v3info *info)
{
    netsnmp_v3info *copy;

    if (NULL == info) {
        return NULL;
    }
    copy = v3info_create();
    if (NULL == copy) {
	return NULL;
    }

    memcpy(copy, info, sizeof(netsnmp_v3info));

    copy->context_engine = engine_copy(info->context_engine);
    copy->context_name   = buffer_copy(info->context_name);

    return copy;
}


   /**
    *
    *  Set either/both of the v3 context information fields
    *    (from C-style string values)
    *
    *  Returns 0 if successful, -1 otherwise
    */
int
v3info_set_context(netsnmp_v3info *info, char *engine, char *context)
{
    if (NULL == info) {
        return -1;
    }

    if (NULL != engine) {
        if (NULL != info->context_engine->ID) {
            buffer_free(info->context_engine->ID);
        }
        info->context_engine->ID = buffer_new(engine, 0, 0);
        if (NULL == info->context_engine->ID) {
            return -1;
        }
    }

    if (NULL != context) {
        if (NULL != info->context_name) {
            buffer_free(info->context_name);
        }
        info->context_name = buffer_new(context, 0, 0);
        if (NULL == info->context_name) {
            return -1;
        }
    }

    return 0;
}


   /**
    *
    *  Free a v3 info structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
v3info_free(netsnmp_v3info *info)
{

    if (NULL == info) {
	return;
    }
    engine_free(info->context_engine);
    buffer_free(info->context_name);
    free( info );
    return;
}


   /**
    *
    *  Print a v3 info structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
v3info_bprint(netsnmp_buf *buf, netsnmp_v3info *info)
{
    if (NULL == buf) {
	return -1;
    }
    if (NULL == info) {
	return 0;
    }

    __B(buffer_append_string(buf, "SNMPv3 Parameters:"))
    __B(buffer_append_string(buf, "\n msgID = "))
    __B(buffer_append_int(   buf, info->msgID))
    __B(buffer_append_string(buf, "\n msg_max_size = "))
    __B(buffer_append_int(   buf, info->msg_max_size))
		/* XXX - Print flags */
		/* XXX - convert the next two to strings */
    __B(buffer_append_string(buf, "\n security Level = "))
    __B(buffer_append_int(   buf, info->sec_level))
    __B(buffer_append_string(buf, "\n security Model = "))
    __B(buffer_append_int(   buf, info->sec_model))
    __B(buffer_append_string(buf, "\n contextEngineID = "))
    __B(buffer_append_bufstr(buf, info->context_engine->ID))
    __B(buffer_append_string(buf, "\n contextName = "))
    __B(buffer_append_bufstr(   buf, info->context_name))
    __B(buffer_append_string(buf, "\n"))
    return 0;
}


   /**
    *
    *  Print a v3 info structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
v3info_sprint(char *str_buf, int len, netsnmp_v3info *info)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == v3info_bprint(buf, info)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a v3 info structure to the specified file.
    *
    */
void
v3info_fprint(FILE * fp, netsnmp_v3info *info)
{
    netsnmp_buf    *buf;

    if (NULL == info) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == v3info_bprint(buf, info)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a v3 info structure to standard output. 
    *
    */
void
v3info_print(netsnmp_v3info *info)
{
    v3info_fprint(stdout, info);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package snmpv3_internals */


   /**
    *
    *  ASN.1-encode an SNMPv3 'HeaderData' sequence
    *  Returns 0 if successful, -ve otherwise
    */
int
v3info_encode(netsnmp_buf *buf, netsnmp_v3info *info)
{
    int start_len;

    if ((NULL == buf) || (NULL == info)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }

    start_len= buf->cur_len;    /* Remember the length before we start */

    __B(encode_integer(buf, ASN_INTEGER,     info->sec_model))
    __B(encode_string( buf, ASN_OCTET_STR, &(info->v3_flags), 1))
    __B(encode_integer(buf, ASN_INTEGER,     info->msg_max_size))
    __B(encode_integer(buf, ASN_INTEGER,     info->msgID))
    __B(encode_sequence(buf, (buf->cur_len - start_len)))
    return 0;
}


netsnmp_v3info*
v3info_decode(netsnmp_buf *buf, netsnmp_v3info *info)
{
    netsnmp_buf     flags;
    netsnmp_buf    *seq    = NULL;
    netsnmp_v3info *v3info = NULL;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    memset( &flags, 0, sizeof(netsnmp_buf));

    if (NULL == info) {
        v3info = (netsnmp_v3info *)calloc(1, sizeof(netsnmp_v3info));
    } else {
        v3info = info;
    }

    seq = decode_sequence(buf);
    if (NULL == seq) {
        goto fail;
    }
    if (NULL == decode_integer(seq, &(v3info->msgID))) {
        goto fail;
    }
    if (NULL == decode_integer(seq, &(v3info->msg_max_size))) {
        goto fail;
    }
    if (NULL == decode_string( seq, &flags)) {
        goto fail;
    }
    v3info->v3_flags = flags.string[0];
    v3info->sec_level = ((AUTH_FLAG & v3info->v3_flags) ?
                        ((PRIV_FLAG & v3info->v3_flags) ?
                                                  NETSNMP_SEC_LEVEL_AUTHPRIV   :
                                                  NETSNMP_SEC_LEVEL_AUTHONLY ) :
                                                  NETSNMP_SEC_LEVEL_NOAUTH   );
    if (NULL == decode_integer(seq, &(v3info->sec_model))) {
        goto fail;
    }
    if (0 != seq->cur_len) {
        goto fail;
    }

    return v3info;

fail:
    buffer_free( seq );
    v3info_free( v3info );
    return NULL;
}


#include "ucd/ucd_api.h"

void
v3info_session_defaults(struct snmp_session *session, netsnmp_v3info *info)
{
    if ((NULL == session) || (NULL == info)) {
        return;
    }

    if (NULL == info->context_engine) {
        if (session->contextEngineIDLen) {
            info->context_engine =
                engine_new(session->contextEngineID,
                           session->contextEngineIDLen);
        }
        else if (session->securityEngineIDLen) {
            info->context_engine =
                engine_new(session->securityEngineID,
                           session->securityEngineIDLen);
        }
    }


    if (NULL == info->context_name) {
        info->context_name = buffer_new(session->contextName,
                                        session->contextNameLen, 0);
    }

    if (NETSNMP_SEC_MODEL_DEFAULT == info->sec_model) {
        if (NETSNMP_SEC_MODEL_DEFAULT == session->securityModel ) {
            info->sec_model = NETSNMP_SEC_MODEL_USM;
        } else {
            info->sec_model = session->securityModel;
        }
    }
    if (NETSNMP_SEC_LEVEL_DEFAULT == info->sec_level) {
        if (NETSNMP_SEC_LEVEL_DEFAULT == session->securityLevel ) {
            info->sec_level = NETSNMP_SEC_LEVEL_NOAUTH;
        } else {
            info->sec_level = session->securityLevel;
        }
    }

    if (0 == info->msg_max_size) {
        info->msg_max_size = session->rcvMsgMaxSize;
    }
}
