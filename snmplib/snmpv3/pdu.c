/*******************************
 *
 *      snmpv3/pdu.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      SNMPv3 PDU handling routines
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
#include <net-snmp/snmpv3.h>
#include <net-snmp/protocol_api.h>

#include "protocol/encode.h"
#include "protocol/decode.h"
#include "ucd/ucd_convert.h"
#include "snmpv3/snmpv3.h"

#include "lcd_time.h"

int snmpv3_check_pdu(netsnmp_pdu *pdu);

#define _CHECK_VERSION( v, x )	switch ((v)) { \
				case SNMP_VERSION_3:	\
				case SNMP_VERSION_ANY:	\
				case SNMP_DEFAULT_VERSION: \
				    break;		\
				case SNMP_VERSION_1:	\
				case SNMP_VERSION_2c:	\
				case SNMP_VERSION_ANYC:	\
				default:		\
				    return (x);		\
				}

int snmpv3_ignore_unauth_reports = FALSE;

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/snmpv3_api.h>)
                 *
                 **************************************/
                /** @package snmpv3_api */


   /**
    *
    *  Create a new SNMPv3 PDU structure,
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_pdu *
snmpv3_create_pdu(int command)
{
    netsnmp_pdu *pdu;

    pdu = pdu_create(SNMP_VERSION_3, command);
    return pdu;
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package snmpv3_internals */


   /**
    *
    *  ASN.1-encode an SNMPv3 PDU
    *  Returns 0 if successful, -ve otherwise
    */
int
snmpv3_encode_pdu(netsnmp_buf *buf, netsnmp_pdu *pdu)
{
    int start_len;

    if ((NULL == buf) ||
        (NULL == pdu)) {
        return -1;
    }

    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }

    if (0 > snmpv3_check_pdu(pdu)) {
        return -1;
    }

    start_len= buf->cur_len;    /* Remember the length before we start */

    /*
     * Encode the ScopedPDU
     */
    __B(encode_basic_pdu(buf, pdu))
    __B(encode_bufstr(buf, pdu->v3info->context_name))
    if (NULL != pdu->v3info->context_engine) {
        __B(encode_bufstr(buf, pdu->v3info->context_engine->ID))
    } else {
        __B(encode_bufstr(buf, NULL))
    }
    __B(encode_sequence(buf, (buf->cur_len - start_len)))

		/*
		 * XXX - use the security-model registry,
		 *	 rather than hardwiring USM
		 */
    __B(user_encode(buf, pdu->v3info, pdu->userinfo))

    /*
     * Now finish encoding the full v3 PDU
     */
    __B(v3info_encode( buf, pdu->v3info))
    __B(encode_integer(buf, ASN_INTEGER, pdu->version))
    __B(encode_sequence(buf, (buf->cur_len - start_len)))


    /*
     *  Having finished constructing the PDU,
     *    we can now authenticate it.
     *
     *  XXX - Are we sure that this should be done here, not earlier ?
     */
    if ( pdu->v3info->v3_flags & AUTH_FLAG ) {
        __B(auth_stamp_post(buf, pdu->v3info, pdu->userinfo, pdu->v3info->auth_saved_len))
    }

    return 0;
}


int
snmpv3_build_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf)
{
    if ((NULL == sess) ||
        (NULL == pdu)  ||
        (NULL == buf)) {
        return -1;
    }

    _CHECK_VERSION(sess->version, -1 )
    _CHECK_VERSION( pdu->version, -1 )

    /*
     * If any of the PDU elements are missing,
     * use the equivalent session defaults
     */
    if ((SNMP_VERSION_ANY     == pdu->version) ||
        (SNMP_DEFAULT_VERSION == pdu->version)) {
        pdu->version = sess->version;
    }
    if (NULL == pdu->v3info) {
        pdu->v3info = v3info_copy(sess->v3info);
    }
    if (NULL == pdu->userinfo) {
        pdu->userinfo = user_copy(sess->userinfo);
    }
    if (NULL == pdu->userinfo->sec_engine) {
        pdu->userinfo->sec_engine = engine_copy(pdu->v3info->context_engine);
    }

    /*
     * If any of the PDU elements have 'default' settings,
     * use the appropriate basic value.
     */
    if (NETSNMP_SEC_MODEL_DEFAULT == pdu->v3info->sec_model) {
        pdu->v3info->sec_model = NETSNMP_SEC_MODEL_USM;
    }
    if (NETSNMP_SEC_LEVEL_DEFAULT == pdu->v3info->sec_level) {
        pdu->v3info->sec_level = NETSNMP_SEC_LEVEL_NOAUTH;
    }
    if (NETSNMP_SEC_MODEL_USM == pdu->v3info->sec_model) {
        if (NETSNMP_AUTH_PROTOCOL_DEFAULT == pdu->userinfo->auth_protocol) {
            pdu->userinfo->auth_protocol = NETSNMP_AUTH_PROTOCOL_MD5;
        }
        if (NETSNMP_PRIV_PROTOCOL_DEFAULT == pdu->userinfo->priv_protocol) {
            pdu->userinfo->priv_protocol = NETSNMP_PRIV_PROTOCOL_DES;
        }
    }

    /*
     * Set the SNMPv3 flags to match the desired security level
     */
    if (NETSNMP_SEC_LEVEL_AUTHONLY == pdu->v3info->sec_level) {
        pdu->v3info->v3_flags |= AUTH_FLAG;
    }
    if (NETSNMP_SEC_LEVEL_AUTHPRIV == pdu->v3info->sec_level) {
        pdu->v3info->v3_flags |= AUTH_FLAG;
        pdu->v3info->v3_flags |= PRIV_FLAG;
    }

    return snmpv3_encode_pdu(buf, pdu);
}


int
snmpv3_check_pdu(netsnmp_pdu *pdu)
{
    if (NULL == pdu ) {
        return -1;
    }

    if (SNMP_VERSION_3 != pdu->version) {
        return -1;
    }

    if (NULL == pdu->v3info) {
        return -1;
    }

    /*
     * Check command for compatability with SNMPv3
     */
    switch (pdu->command) {
    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_SET:
    case SNMP_MSG_GETBULK:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_INFORM:
    case SNMP_MSG_REPORT:
	return 0;		/* OK */

    case SNMP_MSG_TRAP:
    default:
	return -1;		/* Not valid */
    }

    /* NOT REACHED */
    return -1;
}

netsnmp_pdu*
snmpv3_decode_pdu(netsnmp_buf *buf)
{
    netsnmp_buf    *seq    = NULL;
    netsnmp_pdu    *pdu    = NULL;
    netsnmp_v3info *v3info = NULL;
    netsnmp_user   *user   = NULL;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    v3info = v3info_decode(buf, NULL);
    if (NULL == v3info) {
        return NULL;
    }
    user   = user_decode(buf, v3info, NULL);
    if (NULL == user) {
        v3info_free( v3info );
        return NULL;
    }

    seq = decode_sequence( buf );
    if (NULL == seq) {
        v3info_free( v3info );
        user_free( user );
        return NULL;
    }
    v3info->context_engine = engine_decode_ID(seq, NULL);
    v3info->context_name   = decode_string(seq, NULL);
    pdu = decode_basic_pdu(seq, NULL);
    if (NULL == pdu) {
        v3info_free( v3info );
        user_free( user );
        buffer_free( seq );
        return NULL;
    }

    pdu->v3info   = v3info;
    pdu->userinfo = user;

    return pdu;
}


int
snmpv3_verify_msg(netsnmp_request *rp, netsnmp_pdu *pdu)
{
    netsnmp_pdu     *rpdu;
  
    if ((NULL == rp)              ||
        (NULL == rp->pdu)         ||
        (NULL == rp->pdu->v3info) ||
        (NULL == pdu)             ||
        (NULL == pdu->v3info)) {
        return -1;
    }

    /*
     * Reports don't have to match anything
     */
    if (SNMP_MSG_REPORT == pdu->command) {
        return 0;
    }

    rpdu = rp->pdu;
    if ((rp->request_id      != pdu->request)  ||
        (rpdu->request       != pdu->request)  ||
        (rpdu->version       != pdu->version)  ||
        (rpdu->v3info->sec_model != pdu->v3info->sec_model) ||
        (rpdu->v3info->sec_level != pdu->v3info->sec_level)) {
        return -1;
    }

    if ((0 != engine_compare(rpdu->v3info->context_engine,
                              pdu->v3info->context_engine)) ||
        (0 != buffer_compare(rpdu->v3info->context_name,
                              pdu->v3info->context_name))   ||
        (0 != engine_compare(rpdu->userinfo->sec_engine,
                              pdu->userinfo->sec_engine))   ||
        (0 != buffer_compare(rpdu->userinfo->sec_name,
                              pdu->userinfo->sec_name))) {
        return -1;
    }

    return 0;
}



   /**
    *  Parse an SNMPv3 PDU from the given input buffer.
    *
    *  blah, blah, returns pointer, blah, release memory, blah blah
    */
netsnmp_pdu*
snmpv3_parse_pdu(netsnmp_buf *buf)
{
    netsnmp_buf *seq  = NULL;
    netsnmp_pdu *pdu  = NULL;
    netsnmp_buf *tmp  = NULL;
    char *cp;
    int   i;
    long version;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    cp = buf->string;
    i  = buf->cur_len;
    seq = decode_sequence(buf);
    if (NULL == seq) {
        return NULL;
    }
    if (NULL == decode_integer(seq, &version)) {
        buffer_free(seq);
        return NULL;
    }

		/*
		 * XXX - Check version
		 */
    pdu = snmpv3_decode_pdu(seq);
    if ((NULL == pdu) ||
        (NULL == pdu->v3info)) {
        buffer_free(seq);
        return NULL;
    }
    if (0 != seq->cur_len) {
        pdu_free(pdu);
        buffer_free(seq);
        return NULL;
    }

    if (AUTH_FLAG & pdu->v3info->v3_flags) {
        tmp = buffer_new(cp, i, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
        if (-1 == auth_verify(tmp, pdu->v3info, pdu->userinfo)) {
            pdu_free(pdu);
            buffer_free(seq);
            buffer_free(tmp);
            return NULL;
        }
        buffer_free(tmp);
    }

    pdu->version = version;
    buffer_free(seq);

    return pdu;
}


