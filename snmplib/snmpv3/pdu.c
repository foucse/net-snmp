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
#include "ucd/ucd_convert.h"
#include "snmpv3/snmpv3.h"

#include "lcd_time.h"

int snmpv3_check_pdu(netsnmp_pdu *pdu);

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

    switch (pdu->version) {
    case SNMP_VERSION_3:
        break;			/* OK */
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
    case SNMP_VERSION_ANYC:
    case SNMP_VERSION_ANY:
    case SNMP_DEFAULT_VERSION:
    default:
        return -1;              /* Must have a real valid version to send */
    }

    if ((NULL == buf) || (NULL == pdu)) {
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


                /**************************************
                 *
                 *      Temporary
                 *
                 **************************************/
#include "ucd/ucd_api.h"
extern void snmpv3_calc_msg_flags (int, int, u_char *);

int
snmpv3_build(u_char **pkt, size_t *pkt_len, size_t *offset,
            struct snmp_session *session, struct snmp_pdu *pdu)
{
    netsnmp_pdu *p;
    netsnmp_buf *buf;
    netsnmp_engine *engine;
    int boots;
    int time;

    ucd_session_defaults(session, pdu);

    p = ucd_convert_pdu( pdu );
    if ((NULL == p) ||
        (NULL == p->v3info) ||
        (NULL == p->userinfo)) {
        return -1;       /* Error */
    }

printf("**** Using NEW version !!! *** \n");

    /*
     * Fill in missing PDU parameters from session defaults
     */

    user_session_defaults(session, p->userinfo);
    v3info_session_defaults(session, p->v3info);

    snmpv3_calc_msg_flags(p->v3info->sec_level, p->command, &(p->v3info->v3_flags));

    engine = p->userinfo->sec_engine;
    if (engine && engine->ID ) {
        (void)get_enginetime(engine->ID->string, engine->ID->cur_len,
                             &boots, &time, FALSE);
        engine->boots = boots;
        engine->time  = time;
    }


    memset( *pkt, 0, *pkt_len );        /* clear the buffer! */
    buf = buffer_new( *pkt, *pkt_len,
        NETSNMP_BUFFER_RESIZE|NETSNMP_BUFFER_REVERSE );
    
    if (0 > snmpv3_encode_pdu( buf, p )) {
        return -1;
    }

    *pkt     = buf->string;
    *pkt_len = buf->max_len;
    *offset  = buf->cur_len;
    buf->flags |= NETSNMP_BUFFER_NOFREE;

    pdu_free( p );
    buffer_free( buf );
    return 0;
}
