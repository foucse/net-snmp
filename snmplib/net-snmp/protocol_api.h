/*******************************
 *
 *      net-snmp/protocol_api.h
 *
 *      Net-SNMP library - Version-independent SNMP interface
 *
 *******************************/

#ifndef _NET_SNMP_PROTOCOL_API_H
#define _NET_SNMP_PROTOCOL_API_H

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/types.h>

#define UCD_MSG_FLAG_RESPONSE_PDU            0x100
#define UCD_MSG_FLAG_EXPECT_RESPONSE         0x200
#define UCD_MSG_FLAG_FORCE_PDU_COPY          0x400
#define UCD_MSG_FLAG_ALWAYS_IN_VIEW          0x800
#define UCD_MSG_FLAG_PDU_TIMEOUT            0x1000

	/* basic PDU-handling routines */

netsnmp_pdu* pdu_create(int version, int command);
netsnmp_pdu* pdu_copy(       netsnmp_pdu *pdu);
netsnmp_pdu* pdu_parse(      netsnmp_buf *buf);
void         pdu_free(       netsnmp_pdu *pdu);
int          pdu_add_varbind(netsnmp_pdu *pdu, netsnmp_varbind *varbind);
netsnmp_varbind* pdu_return_varbind(  netsnmp_pdu *pdu, int idx);
netsnmp_varbind* pdu_extract_varbind( netsnmp_pdu *pdu, int idx);

int   pdu_bprint(netsnmp_buf *buf,       netsnmp_pdu *pdu);
char* pdu_sprint(char *str_buf, int len, netsnmp_pdu *pdu);
void  pdu_fprint(FILE * fp,              netsnmp_pdu *pdu);
void  pdu_print(                         netsnmp_pdu *pdu);

int   snmp_build_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf);


	/* ASN.1 encoding/decoding routines */

int encode_value(    netsnmp_buf *buf, netsnmp_value   *value);
int encode_varbind(  netsnmp_buf *buf, netsnmp_varbind *vb);
int encode_vblist(   netsnmp_buf *buf, netsnmp_varbind *vblist);
int encode_basic_pdu(netsnmp_buf *buf, netsnmp_pdu     *pdu);

netsnmp_value*   decode_value(    netsnmp_buf *buf);
netsnmp_varbind* decode_varbind(  netsnmp_buf *buf);
netsnmp_varbind* decode_vblist(   netsnmp_buf *buf);
netsnmp_pdu*     decode_basic_pdu(netsnmp_buf *buf, netsnmp_pdu *p);

#endif /* _NET_SNMP_PROTOCOL_API_H */
