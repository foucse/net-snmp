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


	/* basic PDU-handling routines */

netsnmp_pdu*  pdu_create(int version, int command);
void          pdu_free(       netsnmp_pdu *pdu);
int           pdu_add_varbind(netsnmp_pdu *pdu, netsnmp_varbind *varbind);
netsnmp_varbind* pdu_return_varbind(  netsnmp_pdu *pdu, int idx);
netsnmp_varbind* pdu_extract_varbind( netsnmp_pdu *pdu, int idx);

int   pdu_bprint(netsnmp_buf *buf,       netsnmp_pdu *pdu);
char* pdu_sprint(char *str_buf, int len, netsnmp_pdu *pdu);
void  pdu_fprint(FILE * fp,              netsnmp_pdu *pdu);
void  pdu_print(                         netsnmp_pdu *pdu);


	/* ASN.1 encoding routines */

int encode_value(    netsnmp_buf *buf, netsnmp_value   *value);
int encode_varbind(  netsnmp_buf *buf, netsnmp_varbind *vb);
int encode_vblist(   netsnmp_buf *buf, netsnmp_varbind *vblist);
int encode_basic_pdu(netsnmp_buf *buf, netsnmp_pdu     *pdu);

#endif /* _NET_SNMP_PROTOCOL_API_H */
