/*******************************
 *
 *      net-snmp/community_api.h
 *
 *      Net-SNMP library - Community-based SNMP interface
 *
 *******************************/

#ifndef _NET_SNMP_COMMUNITY_API_H
#define _NET_SNMP_COMMUNITY_API_H

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/types.h>


	/* Community-based PDU-handling routines */

netsnmp_pdu* community_create_pdu(int version, int command, char *cstring   );
int          community_set_cstring(netsnmp_pdu *pdu, char *cstring, int len);
int          community_set_cinfo(  netsnmp_pdu *pdu, netsnmp_comminfo *cinfo);


	/* Community-info handling routines */

netsnmp_comminfo* cinfo_create(                       char *cstring, int len);
netsnmp_comminfo* cinfo_copy(netsnmp_comminfo *cinfo                        );
int               cinfo_set( netsnmp_comminfo *cinfo, char *cstring, int len);
void              cinfo_free(netsnmp_comminfo *cinfo                        );

int   cinfo_bprint(netsnmp_buf *buf,       netsnmp_comminfo *cinfo);
char* cinfo_sprint(char *str_buf, int len, netsnmp_comminfo *cinfo);
void  cinfo_fprint(FILE * fp,              netsnmp_comminfo *cinfo);
void  cinfo_print(                         netsnmp_comminfo *cinfo);

#endif _NET_SNMP_COMMUNITY_API_H
