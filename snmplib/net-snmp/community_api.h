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
int          community_set_info(   netsnmp_pdu *pdu, netsnmp_comminfo *info);


	/* Community-info handling routines */

netsnmp_comminfo* comminfo_create(                      char *cstring, int len);
netsnmp_comminfo* comminfo_copy(netsnmp_comminfo *info                        );
int               comminfo_set( netsnmp_comminfo *info, char *cstring, int len);
void              comminfo_free(netsnmp_comminfo *info                        );

int   comminfo_bprint(netsnmp_buf *buf,       netsnmp_comminfo *info);
char* comminfo_sprint(char *str_buf, int len, netsnmp_comminfo *info);
void  comminfo_fprint(FILE * fp,              netsnmp_comminfo *info);
void  comminfo_print(                         netsnmp_comminfo *info);

#endif /* _NET_SNMP_COMMUNITY_API_H */
