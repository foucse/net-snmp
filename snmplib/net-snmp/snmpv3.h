/*******************************
 *
 *      net-snmp/snmpv3.h
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *******************************/

#ifndef _NET_SNMP_SNMPV3_API_H
#define _NET_SNMP_SNMPV3_API_H

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/types.h>

extern int snmpv3_ignore_unauth_reports;

netsnmp_pdu *snmpv3_create_pdu(int command);

#define	NETSNMP_AUTH_PROTOCOL_DEFAULT	0
#define	NETSNMP_AUTH_PROTOCOL_NONE	1
#define	NETSNMP_AUTH_PROTOCOL_MD5	2
#define	NETSNMP_AUTH_PROTOCOL_SHA	3

int           auth_protocol(char *tag);
netsnmp_oid * auth_oid( int protocol );

#define	NETSNMP_PRIV_PROTOCOL_DEFAULT	0
#define	NETSNMP_PRIV_PROTOCOL_NONE	1
#define	NETSNMP_PRIV_PROTOCOL_DES	2

int           priv_protocol(char *tag);
netsnmp_oid * priv_oid( int protocol );

#define AUTH_FLAG			0x01
#define PRIV_FLAG			0x02
#define RESPONSE_FLAG			0x04

#define	NETSNMP_SEC_LEVEL_DEFAULT	0
#define	NETSNMP_SEC_LEVEL_NOAUTH	1
#define	NETSNMP_SEC_LEVEL_AUTHONLY	2
#define	NETSNMP_SEC_LEVEL_AUTHPRIV	3

#define	NETSNMP_SEC_MODEL_DEFAULT	-1
#define	NETSNMP_SEC_MODEL_USM		3

netsnmp_user* user_create(char *name, int len, netsnmp_engine *engine);
netsnmp_user* user_copy(netsnmp_user *info);
void          user_free(netsnmp_user *info);

int   user_bprint(netsnmp_buf *buf,       netsnmp_user *user);
char* user_sprint(char *str_buf, int len, netsnmp_user *user);
void  user_fprint(FILE * fp,              netsnmp_user *user);
void  user_print(                         netsnmp_user *user);

netsnmp_engine* engine_new(char *id, int len);
netsnmp_engine* engine_copy(netsnmp_engine *engine);
void            engine_free(netsnmp_engine *engine);

int   engine_bprint(netsnmp_buf *buf,       netsnmp_engine *engine);
char* engine_sprint(char *str_buf, int len, netsnmp_engine *engine);
void  engine_fprint(FILE * fp,              netsnmp_engine *engine);
void  engine_print(                         netsnmp_engine *engine);

netsnmp_v3info* v3info_create( void );
netsnmp_v3info* v3info_copy(       netsnmp_v3info *info);
int             v3info_set_context(netsnmp_v3info *info, char *engine, char *context);
void            v3info_free(       netsnmp_v3info *info);

int   v3info_bprint(netsnmp_buf *buf,       netsnmp_v3info *info);
char* v3info_sprint(char *str_buf, int len, netsnmp_v3info *info);
void  v3info_fprint(FILE * fp,              netsnmp_v3info *info);
void  v3info_print(                         netsnmp_v3info *info);

#endif /* _NET_SNMP_SNMPV3_API_H */
