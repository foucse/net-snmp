
#ifndef _SNMPV3_SNMPV3_H
#define _SNMPV3_SNMPV3_H

#include "ucd/ucd_api.h"

int user_encode(  netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_user *userinfo);
int v3info_encode(netsnmp_buf *buf, netsnmp_v3info *info);
int engine_encode(netsnmp_buf *buf, netsnmp_engine *engine);
netsnmp_user*   user_decode(     netsnmp_buf *buf, netsnmp_user   *user);
netsnmp_v3info* v3info_decode(   netsnmp_buf *buf, netsnmp_v3info *info);
netsnmp_engine* engine_decode_ID(netsnmp_buf *buf, netsnmp_engine *e);
netsnmp_engine* engine_decode(   netsnmp_buf *buf, netsnmp_engine *e);
void user_session_defaults(  struct snmp_session *session, netsnmp_user *info);
void v3info_session_defaults(struct snmp_session *session, netsnmp_v3info *info);

int engine_compare(netsnmp_engine *one, netsnmp_engine *two);

int priv_encrypt(netsnmp_buf *buf,
             netsnmp_v3info  *v3info,
             netsnmp_user    *userinfo);
int auth_stamp_pre(netsnmp_buf *buf,
               netsnmp_v3info  *v3info,
               netsnmp_user    *userinfo);
int auth_stamp_post(netsnmp_buf *buf,
                netsnmp_v3info  *v3info,
                netsnmp_user    *userinfo,
                int              auth_len);

#endif /* _SNMPV3_SNMPV3_H */
