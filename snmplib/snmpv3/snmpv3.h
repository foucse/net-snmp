
#ifndef _SNMPV3_SNMPV3_H
#define _SNMPV3_SNMPV3_H

#include "ucd/ucd_api.h"

int             user_encode(     netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_user *userinfo);
netsnmp_user*   user_decode(     netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_user *userinfo);
netsnmp_v3info* v3info_decode(   netsnmp_buf *buf, netsnmp_v3info *info);
int             v3info_encode(   netsnmp_buf *buf, netsnmp_v3info *info);
int             engine_encode(   netsnmp_buf *buf, netsnmp_engine *engine);
netsnmp_engine* engine_decode(   netsnmp_buf *buf, netsnmp_engine *e);
netsnmp_engine* engine_decode_ID(netsnmp_buf *buf, netsnmp_engine *e);
netsnmp_pdu*    snmpv3_decode_pdu(netsnmp_buf *buf);
int             snmpv3_build_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf);

void user_session_defaults(  struct snmp_session *session, netsnmp_user *info);
void v3info_session_defaults(struct snmp_session *session, netsnmp_v3info *info);

int snmpv3_verify_msg(netsnmp_request *rp, netsnmp_pdu *pdu);
int engine_compare(netsnmp_engine *one, netsnmp_engine *two);

int priv_encrypt(netsnmp_buf *buf,
             netsnmp_v3info  *v3info,
             netsnmp_user    *userinfo);
int priv_decrypt(netsnmp_buf     *buf,
             netsnmp_v3info  *v3info,
             netsnmp_user *userinfo);
int auth_stamp_pre(netsnmp_buf *buf,
               netsnmp_v3info  *v3info,
               netsnmp_user    *userinfo);
int auth_stamp_post(netsnmp_buf *buf,
                netsnmp_v3info  *v3info,
                netsnmp_user    *userinfo,
                int              auth_len);
int auth_verify(netsnmp_buf     *buf,
               netsnmp_v3info  *v3info,
               netsnmp_user    *userinfo);

#endif /* _SNMPV3_SNMPV3_H */
