#ifndef COMMUNITY_COMMUNITY_H
#define COMMUNITY_COMMUNITY_H

int               comminfo_encode(netsnmp_buf *buf, netsnmp_comminfo *info);
netsnmp_comminfo* comminfo_decode(netsnmp_buf *buf);
netsnmp_pdu*     community_decode_pdu(netsnmp_buf *buf);
int              community_build_pdu( netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf);
extern void snmp_set_detail (const char *);

#endif /* COMMUNITY_COMMUNITY_H */
