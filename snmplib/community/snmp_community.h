/*
 * FILE: snmp_community.h
 * File containing definitions needed by the community module.
 */

int netsnmp_community_build(u_char **pkt, size_t *pkt_len, size_t *offset,
            struct snmp_session *session, struct snmp_pdu *pdu);

