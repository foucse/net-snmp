/*******************************
 *
 *	net-snmp/types.h
 *
 *	Net-SNMP library - Data types and definitions
 *
 *******************************/



#ifndef _NET_SNMP_TYPES_H
#define _NET_SNMP_TYPES_H

	/* Base ASN.1 types */
#define ASN_BOOLEAN         ((u_char)0x01)
#define ASN_INTEGER         ((u_char)0x02)
#define ASN_BIT_STR         ((u_char)0x03)
#define ASN_OCTET_STR       ((u_char)0x04)
#define ASN_NULL            ((u_char)0x05)
#define ASN_OBJECT_ID       ((u_char)0x06)
#define ASN_SEQUENCE        ((u_char)0x10)
#define ASN_SET             ((u_char)0x11)

#define ASN_UNIVERSAL       ((u_char)0x00)
#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_CONTEXT         ((u_char)0x80)
#define ASN_PRIVATE         ((u_char)0xC0)

#define ASN_PRIMITIVE       ((u_char)0x00)
#define ASN_CONSTRUCTOR     ((u_char)0x20)


	/* Defined types: SMIv1 - RFC 1155 */
#define ASN_IPADDRESS   (ASN_APPLICATION | 0)
#define ASN_COUNTER     (ASN_APPLICATION | 1)
#define ASN_GAUGE       (ASN_APPLICATION | 2)
#define ASN_TIMETICKS   (ASN_APPLICATION | 3)
#define ASN_OPAQUE      (ASN_APPLICATION | 4)

	/* Defined types: SMIv2 - RFC 1902/2578 */
#define ASN_UNSIGNED    (ASN_APPLICATION | 2)  /* same as GAUGE */
#define ASN_NSAP        (ASN_APPLICATION | 5)  /* historic - don't use */
#define ASN_COUNTER64   (ASN_APPLICATION | 6)
#define ASN_UINTEGER    (ASN_APPLICATION | 7)  /* historic - don't use */

	/* Opaque Special Types: draft-perkins-opaque-01.txt */
#define ASN_FLOAT       (ASN_APPLICATION | 8)
#define ASN_DOUBLE      (ASN_APPLICATION | 9)
#define ASN_INTEGER64   (ASN_APPLICATION | 10)
#define ASN_UNSIGNED64  (ASN_APPLICATION | 11)


struct counter64 {
    u_long high;
    u_long low;
};
typedef struct counter64 integer64;
typedef struct counter64 unsigned64;


#endif /* _NET_SNMP_TYPES_H */
