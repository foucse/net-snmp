/*******************************
 *
 *      net-snmp/types.h
 *
 *      Net-SNMP library - Data types and definitions
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
#define ASN_PRIMITIVE       ((u_char)0x00)
#define ASN_CONSTRUCTOR     ((u_char)0x20)
#define ASN_APPLICATION     ((u_char)0x40)
#define ASN_CONTEXT         ((u_char)0x80)
#define ASN_PRIVATE         ((u_char)0xC0)


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

	/* Exception pseudo-types */
#define SNMP_NOSUCHOBJECT    (ASN_CONTEXT | ASN_PRIMITIVE | 0x0)
#define SNMP_NOSUCHINSTANCE  (ASN_CONTEXT | ASN_PRIMITIVE | 0x1)
#define SNMP_ENDOFMIBVIEW    (ASN_CONTEXT | ASN_PRIMITIVE | 0x2)


struct counter64 {
    u_long high;
    u_long low;
};
typedef struct counter64 integer64;
typedef struct counter64 unsigned64;


#define SNMP_MSG_GET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x0)
#define SNMP_MSG_GETNEXT    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x1)
#define SNMP_MSG_RESPONSE   (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x2)
#define SNMP_MSG_SET        (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x3)
#define SNMP_MSG_TRAP       (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x4)
#define SNMP_MSG_GETBULK    (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x5)
#define SNMP_MSG_INFORM     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x6)
#define SNMP_MSG_TRAP2      (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x7)
#define SNMP_MSG_REPORT     (ASN_CONTEXT | ASN_CONSTRUCTOR | 0x8)



#define SNMP_VERSION_1      0
#define SNMP_VERSION_2c    1
#define SNMP_VERSION_2u    2 		/* Not supported */
#define SNMP_VERSION_3     3   
#define SNMP_VERSION_sec   128		/* Not supported */
#define SNMP_VERSION_2p    129		/* Not supported */
#define SNMP_VERSION_2star 130		/* Not supported */

#define SNMP_DEFAULT_VERSION         -1		
#define SNMP_VERSION_ANY             -2		
#define SNMP_VERSION_ANYC            -3		/* Any Community-based */

#endif /* _NET_SNMP_TYPES_H */
