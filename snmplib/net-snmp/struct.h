/*******************************
 *
 *      net-snmp/struct.h
 *
 *      Net-SNMP library - Data structures
 *
 *******************************/


        /* Mostly just placeholders.... */

#ifndef _NET_SNMP_STRUCT_H
#define _NET_SNMP_STRUCT_H

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif

#define NETSNMP_NAMEBUF_LEN     16
#define NETSNMP_VALBUF_LEN      30

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#include <smi.h>
typedef SmiNode netsnmp_mib;


typedef struct netsnmp_oid_s {
    unsigned int        *name;
    unsigned int         len;
    unsigned int         namebuf[ NETSNMP_NAMEBUF_LEN ];
} netsnmp_oid;

typedef struct counter64        int64;

typedef struct netsnmp_value_s {
    int          type;
    int          len;
    union {
        long            *integer;
        u_char          *string;
        netsnmp_oid     *oid;
        int64           *integer64;
        float           *floatVal;
        double          *doubleVal;
    }           val;

    u_char         valbuf[ NETSNMP_VALBUF_LEN ];

} netsnmp_value;


typedef struct netsnmp_varbind_s netsnmp_varbind;
typedef struct netsnmp_pdu_s     netsnmp_pdu;

struct netsnmp_varbind_s {
    netsnmp_varbind     *prev, *next;
    netsnmp_pdu         *pdu;
    netsnmp_oid         *oid;
    netsnmp_value       *value;
};

struct netsnmp_pdu_s {
          /* Incomplete, and subject to change.... */
    int                  version;
    int                  command;
    int                  errindex;
    int                  errstatus;
    int                  request;
    netsnmp_varbind     *varbind_list;
};

#endif /* _NET_SNMP_STRUCT_H */
