/*******************************
 *
 *      net-snmp/struct.h
 *
 *      Net-SNMP library - Data structures
 *
 *******************************/

#ifndef _NET_SNMP_STRUCT_H
#define _NET_SNMP_STRUCT_H


        /* Mostly just placeholders.... */

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


typedef struct netsnmp_oid_s {
    unsigned int        *name;
    unsigned int         len;
    unsigned int         namebuf[ NETSNMP_NAMEBUF_LEN ];
} netsnmp_oid;

#include <net-snmp/utils.h>
#include <net-snmp/types.h>

#include <smi.h>
typedef SmiNode netsnmp_mib;


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
typedef struct netsnmp_engine_s  netsnmp_engine;
typedef struct netsnmp_user_s    netsnmp_user;

struct netsnmp_varbind_s {
    netsnmp_varbind     *prev, *next;
    netsnmp_pdu         *pdu;
    netsnmp_oid         *oid;
    netsnmp_value       *value;
};

struct netsnmp_engine_s {
    netsnmp_engine      *prev, *next;
    int                  ref_count;
    netsnmp_buf         *ID;
    int                  boots;
    int                  time;
};

typedef struct netsnmp_comminfo_s {
    int                  ref_count;
    int                  len;
    u_char              *string;
    u_char               buf[NETSNMP_NAMEBUF_LEN];
} netsnmp_comminfo;

typedef struct netsnmp_v3info_s {
	/* Header Data */
    int                  msgID;
    int                  msg_max_size;
    u_char               v3_flags;
    int                  sec_level;
    int                  sec_model;
	/* Scoped PDU context data */
    netsnmp_engine      *context_engine;
    netsnmp_buf         *context_name;

    int                  auth_saved_len;
} netsnmp_v3info;


struct netsnmp_user_s {
    netsnmp_user        *prev, *next;
    int                  ref_count;

    netsnmp_buf         *user_name;
    netsnmp_buf         *sec_name;
    netsnmp_engine      *sec_engine;

    int                  auth_protocol;
    netsnmp_buf         *auth_key;

    int                  priv_protocol;
    netsnmp_buf         *priv_key;
    netsnmp_buf         *priv_params;
    
};


struct netsnmp_pdu_s {
          /* Incomplete, and subject to change.... */
    int                  version;
    int                  command;
    int                  errindex;
    int                  errstatus;
    int                  request;
    int                  flags;
    netsnmp_varbind     *varbind_list;
    netsnmp_comminfo    *community;
    netsnmp_v3info      *v3info;
    netsnmp_user        *userinfo;
};



#endif /* _NET_SNMP_STRUCT_H */
