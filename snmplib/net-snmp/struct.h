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
#define NETSNMP_MAX_PACKET_LEN  1500

#ifndef FALSE
#define FALSE 0
#endif
#ifndef TRUE
#define TRUE 1
#endif

#define SNMP_CALLBACK_OP_RECEIVED_MESSAGE	1
#define SNMP_CALLBACK_OP_TIMED_OUT		2
#define SNMP_CALLBACK_OP_SEND_FAILED		3
#define SNMP_CALLBACK_OP_CONNECT		4
#define SNMP_CALLBACK_OP_DISCONNECT		5

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
    long                 boots;
    long                 time;
};

typedef struct netsnmp_comminfo_s {
    int                  ref_count;
    int                  len;
    u_char              *string;
    u_char               buf[NETSNMP_NAMEBUF_LEN];
} netsnmp_comminfo;

typedef struct netsnmp_v3info_s {
	/* Header Data */
    long                 msgID;
    long                 msg_max_size;
    u_char               v3_flags;
    long                 sec_level;
    long                 sec_model;
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
    netsnmp_buf         *auth_params;

    int                  priv_protocol;
    netsnmp_buf         *priv_key;
    netsnmp_buf         *priv_params;
    
};


struct netsnmp_pdu_s {
          /* Incomplete, and subject to change.... */
    long                 version;
    long                 command;
    long                 errindex;
    long                 errstatus;
    long                 request;
    long                 flags;
    long                 timeout;

    netsnmp_varbind     *varbind_list;
    netsnmp_comminfo    *community;
    netsnmp_v3info      *v3info;
    netsnmp_user        *userinfo;

    void *transport_data;
    int   transport_data_length;
};



typedef struct _snmp_transport   netsnmp_transport;	/* XXX - Temp */
typedef struct netsnmp_session_s netsnmp_session;
typedef struct netsnmp_request_s netsnmp_request;

typedef int (NetSnmpPreParseHook)  (netsnmp_session*, netsnmp_transport*, void*, int);
typedef netsnmp_pdu* (NetSnmpParseHook) (netsnmp_buf*);
typedef int (NetSnmpPostParseHook) (netsnmp_session*, netsnmp_pdu*);
typedef int (NetSnmpBuildHook)     (netsnmp_session*, netsnmp_pdu*, netsnmp_buf *);
typedef int (NetSnmpCheckHook)     (u_char*, size_t);
typedef int (NetSnmpCallback)    (int, netsnmp_session*, int, void*, void*);

typedef struct netsnmp_hooks_s {
    NetSnmpPreParseHook  *hook_pre;
    NetSnmpParseHook     *hook_parse;
    NetSnmpPostParseHook *hook_post;
    NetSnmpBuildHook     *hook_build;
    NetSnmpCheckHook     *check_packet;
    NetSnmpCallback      *callback;
    void                 *callback_magic;
} netsnmp_hooks;


struct netsnmp_session_s {
    netsnmp_session     *prev;
    netsnmp_session     *next;

    int                  version;
    int                  flags;
    int                  retries;
    int                  timeout;

    int			 snmp_errno;
    int			 sys_errno;
    char		*err_detail;


    netsnmp_comminfo    *read_community;
    netsnmp_comminfo    *write_community;

    netsnmp_v3info      *v3info;
    netsnmp_user        *userinfo;

    netsnmp_transport   *transport;
    netsnmp_buf         *rxbuf;
    netsnmp_hooks       *hooks;
    int                  sndMsgMaxSize;

    netsnmp_request     *request_head;
    netsnmp_request     *request_tail;

    
};

struct netsnmp_request_s {
    netsnmp_request    *next, *prev;
    long                request_id;	/* request id */
    long                message_id;	/* message id */
    NetSnmpCallback    *callback; /* user callback per request (NULL if unused) */
    void               *cb_data;   /* user callback data per request (NULL if unused) */
    int                 retries;	/* Number of retries */
    u_long              timeout;	/* length to wait for timeout */
    struct timeval      time; /* Time this request was made */
    struct timeval      expire;  /* time this request is due to expire */
    netsnmp_session    *session;
    netsnmp_pdu        *pdu;   /* The pdu for this request
			       (saved so it can be retransmitted */
};

#endif /* _NET_SNMP_STRUCT_H */
