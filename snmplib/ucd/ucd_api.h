
#ifndef _UCD_UCD_API_H
#define _UCD_UCD_API_H

#ifndef OPAQUE_SPECIAL_TYPES
#define OPAQUE_SPECIAL_TYPES
#endif
#define MAX_OID_LEN  128

#define USM_AUTH_KU_LEN     32
#define USM_PRIV_KU_LEN     32

#define SNMP_CMD_CONFIRMED(c) (c == SNMP_MSG_INFORM || c == SNMP_MSG_GETBULK ||\
                               c == SNMP_MSG_GETNEXT || c == SNMP_MSG_GET || \
                               c == SNMP_MSG_SET)

#define UCD_MSG_FLAG_RESPONSE_PDU            0x100
#define UCD_MSG_FLAG_EXPECT_RESPONSE         0x200
#define UCD_MSG_FLAG_FORCE_PDU_COPY          0x400
#define UCD_MSG_FLAG_ALWAYS_IN_VIEW          0x800
#define UCD_MSG_FLAG_PDU_TIMEOUT            0x1000

#define ASN1_H					/* XXX -  Liar! */
typedef u_long oid;

struct variable_list {
    struct variable_list *next_variable;    /* NULL for last variable */
    oid	    *name;  /* Object identifier of variable */
    size_t  name_length;    /* number of subid's in name */
    u_char  type;   /* ASN type of variable */
    union { /* value of variable */
	long	*integer;
	u_char	*string;
	oid	*objid;
	u_char  *bitstring;
	struct counter64 *counter64;
#ifdef OPAQUE_SPECIAL_TYPES
	float   *floatVal;
	double	*doubleVal;
/*	t_union *unionVal; */
#endif /* OPAQUE_SPECIAL_TYPES */
    } val;
    size_t	    val_len;
    oid name_loc[MAX_OID_LEN];  /* 90 percentile < 24. */
    u_char buf[40];             /* 90 percentile < 40. */
    void *data;			/* (Opaque) hook for additional data */
    void (*dataFreeHook)(void *);	/* callback to free above */
    int  index;
};

struct snmp_pdu {

	/*
	 * Protocol-version independent fields
	 */
    long    version;
    int	    command;	/* Type of this PDU */
    long    reqid;	/* Request id - note: not incremented on retries */
    long    msgid;      /* Message id for V3 messages 
                         * note: incremented for each retry */
    long    transid;    /* Unique ID for incoming transactions */
    long    sessid;     /* Session id for AgentX messages */
    long    errstat;	/* Error status (non_repeaters in GetBulk) */
    long    errindex;	/* Error index (max_repetitions in GetBulk) */
    u_long  time;	/* Uptime */
    u_long  flags;

    int	    securityModel;
    int	    securityLevel;  /* noAuthNoPriv, authNoPriv, authPriv */
    int	    msgParseModel;

    /*  Transport-specific opaque data.  This replaces the IP-centric address
	field.  */

    void  *transport_data;
    int    transport_data_length;

    /*  The actual transport domain.  This SHOULD NOT BE FREE()D.  */

    const oid *tDomain;
    size_t tDomainLen;

    struct variable_list *variables;


	/*
	 * SNMPv1 & SNMPv2c fields
	 */
    u_char  *community;		/* community for outgoing requests. */
    size_t  community_len;	/* Length of community name. */

	/*
	 * Trap information
	 */
    oid	    *enterprise;	/* System OID */
    size_t  enterprise_length;
    long    trap_type;		/* trap type */
    long    specific_type;	/* specific type */
    unsigned char agent_addr[4];	/* This is ONLY used for v1 TRAPs  */

	/*
	 * SNMPv3 fields
	 */
    u_char  *contextEngineID;	/* context snmpEngineID */
    size_t  contextEngineIDLen; /* Length of contextEngineID */
    char    *contextName;	/* authoritative contextName */
    size_t  contextNameLen;	/* Length of contextName */
    u_char  *securityEngineID;	/* authoritative snmpEngineID for security */
    size_t  securityEngineIDLen;/* Length of securityEngineID */
    char    *securityName;	/* on behalf of this principal */
    size_t  securityNameLen;	/* Length of securityName. */

	/*
	 * AgentX fields
	 *	(also uses SNMPv1 community field)
	 */
    int	    priority;
    int	    range_subid;

    void * securityStateRef;
};


struct snmp_session;
typedef int (*snmp_callback) (int, struct snmp_session *, int, struct snmp_pdu *, void *);

struct snmp_session {
	/*
	 * Protocol-version independent fields
	 */
    long  version;
    int	    retries;	/* Number of retries before timeout. */
    long    timeout;    /* Number of uS until first timeout, then exponential backoff */
    u_long  flags;
    struct  snmp_session *subsession;
    struct  snmp_session *next;

    char    *peername;	/* Domain name or dotted IP address of default peer */
    u_short remote_port;/* UDP port number of peer. */
    u_short local_port; /* My UDP port number, 0 for default, picked randomly */
    /* Authentication function or NULL if null authentication is used */
    u_char    *(*authenticator) (u_char *, size_t *, u_char *, size_t);
    snmp_callback callback; /* Function to interpret incoming data */
    /* Pointer to data that the callback function may consider important */
    void    *callback_magic;

    int     s_errno;        /* copy of system errno */
    int     s_snmp_errno;   /* copy of library errno */
    long    sessid;         /* Session id - AgentX only */

	/*
	 * SNMPv1 & SNMPv2c fields
	 */
    u_char  *community;	        /* community for outgoing requests. */
    size_t  community_len;      /* Length of community name. */

    size_t  rcvMsgMaxSize;	/*  Largest message to try to receive.  */
    size_t  sndMsgMaxSize;	/*  Largest message to try to send.  */
  
	/*
	 * SNMPv3 fields
	 */
    u_char  isAuthoritative;    /* are we the authoritative engine? */
    u_char  *contextEngineID;	/* authoritative snmpEngineID */
    size_t  contextEngineIDLen; /* Length of contextEngineID */
    u_int   engineBoots;        /* initial engineBoots for remote engine */
    u_int   engineTime;         /* initial engineTime for remote engine */
    char    *contextName;	/* authoritative contextName */
    size_t  contextNameLen;     /* Length of contextName */
    u_char  *securityEngineID;	/* authoritative snmpEngineID */
    size_t  securityEngineIDLen;  /* Length of contextEngineID */
    char    *securityName;	/* on behalf of this principal */
    size_t  securityNameLen;    /* Length of securityName. */
    oid     *securityAuthProto; /* auth protocol oid */
    size_t  securityAuthProtoLen; /* Length of auth protocol oid */
    u_char  securityAuthKey[USM_AUTH_KU_LEN];  /* Ku for auth protocol XXX */
    size_t  securityAuthKeyLen; /* Length of Ku for auth protocol */
    oid     *securityPrivProto; /* priv protocol oid */
    size_t  securityPrivProtoLen; /* Length of priv protocol oid */
    u_char  securityPrivKey[USM_PRIV_KU_LEN];  /* Ku for privacy protocol XXX */
    size_t  securityPrivKeyLen; /* Length of Ku for priv protocol */
    int	    securityModel;
    int	    securityLevel;  /* noAuthNoPriv, authNoPriv, authPriv */

    /* security module specific */
    void    *securityInfo;
};


void snmp_set_suffix_only(int);

#endif /* _UCD_UCD_API_H */
