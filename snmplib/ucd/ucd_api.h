
#ifndef _UCD_UCD_API_H
#define _UCD_UCD_API_H

#define OPAQUE_SPECIAL_TYPES
#define MAX_OID_LEN  128


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


#endif /* _UCD_UCD_API_H */
