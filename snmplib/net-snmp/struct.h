/*******************************
 *
 *	net-snmp/struct.h
 *
 *	Net-SNMP library - Data structures
 *
 *******************************/


	/* Mostly just placeholders.... */

#ifndef _NET_SNMP_STRUCT_H
#define _NET_SNMP_STRUCT_H

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif

#define NETSNMP_NAMEBUF_LEN	16
#define NETSNMP_VALBUF_LEN	30

#include <smi.h>
typedef SmiNode *netsnmp_mib;


typedef struct netsnmp_oid_t {
    unsigned int	*name;
    unsigned int	 len;
    unsigned int	 namebuf[ NETSNMP_NAMEBUF_LEN ];
} *netsnmp_oid;

typedef struct counter64	int64;

typedef struct netsnmp_value_t {
    int		 type;
    int		 len;
    union {
	long		*integer;
	u_char		*string;
	netsnmp_oid	 oid;
	int64		*integer64;
	float		*floatVal;
	double		*doubleVal;
    }		val;

    char	 valbuf[ NETSNMP_VALBUF_LEN ];

} netsnmp_value;


typedef struct netsnmp_varbind_t {
    netsnmp_oid		oid;
    netsnmp_value	value;
} *netsnmp_varbind;



#endif /* _NET_SNMP_STRUCT_H */
