/*******************************
 *
 *	net-snmp/var_api.h
 *
 *	Net-SNMP library - Variable-handling public interface
 *
 *******************************/

#ifndef _NET_SNMP_VAR_API_H
#define _NET_SNMP_VAR_API_H

#include <stdio.h>
#include <net-snmp/struct.h>


	/* OID-related routines */


netsnmp_oid var_create_oid(       void                  );
netsnmp_oid var_create_oid_name(  char   *name          );
netsnmp_oid var_create_oid_value( u_long *name, int len );
int         var_set_oid(       netsnmp_oid oid, char   *name          );
int         var_set_oid_value( netsnmp_oid oid, u_long *name, int len );
char*       var_sprint_oid( char *buf, int len, netsnmp_oid oid );
void        var_fprint_oid( FILE *fp,           netsnmp_oid oid );
void        var_print_oid(                      netsnmp_oid oid );


#endif /* _NET_SNMP_VAR_API_H */
