/*******************************
 *
 *      net-snmp/var_api.h
 *
 *      Net-SNMP library - Variable-handling public interface
 *
 *******************************/

#ifndef _NET_SNMP_VAR_API_H
#define _NET_SNMP_VAR_API_H

#include <stdio.h>
#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/types.h>


        /* OID-related routines */

netsnmp_oid* oid_create(       void                  );
netsnmp_oid* oid_create_name(  char   *name          );
netsnmp_oid* oid_create_value( u_int  *name, int len );
netsnmp_oid* oid_copy(      netsnmp_oid *oid                        );
int          oid_set_name(  netsnmp_oid *oid, char   *name          );
int          oid_set_value( netsnmp_oid *oid, u_int  *name, int len );
void         oid_free(      netsnmp_oid *oid                        );

int   oid_bprint( netsnmp_buf *buf,   netsnmp_oid *oid );
char* oid_sprint( char *buf, int len, netsnmp_oid *oid );
void  oid_fprint( FILE *fp,           netsnmp_oid *oid );
void  oid_print(                      netsnmp_oid *oid );


        /* Value-related routines */

netsnmp_value* var_create_value( void                                               );
netsnmp_value* var_create_set_value(                   char *val, int len, int type );
netsnmp_value* var_copy_value(   netsnmp_value *value                               );
int            var_set_value(    netsnmp_value *value, char *val, int len, int type );
void           var_free_value(   netsnmp_value *value                               );

int   var_bprint_value( netsnmp_buf* buf,       netsnmp_value *value, netsnmp_mib *mib );
char* var_sprint_value( char *str_buf, int len, netsnmp_value *value, netsnmp_mib *mib );
void  var_fprint_value( FILE *fp,               netsnmp_value *value, netsnmp_mib *mib );
void  var_print_value(                          netsnmp_value *value, netsnmp_mib *mib );


        /* Varbind-related routines */

netsnmp_varbind* var_create_varbind( void                                                      );
netsnmp_varbind* var_create_set_varbind(                netsnmp_oid *oid, netsnmp_value *value );
netsnmp_varbind* var_copy_varbind( netsnmp_varbind *vb                                         );
int              var_set_varbind(  netsnmp_varbind *vb, netsnmp_oid *oid, netsnmp_value *value );
void             var_free_varbind( netsnmp_varbind *vb                                         );

int   var_bprint_varbind( netsnmp_buf *buf,       netsnmp_varbind *varbind );
char* var_sprint_varbind( char *str_buf, int len, netsnmp_varbind *varbind );
void  var_fprint_varbind( FILE *fp,               netsnmp_varbind *varbind );
void  var_print_varbind(                          netsnmp_varbind *varbind );


        /* Varbind-list-related routines */

int              vblist_add_varbind(     netsnmp_varbind *vblist, netsnmp_varbind *varbind );
netsnmp_varbind* vblist_return_varbind(  netsnmp_varbind *vblist, int idx                  );
netsnmp_varbind* vblist_extract_varbind( netsnmp_varbind *vblist, int idx                  );
void             vblist_free(            netsnmp_varbind *vblist                           );

int   vblist_bprint( netsnmp_buf *buf,       netsnmp_varbind *vblist );
char* vblist_sprint( char *str_buf, int len, netsnmp_varbind *vblist );
void  vblist_fprint( FILE *fp,               netsnmp_varbind *vblist );
void  vblist_print(                          netsnmp_varbind *vblist );

#endif /* _NET_SNMP_VAR_API_H */
