/*******************************
 *
 *	net-snmp/mib_api.h
 *
 *	Net-SNMP library - MIB-handling public interface
 *
 *******************************/

#ifndef _NET_SNMP_MIB_API_H
#define _NET_SNMP_MIB_API_H

#include <stdio.h>
#include <net-snmp/struct.h>
#include <net-snmp/utils.h>

#define	NETSNMP_MIBERR_NOERROR		 0
#define	NETSNMP_MIBERR_GENERROR		-1
#define	NETSNMP_MIBERR_NOTFOUND		-2
#define	NETSNMP_MIBERR_NOTLOADED	-3
#define	NETSNMP_MIBERR_DUPLICATE	-4

#ifndef PATH_SEPARATOR
#define PATH_SEPARATOR ':'
#endif

int mib_init(       char *tags );
int mib_close_down( char *tags );

	/* Directory-related routines */

char* mib_list_directories(   void      );
int   mib_set_directories(    char *dir );
int   mib_add_directories(    char *dir );
int   mib_remove_directories( char *dir );

	/* File- and module-related routines */

char* mib_list_modules(   void         );
int   mib_load_modules(   char *list   );
int   mib_load_all(       void         );
int   mib_unload_modules( char *list   );
int   mib_unload_all(     void         );
char* mib_module_to_file( char *name   );

	/* Object-related routines */

typedef	void (mibtree_callback)(netsnmp_mib mib, void* data);

netsnmp_mib     mib_find(        char       *name );
netsnmp_mib     mib_find_by_oid( netsnmp_oid oid );
netsnmp_oid     mib_objectid(    netsnmp_mib mib );
netsnmp_varbind mib_varbind(     netsnmp_mib mib, int value );
void            mib_tree_walk(   mibtree_callback callback, void* data);
void            mib_tree_dump(   FILE *fp );

	/* Output routines */

int   mib_bprint( netsnmp_buf buf,    netsnmp_mib mib );
char *mib_sprint( char *buf, int len, netsnmp_mib mib );
void  mib_fprint( FILE *fp,           netsnmp_mib mib );
void  mib_print(                      netsnmp_mib mib );

#endif /* _NET_SNMP_MIB_API_H */
