/*******************************
 *
 *	ucd_mib_api.c
 *
 *	Net-SNMP library - MIB-handling interface
 *
 *	Compatability with old UCD-SNMP mib API
 *	
 *******************************/

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>

#include <stdio.h>
#include <ctype.h>

#include <net-snmp/mib_api.h>
#include <net-snmp/var_api.h>
#include <smi.h>

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif

#include <ucd/ucd_api.h>

#include "default_store.h"

	/*
	 * Defined in 'mib_api(3)'
	 */
void init_mib (void)
{
    (void)mib_init( "mib" );
}
void init_mib_internals (void)
{
    (void)mib_init( "mib" );
}

int  add_mibdir (const char *dir)
{
    if ( mib_add_directories( (char*)dir ) < 0 ) {
	return -1;
    }
    return 99;	/* XXX */
}

void add_module_replacement (const char *old_mod, const char *new_mod, const char *tag, int len)
{
}
struct tree *read_module (const char *name)
{
    (void)mib_load_modules( (char*)name );
    return NULL;
}
struct tree *read_mib (const char *name)
{
    (void)mib_load_modules( (char*)name );
    return NULL;
}
struct tree *read_all_mibs (void)
{
    (void)mib_load_all( );
    return NULL;
}

void shutdown_mib (void)
{
    (void)mib_close_down( "mib" );
}

void print_mib (FILE *fp)
{
    mib_tree_dump( fp );
}

int read_objid (char *input, oid *output, int *out_len)
{
    struct netsnmp_oid_t  o;
    int i;

    memset( &o, 0, sizeof( struct netsnmp_oid_t ));
    if ( var_set_oid( &o, input ) < 0 ) {
	return 0;
    }

    
    *out_len = o.len;
    for ( i=0; i<o.len; i++ ) {
	output[i] = o.name[i];
    }
    return 1;
}

int get_module_node (char *name, char *module, oid *objid, int *objidlen)
{
    char *buf;
    int   i;

    if (( module == NULL )  ||
        ( *module == '\0' ) ||
	( strcasecmp( module, "ANY" ) == 0 )) {

	return(read_objid( name, objid, objidlen ));
    }

    if (( name == NULL ) ||
	( *name == '\0' )) {
	return 0;
    }

    i   = strlen( module ) + strlen( name ) + 2;
    buf = (char*)calloc( i+1, 1 );
    if ( buf == NULL ) {
	return 0;
    }

    sprintf( buf, "%s::%s", module, name );
    i = read_objid( buf, objid, objidlen );
    free( buf );
    return i;
}



netsnmp_mib mib_find_by_oid( netsnmp_oid o );
void fprint_description (FILE *fp, oid *objid, int objidlen)
{
    SmiNode *node;
    netsnmp_oid o;

    o = var_create_oid_ucd( objid, objidlen );
    node = (SmiNode*)mib_find_by_oid( o );

    if (( node != NULL ) &&
        ( node->description != NULL ) &&
        (*node->description != '\0' )) {
	fprintf( fp, "%s\n", node->description);
    }
}
void print_description (oid *objid, int objidlen)
{
    fprint_description( stdout, objid, objidlen);
}

void snmp_set_mib_warnings (int i)
{
    int flags;
    flags = smiGetFlags();

    switch (i){
    case 0:
	flags &= ~(SMI_FLAG_ERRORS | SMI_FLAG_RECURSIVE | SMI_FLAG_STATS );
	break;

    case 1:
	flags |=  SMI_FLAG_ERRORS;
	flags |=  SMI_FLAG_RECURSIVE;
	flags &= ~SMI_FLAG_STATS;
	break;

    case 2:
	flags |=  SMI_FLAG_ERRORS;
	flags |=  SMI_FLAG_RECURSIVE;
	flags |=  SMI_FLAG_STATS;
	break;

    default:
	return;
    }
    smiSetFlags( flags );
    return;
}
void snmp_set_save_descriptions (int i)
{
    int flags;
    flags = smiGetFlags();

    switch (i){
    case 0:
	flags |=  SMI_FLAG_NODESCR;
	break;

    case 1:
	flags &= ~SMI_FLAG_NODESCR;
	break;

    default:
	return;
    }
    smiSetFlags( flags );
    return;
}


	/*
	 * Declared in 'mib.h' or 'parse.h'
	 *    but not defined in 'mib_api(3)'
	 */

char *
snmp_out_toggle_options(char *options)
{
    while(*options) {
        switch(*options++) {
        case 'n':
            ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_OIDS);
            break;
        case 'e':
            ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM);
            break;
        case 'b':
            ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_DONT_BREAKDOWN_OIDS);
            break;
	case 'E':
	    ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_ESCAPE_QUOTES);
	    break;
	case 'X':
	    ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_EXTENDED_INDEX);
	    break;
	case 'q':
	    ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT);
	    break;
        case 'f':
            ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_FULL_OID);
	    break;
	case 't':
	    ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS);
	    break;
	case 'v':
	    ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_BARE_VALUE);
	    break;
        case 's':
	    snmp_set_suffix_only(1);
	    break;
        case 'S':
	    snmp_set_suffix_only(2);
	    break;
	case 'T':
	     ds_toggle_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT);
	     break;
        default:
	    return options-1;
	}
    }
    return NULL;
}
void snmp_mib_toggle_options_usage(const char *lead, FILE *outf) { }
struct tree *get_tree (oid *o, int len, struct tree *t)	{ return NULL; }
struct tree *get_tree_head (void)			{ return NULL; }


char *snmp_mib_toggle_options(char *o)			{return NULL; }
char *snmp_in_toggle_options( char *o)			{return NULL; }
void  snmp_in_toggle_options_usage( char *o, FILE *fp)	{ }
void  snmp_out_toggle_options_usage(char *o, FILE *fp)	{ }
oid *snmp_parse_oid (const char *name, oid *o, size_t *len )
{
    if (read_objid ((char *)name, o, len) == 0 ) {
	return NULL;
    }
    return o;
}

struct tree *find_tree_node (const char *name, int modid)
{
    SmiNode *node;
    struct tree *ucd_node = NULL;

    node = (SmiNode*)mib_find( (char *)name );
    if ( node == NULL ) {
	return NULL;
    }

	/* TODO: Convert 'node' into the old tree form */
    
    return ucd_node;
}


#ifdef NOT_IMPLEMENTED
	/*
	 * Declared in 'mib.h' or 'parse.h'
	 *    but not defined in 'mib_api(3)'
	 *    or used by basic applications
	 */

int unload_module(const char *name);
void print_ascii_dump (FILE *);
int get_node (char *, oid *, int *);
struct tree *get_symbol (oid *, int, struct tree *, char *);
void  set_function (struct tree *);
int  which_module (const char *);
char *module_name (int, char *);
void print_subtree (FILE *, struct tree *, int);
void print_ascii_dump_tree (FILE *, struct tree *, int);
const char *get_tc_descriptor (int);
struct tree *find_best_tree_node(const char *, struct tree *, u_int *);
 /* backwards compatability */
struct tree *find_node (const char *, struct tree*);
struct module *find_module (int);
void adopt_orphans (void);
void snmp_set_mib_errors (int);
void snmp_set_mib_comment_term (int);
void snmp_set_mib_parse_label (int);
void print_mib(FILE *);
void print_mib_tree(FILE *, struct tree *);
int  get_mib_parse_error_count(void);
int  snmp_get_token(FILE *fp, char *token, int maxtlen);
struct tree * find_best_tree_node(const char *name, struct tree *tree_top, u_int *match);
#endif
