/*******************************
 *
 *	ucd_varbind.c
 *
 *	Net-SNMP library - Variable-handling interface
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

#include <net-snmp/var_api.h>
#include <ucd/ucd_api.h>

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif




   /**
    *
    *  Set the OID to the UCD-style list of subidentifier values specified.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int var_set_oid_ucd( netsnmp_oid oid, u_long *name, int len )
{
    u_int name2[ MAX_OID_LEN ];
    int i;

    for ( i=0; i<len; i++ ) {
	name2[i] = name[i];
    }
    return var_set_oid_value( oid, name2, len );
}


   /**
    *
    *  Create a new OID structure and set it to the UCD-style value specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid var_create_oid_ucd( u_long *name, int len )
{
    netsnmp_oid oid;

    oid = var_create_oid();

    if (var_set_oid_ucd( oid, name, len ) < 0 ) {
	if ( oid ) {
	    free( oid );
	}
	oid = NULL;
    }
    return oid;
}


netsnmp_value var_convert_ucd2net_value( struct variable_list *v )
{
    netsnmp_value val;

    val = (netsnmp_value)calloc(1, sizeof( struct netsnmp_value_t ));
    if ( val == NULL ) {
	return NULL;
    }

    val->type = v->type;

		/*
		 * OBJECT ID values use the appropriate internal data
		 *   structure, rather than the UCD-style raw values,
		 *   so this needs to be handled separately.
		 */
    if ( v->type == ASN_OBJECT_ID ) {
	val->val.oid = var_create_oid_ucd( v->val.objid, v->val_len/sizeof(oid));
        val->len     = sizeof( struct netsnmp_oid_t );
	return val;
    }

    val->len  = v->val_len;
    if ( v->val.string != v->buf ) {
	val->val.string = v->val.string;
	v->val.string   = NULL;		/* XXX - ish.... */
    }
    else {
	val->val.string = val->valbuf;
	memcpy( v->buf, val->valbuf, NETSNMP_VALBUF_LEN );
    }

    return val;
}

netsnmp_varbind var_convert_ucd2net_varbind( struct variable_list *v )
{
    netsnmp_varbind vb;

    vb = (netsnmp_varbind)calloc(1, sizeof( struct netsnmp_varbind_t ));
    if ( vb == NULL ) {
	return NULL;
    }
    vb->oid   = var_create_oid_ucd( v->name, v->name_length );
    if ( vb->oid == NULL ) {
	var_free_varbind( vb );
	return NULL;
    }

		/*
		 * OBJECT ID values use the appropriate internal data
		 *   structure, rather than the UCD-style raw values,
		 *   so this needs to be handled separately.
		 */
    if ( v->type == ASN_OBJECT_ID ) {
	vb->value = var_create_value();
	if ( vb->value ) {
	    vb->value->val.oid = var_create_oid_ucd( v->val.objid, v->val_len/sizeof(oid));
	    vb->value->len     = sizeof( struct netsnmp_oid_t );
	    vb->value->type    = ASN_OBJECT_ID;
	}
    }
    else {
	vb->value = var_create_set_value( v->val.string, v->val_len, v->type );
    }
    if ( vb->value == NULL ) {
	var_free_varbind( vb );
	return NULL;
    }

    return vb;
}

netsnmp_varbind var_convert_ucd2net_vblist( struct variable_list *var )
{
    netsnmp_varbind varbind, vblist;
    struct variable_list *v;

    vblist = NULL;
    for ( v = var; v!=NULL; v=v->next_variable ) {
	varbind = var_convert_ucd2net_varbind( v );
	if ( vblist == NULL ) {
	    vblist=varbind;
	}
	else {
	    (void)vblist_add_varbind( vblist, varbind );
	}
    }
    return vblist;
}



netsnmp_mib mib_find_by_oid( netsnmp_oid o );
char *sprint_value (char *buf, oid *objid, int objidlen, struct variable_list *var)
{
    netsnmp_value val;
    netsnmp_mib   mib;
    char *cp;
    netsnmp_oid o;

    val = var_convert_ucd2net_value( var );
    if ( val == NULL ) {
	return NULL;
    }
    o = var_create_oid_ucd( objid, objidlen );
    mib = mib_find_by_oid( o );

    cp = var_sprint_value( buf, SPRINT_MAX_LEN, val, mib );
    var_free_value( val );
    return cp;
}
void fprint_value (FILE *fp, oid *objid, int objidlen, struct variable_list *var)
{
    char buf[SPRINT_MAX_LEN];
    memset( buf, 0, SPRINT_MAX_LEN );
    sprint_value(buf, objid, objidlen, var);
    fprintf(fp, "%s\n", buf);
}
void print_value (oid *objid, int objidlen, struct variable_list *var)
{
    fprint_value( stdout, objid, objidlen, var );
}

char *sprint_objid (char *buf, oid *objid, int objidlen)
{
    return var_sprint_oid( buf, SPRINT_MAX_LEN,
			var_create_oid_ucd(objid, objidlen));
}
int
sprint_realloc_objid(u_char **buf, size_t *buf_len,
		     size_t *out_len, int allow_realloc, 
		     oid *objid, size_t objidlen)
{
    char *cp;

    cp = var_sprint_oid( *buf, *buf_len,
			var_create_oid_ucd(objid, objidlen));
    if ( !cp ) {
	return 0;
    }
    return 1;
}

void fprint_objid (FILE *fp, oid *objid, int objidlen)
{
    char buf[SPRINT_MAX_LEN];
    memset( buf, 0, SPRINT_MAX_LEN );
    sprint_objid(buf, objid, objidlen);
    fprintf(fp, "%s\n", buf);
}
void print_objid (oid *objid, int objidlen)
{
    fprint_objid( stdout, objid, objidlen);
}

char *sprint_variable_list (char *buf, oid *objid, int objidlen, struct variable_list *var)
{
    char val_buf[SPRINT_MAX_LEN];
    netsnmp_varbind vblist;
    char *cp;


    memset( val_buf, 0, SPRINT_MAX_LEN );
    vblist = var_convert_ucd2net_vblist( var );
    cp = vblist_sprint( val_buf, SPRINT_MAX_LEN, vblist );
    if ( cp ) {
	strcpy( buf, cp );
	cp = buf;
    }
    /* vblist_free( vblist ); */

    return cp;
}

char *sprint_variable (char *buf, oid *objid, int objidlen, struct variable_list *var)
{
    char val_buf[SPRINT_MAX_LEN];
    netsnmp_varbind varbind;
    char *cp;

    varbind = var_convert_ucd2net_varbind( var );
    if ( varbind == NULL ) {
	return NULL;
    }
    var_free_oid( varbind->oid );
    varbind->oid = var_create_oid_ucd( objid, objidlen );
    if ( varbind->oid == NULL ) {
	var_free_varbind( varbind );
	return NULL;
    }

    memset( val_buf, 0, SPRINT_MAX_LEN );
    cp = var_sprint_varbind( val_buf, SPRINT_MAX_LEN, varbind );
    if ( cp ) {
	strcpy( buf, cp );
	cp = buf;
    }
    var_free_varbind( varbind );

    return cp;
}
int
sprint_realloc_variable(u_char **buf, size_t *buf_len,
			size_t *out_len, int allow_realloc,
			oid *objid, size_t objidlen,
			struct variable_list *variable)
{
    char *cp;

		/* Yes - I know - wimp-out! */
    cp = sprint_variable( *buf, objid, objidlen, variable );
    if ( !cp ) {
	return 0;
    }
    return 1;
}


void fprint_variable (FILE *fp, oid *objid, int objidlen, struct variable_list *var)
{
    char buf[SPRINT_MAX_LEN];
    memset( buf, 0, SPRINT_MAX_LEN );
    sprint_variable(buf, objid, objidlen, var);
    fprintf(fp, "%s\n", buf);
}
void print_variable (oid *objid, int objidlen, struct variable_list *var)
{
    fprint_variable( stdout, objid, objidlen, var );
}


int val_print_string( netsnmp_buf buf,  char *string, int strlen, netsnmp_mib mib );
int val_print_hexstr( netsnmp_buf buf,  char *string, int strlen, netsnmp_mib mib );
void sprint_hexstring(char *str_buf, const u_char *cp, size_t len)
{
    netsnmp_buf buf;

    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return;
    }
    if ( val_print_hexstr( buf, cp, len, NULL ) == 0 ) {
	strcpy( str_buf, buffer_string( buf ));
    }
    buffer_free( buf );
}
void sprint_asciistring(char *str_buf, const u_char *cp, size_t len)
{
    netsnmp_buf buf;

    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return;
    }
    if ( val_print_string( buf, cp, len, NULL ) == 0 ) {
	strcpy( str_buf, buffer_string( buf ));
    }
    buffer_free( buf );
}
