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
#include <net-snmp/protocol_api.h>
#include <ucd/ucd_api.h>
#include <ucd/ucd_convert.h>


#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif



netsnmp_mib*
mib_find_by_oid( netsnmp_oid *o );
char *sprint_value (char *buf, oid *objid, int objidlen, struct variable_list *var)
{
    netsnmp_value *val;
    netsnmp_mib   *mib;
    char          *cp;
    netsnmp_oid   *o;

    val = ucd_convert_value( var );
    if ( val == NULL ) {
	return NULL;
    }
    o = ucd_convert_oid( objid, objidlen );
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
    return oid_sprint( buf, SPRINT_MAX_LEN,
			ucd_convert_oid(objid, objidlen));
}
int
sprint_realloc_objid(u_char **buf, size_t *buf_len,
		     size_t *out_len, int allow_realloc, 
		     oid *objid, size_t objidlen)
{
    char *cp;

    cp = oid_sprint( *buf, *buf_len,
			ucd_convert_oid(objid, objidlen));
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
    netsnmp_varbind *vblist;
    char *cp;


    memset( val_buf, 0, SPRINT_MAX_LEN );
    vblist = ucd_convert_vblist( var );
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
    netsnmp_varbind *varbind;
    char *cp;

    varbind = ucd_convert_varbind( var );
    if ( varbind == NULL ) {
	return NULL;
    }
    oid_free( varbind->oid );
    varbind->oid = ucd_convert_oid( objid, objidlen );
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
void print_pdu (struct snmp_pdu *pdu)
{
    netsnmp_pdu *p;
    p = ucd_convert_pdu( pdu );
    pdu_print( p );
    /* pdu_free( p ); */
}


int val_print_string( netsnmp_buf *buf,  char *string, int strlen, netsnmp_mib *mib );
int val_print_hexstr( netsnmp_buf *buf,  char *string, int strlen, netsnmp_mib *mib );
void sprint_hexstring(char *str_buf, const u_char *cp, size_t len)
{
    netsnmp_buf *buf;

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
    netsnmp_buf *buf;

    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return;
    }
    if ( val_print_string( buf, cp, len, NULL ) == 0 ) {
	strcpy( str_buf, buffer_string( buf ));
    }
    buffer_free( buf );
}
