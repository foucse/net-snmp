/*******************************
 *
 *	varbind/oid.c
 *
 *	Net-SNMP library - Variable-handling interface
 *
 *	OID-handling routines
 *
 *******************************/

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>

#include <net-snmp/var_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/utils.h>

#include "default_store.h"

int _var_append_subids( netsnmp_oid oid, char *name, netsnmp_mib mib );


		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/varbind_api.h>)
		 *
		 **************************************/
		/** @package varbind_api */


   /**
    *
    *  Set the OID to the name specified.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int var_set_oid( netsnmp_oid oid, char *name )
{
    netsnmp_mib mib;

    if (( oid  == NULL ) ||
        ( name == NULL ) ||
        (*name == '\0' )) {
	return -1;
    }

		/*
		 * This OID structure previously contained a
		 * "long" name, so release those resources.
		 */
    if ( oid->name && (oid->name != oid->namebuf )) {
	free( oid->name );
	oid->name = NULL;
    }

		/*
		 * Find the MIB object for this name,
		 * and use the internal subid list
		 * to initialise this OID structure.
		 */ 
    mib = mib_find( name );
    if ( mib != NULL ) {
	(void)var_set_oid_value( oid, mib->oid, mib->oidlen );
    }

		/*
		 * Append any remaining subids
		 */
    return _var_append_subids( oid, name, mib );
}


   /**
    *
    *  Set the OID to the list of subidentifier values specified.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int var_set_oid_value( netsnmp_oid oid, u_int *name, int len )
{
    int i;

    if ( oid == NULL ) {
	return -1;
    }
		/*
		 * This OID structure previously contained a
		 * "long" name, so release those resources.
		 */
    if ( oid->name && (oid->name != oid->namebuf )) {
	free( oid->name );
	oid->name = NULL;
    }

		/*
		 * Will the new name fit into the in-line buffer ?
		 */
    if ( len > NETSNMP_NAMEBUF_LEN ) {
	oid->name = (unsigned int *)calloc( len, sizeof( unsigned int ));
	if ( oid->name == NULL ) {
	    return -1;
	}
    }
    else {
	oid->name = oid->namebuf;
    }

	/* Set up the new values */
    for ( i=0; i<len; i++ ) {
	oid->name[i] = name[i];
    }
    oid->len = len;
    return 0;
}


   /**
    *
    *  Create a new (empty) OID structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid var_create_oid( void )
{
    return (netsnmp_oid)calloc( 1, sizeof( struct netsnmp_oid_t ));
}


   /**
    *
    *  Create a new OID structure and set it to the name specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid var_create_oid_name( char *name )
{
    netsnmp_oid oid;

    oid = var_create_oid();

    if (var_set_oid( oid, name ) < 0 ) {
	if ( oid ) {
	    free( oid );
	}
	oid = NULL;
    }
    return oid;
}


   /**
    *
    *  Create a new OID structure and set it to the values specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid var_create_oid_value( u_int *name, int len )
{
    netsnmp_oid oid;

    oid = var_create_oid();

    if (var_set_oid_value( oid, name, len ) < 0 ) {
	if ( oid ) {
	    free( oid );
	}
	oid = NULL;
    }
    return oid;
}


   /**
    *
    *  Create a copy of an OID structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid var_copy_oid( netsnmp_oid oid )
{
    if ( oid == NULL ) {
	return NULL;
    }
    return var_create_oid_value( oid->name, oid->len );
}


   /**
    *
    *  Free an OID structure
    *
    *  The oid structure should not be regarded as valid
    *  once this routine has been called.
    */
void var_free_oid( netsnmp_oid oid )
{
    if ( oid == NULL ) {
	return;
    }
    if ( oid->name && (oid->name != oid->namebuf )) {
	free( oid->name );
	oid->name = NULL;
    }
    memset((void*)oid, 0, sizeof( struct netsnmp_oid_t ));
    free( oid );
    return;
}


   /**
    *
    *  Print the name of an OID in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int var_bprint_oid( netsnmp_buf buf, netsnmp_oid oid )
{
    netsnmp_mib mib;
    int ret = -1;
    int  len2 = 0;
    int  i;
    char tmpbuf[ SPRINT_MAX_LEN ];

    if (( oid == NULL ) ||
        ( buf == NULL )) { 
	return -1;
    }

    if (!(ds_get_boolean(DS_LIBRARY_ID,DS_LIB_PRINT_NUMERIC_OIDS))) {
	mib = mib_find_by_oid( oid );
	if ( mib != NULL ) {
	    ret = mib_bprint( buf, mib );
	}
	if ( ret == 0 ) {
	    len2 = mib->oidlen;	/* This much has been handled already */
	}
    }

	/* Append any remaining subidentifiers */
    for ( i=len2; i<oid->len; i++ ) {
	sprintf( tmpbuf, ".%d", oid->name[i] );
	if (buffer_append_string( buf, tmpbuf ) < 0 ) { return -1; }
    }

    return 0;
}


   /**
    *
    *  Print the name of an OID in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char *var_sprint_oid( char *str_buf, int len, netsnmp_oid oid )
{
    netsnmp_buf buf;
    char *cp = NULL;

    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return NULL;
    }
    if ( var_bprint_oid( buf, oid ) == 0 ) {
	cp = buffer_string( buf );
    }
    buffer_free( buf );
    return cp;
}
   /**
    *
    *  Print the name of an OID to the specified file.
    *
    */
void  var_fprint_oid( FILE *fp, netsnmp_oid oid )
{
    char buf[ SPRINT_MAX_LEN ];
    if ( var_sprint_oid( buf, SPRINT_MAX_LEN, oid ) != NULL ) {
	fprintf( fp, "%s", buf );
    }
}
   /**
    *
    *  Print the name of an OID to standard output.
    *
    */
void  var_print_oid( netsnmp_oid oid )
{
    var_fprint_oid( stdout, oid );
}



		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package varbind internals */

   /*
    *  The libSMI 'smiGetNode' routine discards any trailing
    *  subidentifiers, and returns the node for the longest prefix
    *  that it recognises.
    *    We need to append these extra subids when setting up an
    *  OID structure.
    *
    *  In the absence of a libSMI routine to provide this information,
    *  all we can do is search for the point where 'smiGetNode' first
    *  returns the given node.  Everything following that should be
    *  regarded as numeric subidentifiers, and added to the OID.
    *  If this assumption is false (i.e. 'atoi()' returns 0 for
    *  anything other than '0') then give up in disgust.
    *
    *  This approach isn't particularly efficient or elegant,
    *  but it seems to work quite reliably.  It'll do for now
    *  until we develop something more flexible - either within
    *  the net-snmp library, or perhaps an extension to libSMI.
    */
int _var_append_subids( netsnmp_oid oid, char *name, netsnmp_mib mib )
{
    netsnmp_mib mib2;
    char *copy;
    char *cp;
    int i, len;

    if ( *name == '.' ) {
	copy = strdup( name+1 );
    }
    else {
	copy = strdup( name );
    }
    if ( copy == NULL ) {
	return -1;
    }

    for ( cp=strchr( copy, '.' ); cp!=NULL; cp=strchr( cp+1, '.' )) {
	*cp = '\0';
	mib2 = mib_find( copy );
	*cp = '.';
	if ( mib == mib2 ) {	/* Found where the 'mib' object OID ends */
	    break;
	}
    }

    if ( cp ) {
	len = oid->len;
	for ( ; cp!=NULL; cp=strchr( cp+1, '.' )) {

	    i = atoi( cp+1 );
	    if (( i==0 ) && (*(cp+1) != '0')) {
		return -1;		/* atoi translation failed */
	    }
	    oid->name[len] = i;		/* XXX - could overrun alloced memory */
	    len++;
	}
	oid->len = len;
    }
    return 0;
}

