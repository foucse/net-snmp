/*******************************
 *
 *	mib_object.c
 *
 *	Net-SNMP library - MIB-handling interface
 *
 *	Object-related routines
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

#include <stdio.h>
#include <ctype.h>

#include <net-snmp/mib_api.h>

#ifndef SPRINT_MAX_LEN
#define SPRINT_MAX_LEN 512
#endif

int oid_set_name( netsnmp_oid oid, unsigned int* subids, int len );

static void _mib_tree_walk_callback( netsnmp_mib mib, void *data );

		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/mib_api.h>)
		 *
		 **************************************/
		/** @package mib_api */

   /**
    *
    *  Return the MIB object corresponding to the name specified.
    *  If no such object exists, return NULL.
    */
netsnmp_mib mib_find( char *name )
{
    char       *cp;
    char       *copy;
    SmiModule  *mod = NULL;
    netsnmp_mib mib = NULL;


    if (( name == NULL ) ||
	(*name == '\0' )) {
	return NULL;
    }

	/*
	 * libSMI's syntax for specifying a MIB object is
	 *	somewhat more restrictive that {ucd,net}-snmp
	 *	tools have traditionally used.
	 *
	 * The only acceptable forms appear to be:
	 *	-  SNMPv2-MIB::sysDescr
	 *	-  sysDescr
	 *	-  1.3.6.1.2.1.1
	 *
	 * Note that none of:
	 *	- .1.3.6.1.2.1.1		(leading dot)
	 *	- .iso.org.dod.internet.mgmt.mib-2.system.sysDescr
	 *	-  iso.org.dod.internet.mgmt.mib-2.system.sysDescr
	 * are recognised.
	 *
	 *
	 * This means that in order to look up a string representation
	 * of an OID, it's necessary to do some additional processing first.
	 *
	 * In the case of textual forms, we must identify the last non-numeric
	 * descriptor from within the string, and pass that identifier only
	 * (perhaps together with the name of the module) to the libSMI routine.
	 *
	 * In the case of a fully-numeric description, the only 'gotcha'
	 * is the leading dot - indicating a fully-qualified OID.
	 * We've spent years trying to train people to include this,
	 * so it's probably neccesary to continue to support this syntax!
	 */


		/*
		 * Look for fully-numeric form
		 */
    if ( isdigit(*name) ) {
	return (netsnmp_mib)smiGetNode( NULL, name );
    }

		/*
		 * Look for fully-numeric form with leading dot
		 */
    if ( *name == '.' && isdigit(*(name+1)) ) {
	return (netsnmp_mib)smiGetNode( NULL, name+1 );
    }

		/*
		 * If the name given includes a module specification,
		 * then retrieve the corresponding libSMI module.
		 */
    if ( isupper( *name ) ) {
	copy = strdup( name );
	if ( copy != NULL ) {
	    cp = strchr( copy, ':' );	/* MODULE::object */
	    if ( cp ) {
	        *cp = '\0';
	    }
	    cp = strchr( copy, '.' );	/* MODULE.object */
	    if ( cp ) {
	        *cp = '\0';
	    }
	    mod = smiGetModule( copy );
	    free( copy );
	}
    }

		/*
		 * Locate the last non-integer subidentifier in
		 * the specified string, and request this from
		 * the libSMI system. 
		 */
    copy = strdup( name );
    if ( copy == NULL ) {
	return NULL;
    }
    while ( (cp=strrchr( copy, '.' )) != NULL ) {
	if ( !isdigit( *(cp+1))) {
	    break;	/* Found it */
	}
	*cp = '\0';
    }
    if ( !cp && mod ) {
	cp = strrchr( copy, ':' );
    }

    if ( cp ) {
	mib = (netsnmp_mib)smiGetNode( mod, cp+1 );
    }
    else {
	mib = (netsnmp_mib)smiGetNode( mod, copy );
    }

    free(copy);
    return mib;
}


   /**
    *
    *  Return the MIB object corresponding to the OID specified.
    *  If no such object exists, return NULL.
    */
netsnmp_mib mib_find_by_oid( netsnmp_oid oid )
{
    return (netsnmp_mib)smiGetNodeByOID( oid->len, (SmiSubid*)oid->name );
}

netsnmp_mib mib_find_by_ucd_oid( u_long *name, int len )
{
    return (netsnmp_mib)smiGetNodeByOID( len, (SmiSubid*)name );
}


   /**
    *
    *  Return an OID corresponding to this MIB object.
    *
    *  Return NULL on error.
    *
    *  The calling routine is responsible for freeing this memory
    *   when no longer required.
    */
netsnmp_oid mib_objectid( netsnmp_mib mib )
{
    SmiNode *node   = (SmiNode*)mib;
    netsnmp_oid oid = (netsnmp_oid)calloc(1, sizeof(struct netsnmp_oid_t));

    if ( oid == NULL ) {
	return NULL;
    }
    if ( oid_set_name( oid, (unsigned int*)node->oid, node->oidlen ) < 0 ) {
	free( oid );
	return NULL;
    }
    return oid;
}


   /**
    *
    *  Print the name of the MIB object in the buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    */
char *mib_sprint( char *buf, int len, netsnmp_mib mib )
{
    SmiNode *node   = (SmiNode*)mib;
    SmiModule *module;

    if ( mib == NULL ) {
	return NULL;
    }

		/*
		 *  ToDo: Choose style of output
		 */

    module = smiGetNodeModule( node );
    if ( module == NULL ) {
	return NULL;
    }
    if ((  node->name   == NULL ) ||
        ( *node->name   == '\0' ) ||
        (  module->name == NULL ) ||
        ( *module->name == '\0' )) {
	return NULL;
    }
    if ( strlen(node->name) + strlen(module->name) +2 >= len ) {
	return NULL;
    }
    snprintf(buf, len, "%s::%s", module->name, node->name );

    return buf;
}
void mib_fprint( FILE *fp, netsnmp_mib mib )
{
    char buf[ SPRINT_MAX_LEN ];
    if (mib_sprint( buf, SPRINT_MAX_LEN, mib ) != NULL ) {
	fprintf( fp, "%s", buf );
    }
}
void mib_print( netsnmp_mib mib )
{
    mib_fprint( stdout, mib );
}


   /**
    *
    *  Return a varbind initialised to this MIB object.
    *  If 'value' is true, set type and default value (if any).
    *  If 'value' is false, just set the OID.
    *
    *  Return NULL on error.
    *
    *  The calling routine is responsible for freeing this memory
    *   when no longer required.
    */
netsnmp_varbind mib_varbind( netsnmp_mib mib, int value )
{
    SmiNode        *node = (SmiNode*)mib;
    netsnmp_oid     oid;
    netsnmp_varbind vb;

    vb = (netsnmp_varbind)calloc(1, sizeof(struct netsnmp_varbind_t));
    if ( vb == NULL ) {
	return NULL;
    }

			/* Construct the OID name */
    oid = mib_objectid( mib );
    if ( oid == NULL ) {
	free( vb );
	return NULL;
    }

		/*
		 * ToDo:  Set the type (and default value)
		 */

    vb->oid = oid;
    return vb;
}


   /**
    *
    *  General-purpose MIB tree traversal routine.
    *
    *  Walk through the loaded MIB tree, calling the callback routine
    *  provided for each object in turn.
    */
void mib_tree_walk( mibtree_callback callback, void* data)
{
    SmiNode *node;

    node = smiGetFirstNode( NULL, SMI_NODEKIND_ANY );

    while ( node != NULL ) {
	callback( (netsnmp_mib)node, data );
    }
}


void mib_tree_dump( FILE *fp )
{
    mib_tree_walk( _mib_tree_walk_callback, (void*)fp );
}


		/**************************************
		 *
		 *	temporary utility routines
		 *	    will be implemented in other subsystems
		 *
		 **************************************/

   /*
    * oid_set_name()
    *
    * Set the value of an OID structure,
    *   to match the given list of subidentifiers.
    *
    * Returns 0 if successful, -ve otherwise
    */

int oid_set_name( netsnmp_oid oid, unsigned int* subids, int len )
{
    if ( oid == NULL ) {
	return -1;
    }

		/* Free any memory previously allocated for a 'long' name */
    if ( oid->name && oid->name!=oid->namebuf ) {
	free( oid->name );
	oid->name = NULL;
    }
		/* The new name is too long to fit into the
			inline buffer, so allocate new memory for it. */
    if ( len > NETSNMP_NAMEBUF_LEN ) {
	oid->name = (unsigned int*)calloc( len, sizeof(unsigned int));
	if ( oid->name == NULL ) {
	    return -1;
	}
    }
    else {
	oid->name = oid->namebuf;
    }

    memcpy( oid->name, subids, len*sizeof(unsigned int) );
    oid->len = len;
    return 0;
}


		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package mib internals */

   /**
    *
    * Return a string containing information about this node.
    *
    *  The calling routine is responsible for freeing this memory
    *   when no longer required.
    *
    * @todo mibobj_dump needs to display a bit more than just the name!
    */
char* mibobj_dump( netsnmp_mib mib )
{
    SmiNode *node   = (SmiNode*)mib;

    if ( mib == NULL ) {
	return NULL;
    }

    return strdup((char*) node->name );
}


static void _mib_tree_walk_callback( netsnmp_mib mib, void *data )
{
    char *cp;
    FILE *fp = (FILE*)data;

    cp = mibobj_dump( mib );
    if ( cp ) {
	if ( fp ) {
	    fprintf( fp, "%s\n", cp );
	}
	else {
	    printf( "%s\n", cp );
	}
	free( cp );
    }
}
