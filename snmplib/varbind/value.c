/*******************************
 *
 *	varbind/value.c
 *
 *	Net-SNMP library - Variable-handling interface
 *
 *	Value-handling routines
 *	(see 'value_output.c' for value output routines)
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




		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/varbind_api.h>)
		 *
		 **************************************/
		/** @package varbind_api */


   /**
    *
    *  Assign the specified value to the given structure
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int var_set_value( netsnmp_value value, char *val, int len, int type )
{
    if ( value == NULL ) {
	return -1;
    }

#ifdef NOT_SURE_ABOUT_THIS
		/*
		 * No data is needed for NULL type
		 * All other types require data for the value.
		 */
    if ( val == NULL ) {
	if (( len != 0 ) || (type != ASN_NULL)) {
	    return -1;
	}
    }
    else {
	if (( len == 0 ) || (type == ASN_NULL)) {
	    return -1;
	}
    }
#endif

    if ( value->val.string && ( value->val.string != value->valbuf )) {
	free( value->val.string );
	value->val.string = NULL;
    }

    if ( len > NETSNMP_VALBUF_LEN ) {
	value->val.string = (u_char*)calloc(len, 1);
	if ( value->val.string == NULL ) {
	    return -1;
	}
    }
    else {
	value->val.string = value->valbuf;
    }

    value->type = type;
    value->len  = len;
    memcpy( value->val.string, val, len );
    return 0;
}


   /**
    *
    *  Create a new (empty) value structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_value var_create_value( void )
{
    netsnmp_value value;

    value = (netsnmp_value)calloc( 1, sizeof( struct netsnmp_value_t ));
    if ( value ) {
	value->type = ASN_NULL;
    }
    return value;
}


   /**
    *
    *  Create a new value structure and set it to the value specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_value var_create_set_value( char *val, int len, int type )
{
    netsnmp_value value;

    value = var_create_value();

    if (var_set_value( value, val, len, type ) < 0 ) {
	if ( value ) {
	    free( value );
	}
	value = NULL;
    }
    return value;
}


   /**
    *
    *  Create a copy of the given value structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_value var_copy_value(  netsnmp_value value )
{
    if ( value == NULL ) {
	return NULL;
    }
    return var_create_set_value( value->val.string, value->len, value->type );
}


   /**
    *
    *  Free a value structure
    *
    *  The value structure should not be regarded as valid
    *  once this routine has been called.
    */
void var_free_value( netsnmp_value value )
{
    if ( value == NULL ) {
	return;
    }
    if ( value->val.string && (value->val.string != value->valbuf )) {
	free( value->val.string );
	value->val.string = NULL;
    }
    memset((void*)value, 0, sizeof( struct netsnmp_value_t ));
    free( value );
    return;
}


		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package varbind_internals */


