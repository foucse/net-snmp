/*******************************
 *
 *	varbind/vblist.c
 *
 *	Net-SNMP library - Variable-handling interface
 *
 *	Variable-binding list-handling routines
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
    *  Add the specified varbind to the end of the given list
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int vblist_add_varbind( netsnmp_varbind vblist, netsnmp_varbind varbind )
{
    netsnmp_varbind vb;

    if (( varbind  == NULL ) ||
        ( vblist   == NULL )) {
	return -1;
    }

    for ( vb=vblist; vb->next != NULL; vb=vb->next ) {
	;	/* Find the end of the list */
    }

    vb->next      = varbind;
    varbind->prev = vb;
    varbind->pdu  = vb->pdu;

    return 0;
}


   /**
    *
    *  Identify the specified varbind from the given list.
    *   (indexing from 1)
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind vblist_return_varbind( netsnmp_varbind vblist, int idx )
{
    netsnmp_varbind vb;
    int i;

    if (( vblist   == NULL ) ||
        (    idx   <= 0    )) {
	return NULL;
    }

    vb = vblist;
    for ( i=idx ; i>0 ; i-- ) {
	if ( vb == NULL ) {
	    return NULL;
	}
	vb = vb->next;
    }
    return vb;
}


   /**
    *
    *  Extract the specified varbind from the given list,
    *   (indexing from 1) and remove it from the list.
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind vblist_extract_varbind( netsnmp_varbind vblist, int idx )
{
    netsnmp_varbind vb;

    vb = vblist_return_varbind( vblist, idx );

	/*
	 * Unlink it from the list
	 */
    if ( vb ) {
	if ( vb->prev ) {
	    vb->prev->next = vb->next;
	}
	if ( vb->next ) {
	    vb->next->prev = vb->prev;
	}
    }
    return vb;
}


   /**
    *
    *  Free a varbind list
    *
    *  The list should not be regarded as valid
    *  once this routine has been called.
    */
void vblist_free( netsnmp_varbind vblist )
{
    netsnmp_varbind vb, vbnext;

    if ( vblist == NULL ) {
	return;
    }


    for ( vb=vblist; vb != NULL; vb = vbnext ) {
	vbnext = vb->next;
	var_free_varbind( vb );
    }
    return;
}


   /**
    *
    *  Print a varbind list in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int vblist_bprint( netsnmp_buf buf, netsnmp_varbind vblist )
{
    netsnmp_varbind vb;

    for ( vb=vblist; vb!=NULL; vb=vb->next ) {
	if ( var_bprint_varbind( buf, vb ) < 0 ) {
	    return -1;
	}
	__B( buffer_append_char( buf, '\n' ))
    }
    
    return 0;
}


   /**
    *
    *  Print a varbind list in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char *vblist_sprint( char *str_buf, int len, netsnmp_varbind vblist )
{
    netsnmp_buf buf;
    char *cp = NULL;

    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return NULL;
    }
    if ( vblist_bprint( buf, vblist ) == 0 ) {
	cp = buffer_string( buf );
    }
    buffer_free( buf );
    return cp;
}


   /**
    *
    *  Print a varbind list to the specified file.
    *
    */
void  vblist_fprint( FILE *fp, netsnmp_varbind vblist )
{
    char buf[ SPRINT_MAX_LEN ];
    if ( vblist_sprint( buf, SPRINT_MAX_LEN, vblist ) != NULL ) {
	fprintf( fp, "%s", buf );
    }
}
   /**
    *
    *  Print a variable binding to standard output. 
    *
    */
void  vblist_print( netsnmp_varbind vblist )
{
    vblist_fprint( stdout, vblist );
}


		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package varbind_internals */


		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package varbind_internals */


   /**
    *
    *  Add the specified varbind to the given PDU
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int pdu_add_varbind( netsnmp_pdu pdu, netsnmp_varbind varbind)
{
    if (( varbind  == NULL ) ||
        ( pdu      == NULL )) {
	return -1;
    }

    return vblist_add_varbind( pdu->varbind_list, varbind );
}


   /**
    *
    *  Identify the specified varbind from the given PDU
    *   (indexing from 1).
    *  If the specified index is -1, then identify the
    *   varbind indicated by 'errindex' (if applicable).
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind pdu_return_varbind( netsnmp_pdu pdu, int idx )
{
    int i;

    if (( pdu      == NULL )) {
	return NULL;
    }

    i = idx;
    if ( idx == -1 ) {
	i = pdu->errindex;
    }

    return vblist_return_varbind( pdu->varbind_list, i );
}


   /**
    *
    *  Extract the specified varbind from the given PDU
    *   (indexing from 1) and remove it from the PDU.
    *  If the specified index is -1, then identify the
    *   varbind indicated by 'errindex' (if applicable).
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind pdu_extract_varbind( netsnmp_pdu pdu, int idx )
{
    int i;
    netsnmp_varbind vb;

    if (( pdu      == NULL )) {
	return NULL;
    }

    i = idx;
    if ( idx == -1 ) {
	i = pdu->errindex;
    }

    vb = vblist_extract_varbind( pdu->varbind_list, i );
	/*
	 * Adjust if this was the (old) head of the list
	 */
    if ( vb && ( pdu->varbind_list == vb )) {
	pdu->varbind_list = vb->next;
    }
    return vb;
}
