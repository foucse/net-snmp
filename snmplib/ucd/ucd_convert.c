/*******************************
 *
 *	ucd_convert.c
 *
 *	Net-SNMP library - UCD compatability interface
 *
 *	Convert between old and new data structures
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

#include "tools.h"



		/*****************************
		 *
		 *  Convert UCD structures
		 *  to the Net-SNMP equivalents
		 *
		 *****************************/

    /**
     *
     * Create a Net-SNMP OID structure, corresponding
     *  to the specified UCD-style OID representation
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_oid*
ucd_convert_oid( u_long *name, int len )
{
    int i;
    u_int name2[MAX_OID_LEN];
    netsnmp_oid *oid;

    oid = var_create_oid();
    if (NULL == oid) {
	return NULL;
    }

    for (i=0; i<len; i++) {
	name2[i] = name[i];
    }

    if (0 > var_set_oid_value( oid, name2, len )) {
	free( oid );
	oid = NULL;
    }
    return oid;
}


    /**
     *
     * Create a Net-SNMP value structure, corresponding
     *  to the specified UCD-style variable_list structure.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_value*
ucd_convert_value( struct variable_list *v )
{
    netsnmp_value *val;

    val = (netsnmp_value*)calloc(1, sizeof( netsnmp_value ));
    if (NULL == val) {
	return NULL;
    }


	/*
	 * OBJECT ID values use the appropriate internal data
	 *   structure, rather than the UCD-style raw values,
	 *   so this needs to be handled separately.
	 */
    if (ASN_OBJECT_ID == v->type) {
	val->val.oid = ucd_convert_oid( v->val.objid, v->val_len/sizeof(oid));
	if ( val->val.oid == NULL ) {
	    free( val );
	    return NULL;
	}
        val->len     = sizeof( netsnmp_oid );
        val->type    = v->type;
	return val;
    }

	/*
	 * Other types can just use a copy of the UCD raw data
	 */
    if (0 > var_set_value(val, v->val.string, v->val_len, v->type)) {
	free( val );
	return NULL;
    }

    return val;
}


    /**
     *
     * Create a Net-SNMP varbind structure, corresponding
     *  to the specified single UCD-style variable_list structure.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_varbind*
ucd_convert_varbind( struct variable_list *v )
{
    netsnmp_varbind *vb;

    vb = (netsnmp_varbind*)calloc(1, sizeof( netsnmp_varbind ));
    if (NULL == vb) {
	return NULL;
    }

    vb->oid   = ucd_convert_oid( v->name, v->name_length );
    if (NULL == vb->oid) {
	var_free_varbind( vb );
	return NULL;
    }

    vb->value = ucd_convert_value(v);
    if (NULL == vb->value) {
	var_free_varbind( vb );
	return NULL;
    }
    return vb;
}


    /**
     *
     * Create a list of Net-SNMP varbind structures, corresponding
     *  to the specified UCD-style variable_list.
     * Returns a pointer to the head of this list if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_varbind*
ucd_convert_vblist( struct variable_list *var_list )
{
    netsnmp_varbind *varbind, *vblist;
    struct variable_list *v;

    vblist = NULL;
    for (v = var_list; NULL != v; v = v->next_variable) {
	varbind = ucd_convert_varbind( v );
	if (NULL == vblist) {
	    vblist=varbind;
	}
	else {
		/* XXX - error handling */
	    (void)vblist_add_varbind( vblist, varbind );
	}
    }
    return vblist;
}


    /**
     *
     * Create a Net-SNMP PDU structure, corresponding
     *  to the specified UCD-style PDU.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_pdu*
ucd_convert_pdu( struct snmp_pdu *p )
{
    netsnmp_pdu *pdu;

    pdu = pdu_create(p->version, p->command); 
    if (NULL == pdu) {
	return NULL;
    }
    pdu->errstatus = p->errstat;
    pdu->errindex  = p->errindex;
    pdu->request   = p->reqid ;

	/* XXX - handle admin-specific info */

    if (p->variables) {
	pdu->varbind_list = ucd_convert_vblist(p->variables);
	if (NULL == pdu->varbind_list) {
	    pdu_free(pdu);
	    return NULL;
	}
    }
    return pdu;
}



		/*****************************
		 *
		 *  Convert Net-SNMP structures
		 *  back to the UCD equivalents
		 *
		 *****************************/

    /**
     *
     * Convert the specified Net-SNMP OID structure back
     *  to the equivalent UCD-style OID representation,
     *  using the array provided.
     *
     * Returns the number of subidentifiers, or -ve on failure
     *
     */
int
ucd_revert_oid( netsnmp_oid *oid, u_long *name )
{
    int i;

    if (NULL == oid) {
	return -1;
    }

    for (i=0; i<oid->len; i++) {
	name[i] = oid->name[i];
    }
    return oid->len;
}


    /**
     *
     * Create a UCD-style variable_list structure, corresponding
     *  to the specified Net-SNMP value structure.
     *  The OID element of this variable_list structure is undefined.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
struct variable_list *
ucd_revert_value(netsnmp_value *val)
{
    struct variable_list *v;

    v = (struct variable_list *)calloc(1, sizeof(struct variable_list));
    if (NULL == v) {
	return NULL;
    }

    v->type = val->type;

	/*
	 *  Net-SNMP OBJECT ID values use the appropriate internal data
	 *   structure, rather than the raw values expected by UCD,
	 *   so this needs to be handled separately.
	 */
    if (ASN_OBJECT_ID == val->type) {

	v->val_len = ucd_revert_oid(val->val.oid, v->val.objid);
	if (0 > v->val_len) {
	    free( v );
	    return NULL;
	}
	    /*
	     * Convert 'length' from number of subidentifiers,
             *  to the actual size in bytes.
             */
        v->val_len  *= sizeof( oid );
	return v;
    }

	/*
	 * Other types can just use a copy of the UCD raw data
	 *	XXX - this fudges the internal buffer handling!
	 */
    v->val_len  = val->len;
    if (val->val.string != val->valbuf) {
	if (NULL == v->val.string) {
	    free( v );
	    return NULL;
	}
    }
    else {
	v->val.string = v->buf;
	memcpy( v->buf, val->valbuf, NETSNMP_VALBUF_LEN );
    }

    return v;
}


    /**
     *
     * Create a UCD-style variable_list structure, corresponding
     *  to the specified Net-SNMP varbind structure.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
struct variable_list *
ucd_revert_varbind(netsnmp_varbind *vb)
{
    struct variable_list *v;

    v = ucd_revert_value( vb->value );
    if (NULL == v) {
	return NULL;
    }

    v->name_length = ucd_revert_oid( vb->oid, v->name_loc);
    if (0 > v->name_length) {
	free( v );	/* XXX - internal buffer? */
	return NULL;
    }
    return v;
}


    /**
     *
     * Create a list of UCD-style variable_list structures,
     *  corresponding to the specified Net-SNMP varbind list.
     * Returns a pointer to the head of this list if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
struct variable_list *
ucd_revert_vblist(netsnmp_varbind *vblist)
{
    netsnmp_varbind *varbind;
    struct variable_list *v, *vlast, *vhead;

    vhead     = NULL;
    vlast = NULL;
    for ( varbind = vblist; NULL != varbind; varbind=varbind->next) {
	v = ucd_revert_varbind( varbind );
	if (NULL == v) {
	    /* XXX - error handling */
	    return NULL;
	}

	if (NULL == vlast) {
	    vhead = v;
	    vlast = vhead;
	}
	else {
	    vlast->next_variable = v;
	    vlast = v;
	}
    }
    return vhead;
}


    /**
     *
     * Create a UCD-style PDU structure,
     *  corresponding to the specified Net-SNMP PDU.
     * Returns a pointer to this if successful, NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
struct snmp_pdu *
ucd_revert_pdu(netsnmp_pdu *p)
{
    struct snmp_pdu *pdu;

    pdu = (struct snmp_pdu *)calloc(1, sizeof(struct snmp_pdu));
    if (NULL == pdu) {
	return NULL;
    }

    pdu->errstat  = p->errstatus;
    pdu->errindex = p->errindex;
    pdu->reqid    = p->request ;

	/* XXX - handle admin-specific info */

    if (p->varbind_list) {
        pdu->variables = ucd_revert_vblist(p->varbind_list);
        if (NULL == pdu->variables) {
            free(pdu);
            return NULL;
        }
    }
    return pdu;
}
