/*******************************
 *
 *	ucd_convert.c
 *
 *	Net-SNMP library - UCD compatability interface
 *
 *	Convert between old and new data structures
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

#include <stdio.h>
#include <ctype.h>

#include <net-snmp/var_api.h>
#include <net-snmp/protocol_api.h>
#include <net-snmp/community_api.h>
#include <net-snmp/snmpv3.h>
#include <net-snmp/error.h>
#include <ucd/ucd_api.h>

#include "snmpv3.h"
#include "tools.h"
#include "lcd_time.h"
#include "keytools.h"



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

    oid = oid_create();
    if (NULL == oid) {
	return NULL;
    }

    for (i=0; i<len; i++) {
	name2[i] = name[i];
    }

    if (0 > oid_set_value( oid, name2, len )) {
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

    val = var_create_value(v->type);
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
	return val;
    }

	/*
	 * Other types can just use a copy of the UCD raw data
	 */
    if (0 > var_set_value(val, v->val.string, v->val_len)) {
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
     * Extract the general SNMPv3-related information
     *   from a UCD-style PDU structure.
     * Returns a pointer to an appropriate v3info structure if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_v3info*
ucd_convert_v3info( struct snmp_pdu *p )
{
    netsnmp_v3info *info;

    info = v3info_create();
    if (NULL == info) {
        return NULL;
    }

    info->msgID      = p->msgid;
/*  info->msg_max_size = p->sndMsgMaxSize;  */
/*  info->v3_flags   = p->XXX;       */
    info->sec_level  = p->securityLevel;
    info->sec_model  = p->securityModel;

    info->context_engine = engine_new(p->contextEngineID, p->contextEngineIDLen);
    info->context_name   = ((0 < p->contextNameLen) ?
                 buffer_new(p->contextName, p->contextNameLen, 0) : NULL);

    return info;
}


    /**
     *
     * Extract the general SNMPv3-related information
     *   from a UCD-style session structure.
     * Returns a pointer to an appropriate v3info structure if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_v3info*
ucd_session_v3info(struct snmp_session *sess, netsnmp_v3info *v3info )
{
    netsnmp_v3info *info;

    if (NULL == v3info) {
        info = v3info_create();
    } else {
        info = v3info;
    }

    if (NULL == info) {
        return NULL;
    }

/*  info->msg_max_size = sess->sndMsgMaxSize;  */
/*  info->v3_flags   = sess->XXX;       */
    info->sec_level  = sess->securityLevel;
    info->sec_model  = sess->securityModel;

    if ((NULL == info->context_engine) &&
        (0 != sess->contextEngineIDLen)) {
        info->context_engine = engine_new(sess->contextEngineID, sess->contextEngineIDLen);
    }
    if (NULL == info->context_name) {
        info->context_name   = ((0 < sess->contextNameLen) ?
                 buffer_new(sess->contextName, sess->contextNameLen, 0) : NULL);
    }

    return info;
}


    /**
     *
     * Extract the USM-specific information
     *   from a UCD-style PDU structure.
     * Returns a pointer to the appropriate userinfo structure if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_user*
ucd_convert_userinfo( struct snmp_pdu *p )
{
    netsnmp_user   *userinfo;
    netsnmp_engine *engine;

    engine   = engine_new(p->securityEngineID, p->securityEngineIDLen);
    userinfo = user_create(p->securityName, p->securityNameLen, engine);
    engine_free(engine);

    return userinfo;
}


    /**
     *
     * Extract the USM-specific information
     *   from a UCD-style session structure.
     * Returns a pointer to the appropriate userinfo structure if successful,
     *  NULL otherwise.
     *
     * The calling routine is responsible for freeing this memory
     *  when it is not longer required.
     *
     */
netsnmp_user*
ucd_session_userinfo( struct snmp_session *sess, netsnmp_v3info *v3info, netsnmp_user *uinfo)
{
    netsnmp_user   *info = uinfo;
    netsnmp_engine *engine;

    if ((NULL == uinfo) &&
        (0 != sess->securityNameLen)) {

        engine = engine_new( sess->securityEngineID, sess->securityEngineIDLen);
        info   = user_create(sess->securityName,     sess->securityNameLen, engine);
        engine_free(engine);
    }

#define USM_LENGTH_KU_HASHBLOCK 64

    if (NULL != info) {
        if ((NULL == info->sec_engine) &&
            (NULL != v3info)) {
            info->sec_engine = engine_copy(v3info->context_engine);
        }

/******
        if (0 != sess->securityAuthProtoLen) {
            info->auth_proto = XXX;
        }
 ******/
        if (0 != sess->securityAuthKeyLen) {

            info->auth_key = buffer_new(NULL, USM_LENGTH_KU_HASHBLOCK, 0);
            info->auth_key->cur_len = info->auth_key->max_len;
            (void)generate_kul(sess->securityAuthProto, sess->securityAuthProtoLen,
                               info->sec_engine->ID->string,
                               info->sec_engine->ID->cur_len,
                               sess->securityAuthKey, sess->securityAuthKeyLen,
                               info->auth_key->string, &(info->auth_key->cur_len));
        }

/*****
        if (0 != sess->securityPrivProtoLen) {
            info->priv_proto = XXX;
        }
 *****/
        if (0 != sess->securityPrivKeyLen) {

            info->priv_key = buffer_new(NULL, USM_LENGTH_KU_HASHBLOCK, 0);
            info->priv_key->cur_len = info->priv_key->max_len;
			/* XXX - Why 'authproto' not 'privproto' ??? */
            (void)generate_kul(sess->securityAuthProto, sess->securityAuthProtoLen,
                               info->sec_engine->ID->string,
                               info->sec_engine->ID->cur_len,
                               sess->securityPrivKey, sess->securityPrivKeyLen,
                               info->priv_key->string, &(info->priv_key->cur_len));
        }
    }

    return info;
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
    if (-1 == pdu->errstatus ) {
	pdu->errstatus = 0;		/* Here or elsewhere ? */
    }
    pdu->errindex  = p->errindex;
    if (-1 == pdu->errindex ) {
	pdu->errindex = 0;		/* Here or elsewhere ? */
    }
    pdu->request   = p->reqid ;

	/* XXX - handle admin-specific info */
    if (p->community) {
	(void)community_set_cstring(pdu, p->community, strlen(p->community));
    }

    if ( SNMP_VERSION_3 == p->version ) {
        pdu->v3info   = ucd_convert_v3info(p);
        pdu->userinfo = ucd_convert_userinfo(p);
	if ((NULL == pdu->v3info) ||
	    (NULL == pdu->userinfo)) {
	    pdu_free(pdu);
	    return NULL;
	}
    }


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
	 */
    v->val_len  = val->len;
    if (40 > val->len) {
        v->val.string = v->buf;
    } else {
        v->val.string = (u_char*)calloc(val->len, 1);
	if (NULL == v->val.string) {
	    free( v );
	    return NULL;
	}
    }
    memcpy(v->val.string, val->val.string, val->len);

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

				/* XXX - Assumes this will fit in the internal buffer! */
    v->name_length = ucd_revert_oid( vb->oid, v->name_loc);
    v->name = v->name_loc;
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


int
ucd_revert_community(struct snmp_pdu *pdu, netsnmp_comminfo *info)
{
    if ((NULL == pdu) ||
        (NULL == info)) {
        return -1;
    }

    pdu->community_len = info->len;
    pdu->community = strdup( info->string );	/* XXX ??? */

    return 0;
}


int
ucd_revert_v3info(struct snmp_pdu *pdu, netsnmp_v3info *info)
{
    if ((NULL == pdu) ||
        (NULL == info)) {
        return -1;
    }

    pdu->msgid           = info->msgID;
/*  pdu->rcvMsgMaxSize   = info->msg_max_size;  */
/*  pdu->XXX             = info->v3_flags;       */
    pdu->securityLevel   = info->sec_level;
    pdu->securityModel   = info->sec_model;

    pdu->contextEngineIDLen = info->context_engine->ID->cur_len;
    pdu->contextEngineID    = buffer_string(info->context_engine->ID);
    pdu->contextNameLen = info->context_name->cur_len;
    pdu->contextName    = buffer_string(info->context_name);

    return 0;
}


int
ucd_revert_userinfo(struct snmp_pdu *pdu, netsnmp_user *info)
{
    if ((NULL == pdu) ||
        (NULL == info)) {
        return -1;
    }

    if ( info->sec_engine &&
         info->sec_engine->ID ) {
        pdu->securityEngineIDLen = info->sec_engine->ID->cur_len;
        pdu->securityEngineID    = buffer_string(info->sec_engine->ID);
        set_enginetime(pdu->securityEngineID, pdu->securityEngineIDLen,
                       info->sec_engine->boots, 
                       info->sec_engine->time, TRUE );
    }
    if ( info->sec_name ) {
        pdu->securityNameLen = info->sec_name->cur_len;
        pdu->securityName    = buffer_string(info->sec_name);
    }

    return 0;
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

    pdu->version  = p->version;
    pdu->command  = p->command;
    pdu->errstat  = p->errstatus;
    pdu->errindex = p->errindex;
    pdu->reqid    = p->request ;

	/* XXX - handle admin-specific info */
    if (p->community) {
        ucd_revert_community(pdu, p->community);
    }
    if (p->v3info) {
        ucd_revert_v3info(pdu, p->v3info);
    }
    if (p->userinfo) {
        ucd_revert_userinfo(pdu, p->userinfo);
    }

    if (p->varbind_list) {
        pdu->variables = ucd_revert_vblist(p->varbind_list);
        if (NULL == pdu->variables) {
            free(pdu);
            return NULL;
        }
    }

    switch (p->command) {
    case SNMP_MSG_RESPONSE:    
    case SNMP_MSG_REPORT:    
        pdu->flags |= UCD_MSG_FLAG_RESPONSE_PDU;
        break;
    default:
        pdu->flags &= ~UCD_MSG_FLAG_RESPONSE_PDU;
        break;
    }

    return pdu;
}
