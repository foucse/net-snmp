/*******************************
 *
 *      snmpv3/auth.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      User-based Security authentication-related routines
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


#include <net-snmp/struct.h>
#include <net-snmp/var_api.h>
#include <net-snmp/snmpv3.h>

#include "protocol/encode.h"
#include "ucd/ucd_api.h"
#include "scapi.h"

int auth_generate_keyed_hash(netsnmp_user *info,
                         netsnmp_buf     *msg,
                         netsnmp_buf     *params);
int auth_check_keyed_hash(netsnmp_user *info,
                      netsnmp_buf     *msg,
                      netsnmp_buf     *params);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/snmpv3_api.h>)
                 *
                 **************************************/
                /** @package snmpv3_api */

   /**
    *
    *  Return the internal authentication protocol (integer)
    *    identifier, corresponding to the given tag.
    *  Returns -1 on failure
    */
int
auth_protocol(char *tag)
{
    if ((NULL == tag) || ('\0' == *tag)) {
        return -1;
    }

    if (0 == strcasecmp( tag, "none" )) {
        return NETSNMP_AUTH_PROTOCOL_NONE;
    }
    else if (0 == strcasecmp( tag, "MD5" )) {
        return NETSNMP_AUTH_PROTOCOL_MD5;
    }
    else if (0 == strcasecmp( tag, "SHA" )) {
        return NETSNMP_AUTH_PROTOCOL_SHA;
    }

    return -1;
}


netsnmp_oid *
auth_oid( int protocol )
{
			/*
			 * XXX - hardwire these values,
			 *	 so we're not reliant
			 *	 on run-time lookups
			 */

    switch (protocol) {
    case NETSNMP_AUTH_PROTOCOL_NONE:
        return oid_create_name((char*) "SNMP-USER-BASED-SM-MIB::usmNoAuthProtocol" );
    case NETSNMP_AUTH_PROTOCOL_MD5:
        return oid_create_name((char*) "SNMP-USER-BASED-SM-MIB::usmHMACMD5AuthProtocol" );
    case NETSNMP_AUTH_PROTOCOL_SHA:
        return oid_create_name((char*) "SNMP-USER-BASED-SM-MIB::usmHMACSHAAuthProtocol" );
    }

    return NULL;
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package snmpv3_internals */

#define USM_MD5_AUTHLEN 12		/* Also used for SHA */
#define USM_MAX_AUTHLEN USM_MD5_AUTHLEN

   /**
    *  Perform any necessary preparations for authenticating
    *    an outgoing PDU.  This is called before the full
    *    UsmSecurityParameters header has been constructed.
    *
    *  Return -1 on failure.
    */
int
auth_stamp_pre(netsnmp_buf     *buf,
               netsnmp_v3info  *v3info,
               netsnmp_user *userinfo)
{
    char authParams[USM_MAX_AUTHLEN];
  
    if ((NULL == buf ) || (NULL == v3info) || (NULL == userinfo)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }
    if (!(v3info->v3_flags & AUTH_FLAG)) {
        return -1;
    }
    switch ( userinfo->auth_protocol ) {
        case NETSNMP_AUTH_PROTOCOL_NONE:
            return 0;				/* XXX ??? */
        case NETSNMP_AUTH_PROTOCOL_MD5:
        case NETSNMP_AUTH_PROTOCOL_SHA:
            break;
        default:
            return -1;
    }


    /*
     *  Insert a 0-valued placeholder for the signature.
     *      (See RFC 2574 - Sections 6.3.1/7.3.1)
     */
    memset(authParams, 0, USM_MAX_AUTHLEN);
    __B(encode_string(buf, ASN_OCTET_STR, authParams, USM_MAX_AUTHLEN))
    return 0;
}


   /**
    *  Finish authenticating the outgoing PDU.
    *  This is called when the full UsmSecurityParameters header
    *    is available, so it's now possibly to generate the
    *    real signature, and insert it into the encoded PDU
    *    in place of the earlier padding.
    *
    *  Return -1 on failure.
    */
int
auth_stamp_post(netsnmp_buf     *buf,
                netsnmp_v3info  *v3info,
                netsnmp_user *userinfo,
                int              auth_len)
{
    netsnmp_buf *authParams;
    char        *cp;
  
    if ((NULL == buf ) || (NULL == v3info) || (NULL == userinfo)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }
    if (!(v3info->v3_flags & AUTH_FLAG)) {
        return -1;
    }
    authParams = buffer_new(NULL, USM_MAX_AUTHLEN, 0);
    if (NULL == authParams) {
        return -1;
    }


    switch ( userinfo->auth_protocol ) {
        case NETSNMP_AUTH_PROTOCOL_MD5:
        case NETSNMP_AUTH_PROTOCOL_SHA:
            if (0 > auth_generate_keyed_hash(userinfo, buf, authParams)) {
                return -1;
            }
            if (USM_MAX_AUTHLEN != authParams->cur_len) {
                return -1;
            }
            /*
             * The packet is being constructed in reverse,
             *   so the encoded PDU is sitting at the end of the buffer.
             *   Find the location of the authentication data within this.
             */
            cp = buf->string + (buf->max_len - auth_len) - authParams->cur_len;
            memcpy(cp, authParams->string, authParams->cur_len);
            return 0;

        default:
            return -1;
    }

    /* NOT REACHED */
    return -1;
}


int
auth_generate_keyed_hash(netsnmp_user *info,
                         netsnmp_buf     *msg,
                         netsnmp_buf     *params)
{
    int          len;
    int          offset;
    netsnmp_oid *oid;

    if ((NULL == info )          || 
        (NULL == info->auth_key) || 
        (NULL == msg)            || 
        (NULL == params)) {
        return -1;
    }
    if (!(msg->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;
    }

    len      = params->max_len;
    offset   = msg->max_len - msg->cur_len;
    oid      = auth_oid(info->auth_protocol);
    if (NULL == oid) {
        return -1;
    }
    if (0 != sc_generate_keyed_hash(
                       oid->name,               oid->len,
                       info->auth_key->string,  info->auth_key->cur_len,
                       msg->string+offset,      msg->cur_len,
                       params->string,         &len)) {
        return -1;
    }
    params->cur_len = len;
    return 0;
}


   /**
    *  Verify that the authParameter 'signature' matches the
    *    incoming PDU, and the given user information.
    *
    *  Return -1 on failure.
    */
int
auth_verify(netsnmp_buf     *buf,
               netsnmp_v3info  *v3info,
               netsnmp_user    *userinfo)
{
    if ((NULL == buf)      || 
        (NULL == v3info)   || 
        (NULL == userinfo)) {
        return -1;
    }
    return auth_check_keyed_hash(userinfo, buf, userinfo->auth_params);
}

int
auth_check_keyed_hash(netsnmp_user *info,
                      netsnmp_buf     *msg,
                      netsnmp_buf     *params)
{
    netsnmp_oid *oid;

    if ((NULL == info )          || 
        (NULL == info->auth_key) || 
        (NULL == msg)            || 
        (NULL == params)) {
        return -1;
    }

    oid      = auth_oid(info->auth_protocol);
    if (NULL == oid) {
        return -1;
    }

    if (0 != sc_check_keyed_hash(
                       oid->name,               oid->len,
                       info->auth_key->string,  info->auth_key->cur_len,
                       msg->string,             msg->cur_len,
                       params->string,          params->cur_len)) {
        return -1;
    }
    return 0;
}
