/*******************************
 *
 *      snmpv3/priv.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      User-based Security privacy-related routines
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
#include "callback.h"
#include "snmp_secmod.h"
#include "snmpusm.h"


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
priv_protocol(char *tag)
{
    if ((NULL == tag) || ('\0' == *tag)) {
        return -1;
    }

    if (0 == strcasecmp( tag, "none" )) {
        return NETSNMP_PRIV_PROTOCOL_NONE;
    }
    else if (0 == strcasecmp( tag, "des" )) {
        return NETSNMP_PRIV_PROTOCOL_DES;
    }

    return -1;
}


netsnmp_oid *
priv_oid( int protocol )
{
			/*
			 * XXX - hardwire these values,
			 *	 so we're not reliant
			 *	 on run-time lookups
			 */

    switch (protocol) {
    case NETSNMP_PRIV_PROTOCOL_NONE:
        return oid_create_name((char*) "SNMP-USER-BASED-SM-MIB::usmNoPrivProtocol" );
    case NETSNMP_PRIV_PROTOCOL_DES:
        return oid_create_name((char*) "SNMP-USER-BASED-SM-MIB::usmDESPrivProtocol" );
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
#define USM_MAX_SALT_LENGTH 64		/* In bits */

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)
   /**
    *  Perform any necessary preparations for authenticating
    *    an outgoing PDU.  This is called before the full
    *    UsmSecurityParameters header has been constructed.
    *
    *  Return -1 on failure.
    */
int
priv_encrypt(netsnmp_buf     *buf,
             netsnmp_v3info  *v3info,
             netsnmp_user *userinfo)
{
    char salt[      BYTESIZE(USM_MAX_SALT_LENGTH)];
    char ivector[   BYTESIZE(USM_MAX_SALT_LENGTH)];
    int  salt_len = BYTESIZE(USM_MAX_SALT_LENGTH);
    netsnmp_buf *encrypted_buf;
    netsnmp_oid *oid;
    int          offset;
    int          len;
  
    if ((NULL == buf ) || (NULL == v3info) || (NULL == userinfo)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }
    if (!(v3info->v3_flags & PRIV_FLAG) ||
        !(userinfo->priv_key)) {
        return -1;
    }
    switch ( userinfo->auth_protocol ) {
        case NETSNMP_PRIV_PROTOCOL_NONE:
            return -1;			/* XXX ??? */
        case NETSNMP_PRIV_PROTOCOL_DES:
            break;
        default:
            return -1;
    }

    oid = priv_oid(userinfo->priv_protocol);
    if (NULL == oid) {
        return -1;
    }

    /*
     * The maximum padding size supported is no more than 64,
     *   so let's use a fixed buffer of that size.
     * We'll need to check that the encrupted version fits
     *   before copying it back into the message buffer.
     */
    encrypted_buf = buffer_new(NULL, buf->cur_len+64, 0);
    if (NULL == encrypted_buf) {
        return -1;
    }

    /*
     *  Encrypt the scoped PDU into the scratch buffer.
     *  Hardwired to seek into a 1DES private key
     */
    if (0 > usm_set_salt(salt, &salt_len,
                         userinfo->priv_key->string+8,
                         userinfo->priv_key->cur_len-8,
                         ivector)) {
        return -1;
    }
    offset   = buf->max_len - buf->cur_len;
    len = encrypted_buf->max_len;
    if (0 > sc_encrypt(oid->name,              oid->len,
                         userinfo->priv_key->string, userinfo->priv_key->cur_len,
                         salt,                      salt_len,
                         buf->string+offset,        buf->cur_len,
                         encrypted_buf->string,    &len)) {
        return -1;
    }
    encrypted_buf->cur_len = len;
    /*
     * Save the encryption vector,
     *   so that it can be inserted into the encoded PDU
     * Note that this is done in two stages, as the buffer
     *   creation utility get confused if the initialisation
     *   data starts with a '\0' character.
     */
    userinfo->priv_params = buffer_new(NULL, BYTESIZE(USM_MAX_SALT_LENGTH), 0 );
    (void)buffer_append(userinfo->priv_params, ivector, BYTESIZE(USM_MAX_SALT_LENGTH));

    /*
     * Copy the encrypted PDU back into the message buffer,
     *   wrapped as an OCTET STRING.
     * We can trick the buffer utilities into handling any size
     *   extension for us, by pretending that the message
     *   buffer is initially empty.
     */
    buf->cur_len = 0;
    __B(encode_string(buf, ASN_OCTET_STR, encrypted_buf->string, encrypted_buf->cur_len))
    return 0;
}
