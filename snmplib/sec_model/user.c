/*******************************
 *
 *      sec_model/user.c
 *
 *      Net-SNMP library - Security Model interface
 *
 *      User-based Security Model (USM) handling routines
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
#include <net-snmp/utils.h>
#include <net-snmp/snmpv3.h>

#include "protocol/encode.h"
#include "protocol/decode.h"
#include "snmpv3/snmpv3.h"
#include "sec_model/secmod.h"

netsnmp_user *user_head = NULL;
netsnmp_user *user_tail = NULL;
netsnmp_user *user_anon = NULL;		/* Used for engine discovery */

netsnmp_user* user_find(char *name, int len, netsnmp_engine *engine);
void user_insert(netsnmp_user *user);
void user_free_session(netsnmp_session *sess);
int user_copy_pdu(netsnmp_pdu *pdu, netsnmp_pdu *copy);
void *user_clone(void *info);
void user_free_sm_info(void *info);
int user_sm_bprint(netsnmp_buf *buf, void *info);

void user_init(void)
{
    netsnmp_secmod *secmod;

    secmod = secmod_new( 3 );
    if (NULL == secmod) {
        return;
    }

    secmod->encode_hook = user_encode_pdu;
    secmod->decode_hook = user_decode_pdu;
    secmod->sm_free     = user_free_sm_info;
    secmod->sm_clone    = user_clone;
    secmod->sm_print    = user_sm_bprint;
    (void)secmod_register(3, "user", secmod);
}



                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/snmpv3_api.h>)
                 *
                 **************************************/
                /** @package snmpv3_api */


   /**
    *  Create a new User structure,
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_user *
user_create(char *name, int len, netsnmp_engine *engine)
{
    netsnmp_user *user = NULL;

    if (NULL == name) {
        return NULL;
    }

    /*
     * If we already know about this user....
     */
    if ((NULL == engine) && ('\0' == *name)) {
        user = user_anon;
    } else {
        user = user_find(name, len, engine);
    }

    /*
     * .... return a reference to the same structure
     */
    if (NULL != user) {
        user->ref_count++;
        return user;
    }

    /*
     * Otherwise, we need to create a new structure,
     *   and insert it into the list at the appropriate place
     */
    user = (netsnmp_user*) calloc(1, sizeof(netsnmp_user));
    if (NULL == user) {
        return NULL;
    }
    user->user_name   = buffer_new(name, len, 0);
    if (NULL == user->user_name) {
        free(user);
        return NULL;
    }
    if (NULL != engine) {
        user->sec_engine = engine_copy( engine );
        if (NULL == user->sec_engine) {
            buffer_free(user->user_name);
            free(user);
            return NULL;
        }
    }

    user_insert(user);
    return user;
}


   /**
    *
    *  Create a copy of a USM structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_user *
user_copy(netsnmp_user *info)
{

    if (NULL == info) {
        return NULL;
    }
    info->ref_count++;
    return info;

/*
    netsnmp_user *info_copy;
    info_copy = (netsnmp_user*) calloc(1, sizeof(netsnmp_user));
    if (NULL == info_copy) {
	return NULL;
    }

    info_copy->user_name   = buffer_copy( info->user_name);
    info_copy->user_name   = buffer_copy( info->user_name);
    info_copy->sec_engine  = engine_copy( info->sec_engine);

    info_copy->auth_protocol    = info->auth_protocol;
    info_copy->auth_key         = buffer_copy( info->auth_key);

    info_copy->priv_protocol    = info->priv_protocol;
    info_copy->priv_key         = buffer_copy( info->priv_key);

    return info_copy;
 */
}


void *
user_clone(void *info)
{
    return (void*)user_copy((netsnmp_user*)info);
}

int
user_copy_pdu(netsnmp_pdu *pdu, netsnmp_pdu *copy)
{
    if ((NULL == pdu) ||
        (NULL == copy)) {
        return -1;
    }

    copy->sm_info = user_clone(pdu->sm_info);
    return 0;
}


   /**
    *
    *  Free a USM structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
user_free(netsnmp_user *info)
{
    if (NULL == info) {
	return;
    }
    if (0 < --info->ref_count) {
        return;
    }

    if (info->prev) {
        info->prev->next = info->next;
    } else {
        user_head->next  = info->next;
    }
    if (info->next) {
        info->next->prev = info->prev;
    } else {
        user_tail->prev  = info->prev;
    }

    buffer_free(info->user_name);
    buffer_free(info->user_name);
    engine_free(info->sec_engine);
    buffer_free(info->auth_key);
    buffer_free(info->priv_key);
    free( info );
    return;
}

void
user_free_sm_info(void *info)
{
    user_free((netsnmp_user *)info);
}

void
user_free_session(netsnmp_session *sess)
{
    if (NULL == sess) {
        return;
    }
    user_free((netsnmp_user *)sess->sm_info);
    return;
}


   /**
    *
    *  Print a USM structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
user_bprint(netsnmp_buf *buf, netsnmp_user *info)
{
    if (NULL == buf) {
	return -1;
    }
    if (NULL == info) {
	return 0;
    }

    __B(buffer_append_string(buf, "UsmSecurity Parameters:\n"))
    __B(engine_bprint(buf, info->sec_engine))
    __B(buffer_append_string(buf, " msgUserName = "))
    __B(buffer_append_bufstr(buf, info->user_name))	/* XXX  user_name ? */
/*
    __B(buffer_append_string(buf, "\n msgAuthParameters = "))
    __B(buffer_append_hexstr(buf, info->auth_parameters))
    __B(buffer_append_string(buf, "\n msgPrivParameters = "))
    __B(buffer_append_hexstr(buf, info->priv_parameters))
 */
    __B(buffer_append_string(buf, "\n"))
    return 0;
}

int
user_sm_bprint(netsnmp_buf *buf, void *info)
{
    return user_bprint(buf, (netsnmp_user*)info);
}


   /**
    *
    *  Print a USM structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
user_sprint(char *str_buf, int len, netsnmp_user *info)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == user_bprint(buf, info)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a USM structure to the specified file.
    *
    */
void
user_fprint(FILE * fp, netsnmp_user *info)
{
    netsnmp_buf    *buf;

    if (NULL == info) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == user_bprint(buf, info)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a USM structure to standard output. 
    *
    */
void
user_print(netsnmp_user *info)
{
    user_fprint(stdout, info);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package snmpv3_internals */

   /**
    *  Find the given User in the internal list.
    *  Returns a pointer to the relevant structure if successful, NULL otherwise.
    */
netsnmp_user *
user_find(char *name, int len, netsnmp_engine *engine)
{
    netsnmp_user *user = NULL;

    if ((NULL == name) || (0 == len)) {
        return NULL;
    }

    for (user = user_head; NULL != user; user = user->next ) {
        if ((user->sec_engine == engine) &&
            (user->user_name->cur_len == len) &&
            (0 == memcmp(name, user->user_name->string, len))) {
            return user;
        }
    }

    /*
     * Not found
     */
    return NULL;
}


    /**
     * Insert the user structure in the internal list of users,
     *   correctly ordered to match the usmUserTable.
     */
void
user_insert(netsnmp_user *user)
{
    netsnmp_user *u;

    if ((NULL == user) || (NULL == user->user_name)) {
        return;
    }

    u = user_head;

    /*
     * Look for the entry immediately following the new entry,
     *   which will therefore be inserted before this point.
     */

    if (NULL == user->sec_engine) {
        /*
         * The list starts with entries without a security engine,
         *   so if the new user entry also doesn't have an engine,
         *   we only need to look through these initial entries,
         *   and just check the security name.
         */
        while (u && (NULL == u->sec_engine) &&
            (0 < buffer_compare(u->user_name, user->user_name))) {
            u = u->next;
        }
    } else {
        /*
         * Otherwise (i.e. the new entry includes a security engine)
         *   skip these initial "no engine" entries.
         */
        while (u && (NULL == u->sec_engine)) {
            u = u->next;
        }

        /*
         * Then look for the "following" entry according to these criteria:
         *
         *       1)  Firstly, entries are sorted by engine ID length
         *       2)  Within equal length IDs,
         *               entries are sorted by engine ID
         *       3)  Within identical IDs,
         *               entries are sorted by security name
         *
         * This matches the ordering of the usmUserTable (see RFC 2574)
         */
        while (u && (0 < engine_compare(u->sec_engine, user->sec_engine))) {
            u = u->next;
        }
        while (u && (u->sec_engine == user->sec_engine) &&
            (0 < buffer_compare(u->user_name, user->user_name))) {
            u = u->next;
        }
    }

    /*
     * Is this user already in the list?
     * Shouldn't happen, but check anyway.
     */
    if (u && (u->sec_engine == user->sec_engine) &&
        (0 == buffer_compare(u->user_name, user->user_name))) {
        return;
    }
 

    /*
     * Now insert the user structure into the list
     *   immediately prior to 'u'
     * If 'u' is NULL, then insert the user at the end of the list
     *   (i.e. after user_tail)
     */
    user->ref_count++;
    if (NULL != u) {
        if (NULL == u->prev) {
            user_head     = user;
        } else {
            u->prev->next = user;
        }
        user->next = u;
        user->prev = u->prev;
        u->prev    = user;
    } else {
        if (NULL == user_tail) {
            user_head     = user;
        } else {
            user_tail->next = user;
        }
        user->prev = user_tail;
        user->next = NULL;
        user_tail  = user;
    }

    /*
     * Remember where the 'null' user is,
     *   so we can use this for agent discovery.
     *
     * This will normally be the head of the list anyway,
     *   but it feels safer to reference it explicitly.
     */
    if ((NULL == user->sec_engine) &&
        ('\0' == *(user->user_name->string))) {
        user->ref_count++;
        user_anon = user;
    }
}


#include "ucd/ucd_api.h"

void
user_session_defaults(struct snmp_session *session, netsnmp_user *info)
{
    if ((NULL == session) || (NULL == info)) {
        return;
    }

    if (NULL == info->sec_engine) {
        if (session->securityEngineIDLen) {
            info->sec_engine =
                engine_new(session->securityEngineID,
                           session->securityEngineIDLen);
        }
    }

    if (NULL == info->user_name) {
        info->user_name = buffer_new(session->securityName,
                                    session->securityNameLen, 0);
    }
}


                /**************************************
                 *
                 *      Security Model Processing routines
                 *
                 **************************************/


#define USM_MD5_AUTHLEN 12		/* Also used for SHA */
#define USM_MAX_AUTHLEN USM_MD5_AUTHLEN

   /**
    *  ASN.1-encode a UserSM-based PDU.
    *  Returns 0 if successful, -ve otherwise
    *
    *  When called, the buffer should contain a scopedPDU
    */
int
user_encode_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf)
{
    int start_len;
    int hdr_start_len;
    u_char *auth_offset      = NULL;
    netsnmp_v3info *v3info   = NULL;
    netsnmp_user   *userinfo = NULL;

    if ((NULL == buf ) || (NULL == pdu) || (NULL == pdu->v3info)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }
    v3info   = pdu->v3info;
    userinfo = (netsnmp_user*)pdu->sm_info;

    if (NULL == userinfo) {
        if (NULL == v3info->sec_name) {
            userinfo = user_create("", 0, v3info->sec_engine);
        } else {
            userinfo = user_create(v3info->sec_name->string,
                                   v3info->sec_name->cur_len,
                                   v3info->sec_engine);
        }
    }

    if (NETSNMP_AUTH_PROTOCOL_DEFAULT == userinfo->auth_protocol) {
        userinfo->auth_protocol = NETSNMP_AUTH_PROTOCOL_MD5;
    }
    if (NETSNMP_PRIV_PROTOCOL_DEFAULT == userinfo->priv_protocol) {
        userinfo->priv_protocol = NETSNMP_PRIV_PROTOCOL_DES;
    }

    start_len     = 0;		/* XXX - we really want the value of 'start_len' from
					from the routine that called this one.
					But since we'll be starting from an empty buffer,
					it should be safe(-ish) to hardwire this.	*/
    hdr_start_len = buf->cur_len;	/* Remember the length before we start */


    if ( v3info->v3_flags & PRIV_FLAG ) {
        /*
         * If this message requires privacy,
         * replace the scoped PDU in the buffer with the encrypted
         *   version, and note the new length (which will probably
         *   be different from the original scoped PDU).
         *
         * Then add the privParameters value from the userinfo structure
         *   (which should be set up by the encryption routine).
         * This is done here (rather than within the encryption routine
         *   itself) so that this value can be correctly included within
         *   the UsmSecurityParameters SEQUENCE header
         */
	__B(priv_encrypt(buf, userinfo))
        hdr_start_len = buf->cur_len;
        __B(encode_bufstr(buf, userinfo->priv_params ))
    }
    else {
        __B(encode_bufstr(buf, NULL))
    }

    if ( v3info->v3_flags & AUTH_FLAG ) {
        /*
         * If this message requires authentication,
         *   add the authParameters field.
         *
         * Note that this may often contain a dummy 'placeholder'
         *   value, as the full authenticated signature probably
         *   cannot be calculated until the rest of the
         *   UsmSecurityParameters have been provided.
         * We therefore need to remember the appropriate location
         *   in the encoded PDU, and fill in the real value later.
         */
        auth_offset    = buffer_string(buf);
        __B(auth_stamp_pre(buf, userinfo))
    }
    else {
        __B(encode_bufstr(buf, NULL))
    }

    /*
     * Now encode the rest of the UsmSecurityParameters header...
     */
    __B(encode_bufstr( buf, userinfo->user_name))
    __B(engine_encode( buf, userinfo->sec_engine))
    __B(encode_sequence(buf, (buf->cur_len - hdr_start_len)))

    /*
     * .... and wrap the whole thing within an OCTET STRING
     */
    __B(encode_asn1_header(buf, ASN_OCTET_STR, (buf->cur_len - hdr_start_len)))


    /*
     * Finish encoding the full v3 PDU
     */
    __B(v3info_encode( buf, v3info))
    __B(encode_integer(buf, ASN_INTEGER, pdu->version))
    __B(encode_sequence(buf, (buf->cur_len - start_len)))


    /*
     * If this message requires authentication, we can now calculate
     *  the real authentication signature and insert it into the encoded PDU.
     */
    if ( v3info->v3_flags & AUTH_FLAG ) {
        __B(auth_stamp_post(buf, userinfo, auth_offset))
    }

    return 0;
}


netsnmp_pdu*
user_decode_pdu(netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_buf *wholeMsg)
{
    netsnmp_buf    *user_params = NULL;
    netsnmp_buf    *seq      = NULL;
    netsnmp_engine *sec_eng  = NULL;
    netsnmp_buf    *user_name = NULL;
    netsnmp_buf    *tmp      = NULL;
    netsnmp_user   *user     = NULL;
    netsnmp_pdu    *pdu      = NULL;
    char *cp;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }


    /*
     * Unpack the UsmSecurityParameters header from the
     *   enclosing OCTET STRING and sequence
     */
    user_params = decode_string(buf, NULL);
    if (NULL == user_params) {
        goto fail;
    }
    seq = decode_sequence(user_params);
    if ((NULL == seq) || (0 != user_params->cur_len)) {
        goto fail;
    }
    sec_eng = engine_decode( seq, NULL );
    if (NULL == sec_eng ) {
        goto fail;
    }
    user_name   = decode_string( seq, NULL );
    if (NULL == user_name ) {
        goto fail;
    }

    /*
     * Retrieve (or create) the user structure for this user
     * This can legitimately fail for non-authenticated requests
     *    (e.g. engine probes)
     */
    user = user_create( user_name->string, user_name->cur_len, sec_eng);
    if (NULL == user) {
        if (NULL != user_name->string) {
            goto fail;
        }

        /*
         *  If there wasn't a security name specified, and so
         *    the 'user_create' call failed, then we still
         *    need something to hang everything else off.
         */
        user = (netsnmp_user *)calloc(1, sizeof(netsnmp_user));
        if (NULL == user) {
            return NULL;
        }
        user->user_name = user_name;
        user->sec_engine = sec_eng;
        user->ref_count++;
    }

    /*
     * Extract the authParameters, and attempt to authenticate the
     *   request if so indicated.  Remember the current location, so we
     *   can blank out the signature before authenticating the message.
     * Note that for unauthenticated requests, the authParameters field
     *   will result in a non-NULL buffer, containing an empty string.
     */
    user->auth_params = decode_string( seq, NULL );
    if (NULL == user->auth_params ) {
        goto fail;
    }
    if ( v3info->v3_flags & AUTH_FLAG ) {

        /*
         * Blank out the signature from the original message,
         *   so we can authenticate it.
         *
         * The good news is that the working copy and 'wholeMsg'
         *   share a common underlying buffer, so blanking this in
         *   the current working copy (via 'cp') works as expected.
         *
         * The bad news is that the 'auth_params' structure also
         *   uses this common underlying buffer.  So we need to
         *   make a copy of the authentication parameters before
         *   wiping them from the original message.
         */
        cp  = seq->string - user->auth_params->cur_len;
        tmp = buffer_copy(user->auth_params);
        buffer_free(user->auth_params);
        user->auth_params = tmp;
        memset(cp, 0, user->auth_params->cur_len);

        /*
         * The signature itself needs to be calculated over the
         *  whole message buffer.
         */
        if (-1 == auth_verify(wholeMsg, user)) {
            goto fail;
        }
    }


    /*
     * Extract the privParameters (which may also be an empty string)
     * If the request has been encrypted, replace the contents of the
     *   input 'buf' with the decrypted version.
     */
    user->priv_params= decode_string( seq, NULL );
    if (NULL == user->priv_params ) {
        goto fail;
    }
    if (0 != seq->cur_len) {
        goto fail;
    }
    buffer_free(seq);
    if ( v3info->v3_flags & PRIV_FLAG ) {
        if (-1 == priv_decrypt(buf, user)) {
            goto fail;
        }
    }


    /*
     *  Now decode the rest of the scopedPDU.
     */
    v3info->sec_engine = engine_copy(user->sec_engine);
    v3info->sec_name   = buffer_copy(user->user_name);

    seq = decode_sequence( buf );
    if (NULL == seq) {
        goto fail;
    }
    v3info->context_engine = engine_decode_ID(seq, NULL);
    v3info->context_name   = decode_string(seq, NULL);
    pdu = decode_basic_pdu(seq, NULL);
    if (NULL == pdu) {
        goto fail;
    }

    pdu->v3info   = v3info;
    pdu->sm_info  = (void*)user;

    return pdu;

fail:
    buffer_free( user_params );
    buffer_free( seq );
    buffer_free( user_name );
    engine_free( sec_eng );
    user_free( user );
    /* v3info_free( v3info ); */
    return NULL;
}


