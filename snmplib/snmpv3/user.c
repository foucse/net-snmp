/*******************************
 *
 *      snmpv3/user.c
 *
 *      Net-SNMP library - SNMPv3 interface
 *
 *      User-based Security Model handling routines
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
#include "snmpv3/snmpv3.h"

netsnmp_user *user_head = NULL;
netsnmp_user *user_tail = NULL;
netsnmp_user *user_anon = NULL;		/* Used for engine discovery */

netsnmp_user* user_find(char *name, int len, netsnmp_engine *engine);
void user_insert(netsnmp_user *user);


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
    user->sec_name   = buffer_new(name, len, 0);
    if (NULL == user->sec_name) {
        free(user);
        return NULL;
    }
    if (NULL != engine) {
        user->sec_engine = engine_copy( engine );
        if (NULL == user->sec_engine) {
            buffer_free(user->sec_name);
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

    if (NULL != info) {
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
    info_copy->sec_name    = buffer_copy( info->sec_name);
    info_copy->sec_engine  = engine_copy( info->sec_engine);

    info_copy->auth_protocol    = info->auth_protocol;
    info_copy->auth_key         = buffer_copy( info->auth_key);

    info_copy->priv_protocol    = info->priv_protocol;
    info_copy->priv_key         = buffer_copy( info->priv_key);

    return info_copy;
 */
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
    buffer_free(info->sec_name);
    engine_free(info->sec_engine);
    buffer_free(info->auth_key);
    buffer_free(info->priv_key);
    free( info );
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
    __B(buffer_append_bufstr(buf, info->sec_name))	/* XXX  user_name ? */
/*
    __B(buffer_append_string(buf, "\n msgAuthParameters = "))
    __B(buffer_append_hexstr(buf, info->auth_parameters))
    __B(buffer_append_string(buf, "\n msgPrivParameters = "))
    __B(buffer_append_hexstr(buf, info->priv_parameters))
 */
    __B(buffer_append_string(buf, "\n"))
    return 0;
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

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
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

#define USM_MD5_AUTHLEN 12		/* Also used for SHA */
#define USM_MAX_AUTHLEN USM_MD5_AUTHLEN

   /**
    *  ASN.1-encode a USM header structure.
    *  Returns 0 if successful, -ve otherwise
    *
    *  When called, the buffer should contain a scopedPDU
    */
int
user_encode(netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_user *userinfo)
{
    int start_len;

    if ((NULL == buf ) || (NULL == v3info) || (NULL == userinfo)) {
        return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
        return -1;	/* XXX - or set the flag ? */
    }


    start_len = buf->cur_len;	/* Remember the length before we start */


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
	__B(priv_encrypt(buf, v3info, userinfo))
        start_len = buf->cur_len;
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
        v3info->auth_saved_len = buf->cur_len;
        __B(auth_stamp_pre(buf, v3info, userinfo))
    }
    else {
        __B(encode_bufstr(buf, NULL))
    }

    /*
     * Now encode the rest of the UsmSecurityParameters header...
     */
    __B(encode_bufstr( buf, userinfo->sec_name))
    __B(engine_encode( buf, userinfo->sec_engine))
    __B(encode_sequence(buf, (buf->cur_len - start_len)))

    /*
     * .... and wrap the whole thing within an OCTET STRING
     */
    __B(encode_asn1_header(buf, ASN_OCTET_STR, (buf->cur_len - start_len)))


#ifdef NOT_HERE
    /*
     * If this message requires authentication, we can now calculate
     *  the real authentication signature and insert it into the encoded PDU.
     */
    if ( v3info->v3_flags & AUTH_FLAG ) {
        __B(auth_stamp_post(buf, v3info, userinfo, auth_saved_len))
    }
#endif
    return 0;
}


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
            (user->sec_name->cur_len == len) &&
            (0 == memcmp(name, user->sec_name->string, len))) {
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

    if ((NULL == user) || (NULL == user->sec_name)) {
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
            (0 < buffer_compare(u->sec_name, user->sec_name))) {
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
            (0 < buffer_compare(u->sec_name, user->sec_name))) {
            u = u->next;
        }
    }

    /*
     * Is this user already in the list?
     * Shouldn't happen, but check anyway.
     */
    if (u && (u->sec_engine == user->sec_engine) &&
        (0 == buffer_compare(u->sec_name, user->sec_name))) {
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
        ('\0' == *(user->sec_name->string))) {
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

    if (NULL == info->sec_name) {
        info->sec_name = buffer_new(session->securityName,
                                    session->securityNameLen, 0);
    }
}
