/*******************************
 *
 *      community/comminfo.c
 *
 *      Net-SNMP library - Community-based SNMP interface
 *
 *      Community-information structure handling routines
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
#include <net-snmp/community_api.h>

typedef u_long oid;
#define SNMPERR_SUCCESS		(0)
#define ERROR_MSG(string)   snmp_set_detail(string)

#include "protocol/encode.h"
#include "protocol/asn1_parse.h"
#include "community/community.h"
#include "snmp_debug.h"

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/community_api.h>)
                 *
                 **************************************/
                /** @package community_api */


   /**
    *
    *  Create a new community-info structure,
    *  for the given community string.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_comminfo *
comminfo_create(char *cstring, int len)
{
    netsnmp_comminfo *info;

    if (NULL == cstring) {
	/* XXX - Is this acceptable or not ? - say No for now */
	return NULL;
    }

		/*
		 * XXX - A possible alternative approach
		 *
		 * Hold a registry of known community-info structures
		 *   and their strings, and return a pointer to the
		 *   appropriate existing one (if any).
		 */

    info = (netsnmp_comminfo*) calloc(1, sizeof(netsnmp_comminfo));

    if (NULL != info) {
	info->ref_count++;
	if (0 > comminfo_set(info, cstring, len)) {
	     free( info );
	     info = NULL;
	}
    }
    return info;
}


   /**
    *
    *  Create a copy of a community-info structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_comminfo *
comminfo_copy(netsnmp_comminfo *info)
{
    if (NULL == info) {
	return NULL;
    }

	/*
	 * Rather than copying the memory,
	 *  point to the same structure, keeping
	 *  a count of the number of references.
	 */
    info->ref_count++;
    return info;
}


   /**
    *
    *  Set the community string to the given value
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
comminfo_set(netsnmp_comminfo *info, char *cstring, int cstr_len)
{
		/*
		 * XXX - this can't cope with setting
		 *   a new value for a shared structure.
		 *   Is this a problem?
		 *
		 * If so, this routine could return a
		 *   pointer to the 'same' comminfo structure
		 *   (or NULL), and create a new one if
		 *   necessary.
		 */
    if ((NULL == info) || (NULL == cstring)) {
        return -1;
    }


    if (info->string && (0 == strcmp(info->string, cstring))) {
	return 0;	/* Already correct */
    }
    if (1 != info->ref_count) {
	return -1;	/* Can't change this if someone else is using it */
    }

    if (info->string && (info->string != info->buf)) {
	free(info->string);	/* Free any previously alloc'ed memory */
	info->string = NULL;
    }

    if (NETSNMP_VALBUF_LEN > cstr_len+1) {
	info->string = info->buf;	/* Use the internal buffer */
    } else {
	info->string = (u_char *)calloc(cstr_len+1, 1);
	if (NULL == info->string) {
	    return -1;
	}
    }
    memcpy(info->string, cstring, cstr_len);
    info->string[cstr_len] = '\0';
    return 0;
}


   /**
    *
    *  Free a community-info structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
comminfo_free(netsnmp_comminfo *info)
{

    if (NULL == info) {
	return;
    }
    if (0 < --(info->ref_count)) {
	return;		/* Someone else is still using this */
    }

    if (info->string && (info->string != info->buf)) {
	free(info->string);	/* Free any alloc'ed memory */
    }
    info->string = NULL;
    free( info );
    return;
}


   /**
    *
    *  Print a community-info structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
comminfo_bprint(netsnmp_buf *buf, netsnmp_comminfo *info)
{
    if (NULL == buf) {
	return -1;
    }
    if (NULL == info) {
	return 0;
    }

    __B(buffer_append_string(buf, info->string))
    return 0;
}


   /**
    *
    *  Print a community-info structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
comminfo_sprint(char *str_buf, int len, netsnmp_comminfo *info)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == comminfo_bprint(buf, info)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a community-info structure to the specified file.
    *
    */
void
comminfo_fprint(FILE * fp, netsnmp_comminfo *info)
{
    netsnmp_buf    *buf;

    if (NULL == info) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == comminfo_bprint(buf, info)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a community-info structure to standard output. 
    *
    */
void
comminfo_print(netsnmp_comminfo *info)
{
    comminfo_fprint(stdout, info);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package community_internals */


   /**
    *
    *  ASN.1-encode a community-info structure.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
comminfo_encode(netsnmp_buf *buf, netsnmp_comminfo *info)
{
    int cstr_len;

    if ((NULL == buf) || (NULL == info)) {
	return -1;
    }
    if (info->string) {
	cstr_len = strlen(info->string);
    } else {
        cstr_len = 0;
    }
    return encode_string(buf, ASN_OCTET_STR, info->string, cstr_len);
}


netsnmp_comminfo*
comminfo_decode(netsnmp_buf *buf)
{
    netsnmp_buf      *seq      = NULL;
    netsnmp_buf      *str      = NULL;
    netsnmp_comminfo *comminfo = NULL;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    str = decode_string(buf, NULL);
    if (NULL == str) {
        return NULL;
    }
    comminfo = comminfo_create(str->string, str->cur_len);
    buffer_free(str);
    return comminfo;
}


/*******************************************************************-o-******
 * snmp_comstr_parse
 *
 * Parameters:
 *	*data		(I)   Message.
 *	*length		(I/O) Bytes left in message.
 *	*psid		(O)   Community string.
 *	*slen		(O)   Length of community string.
 *	*version	(O)   Message version.
 *      
 * Returns:
 *	Pointer to the remainder of data.
 *
 *
 * Parse the header of a community string-based message such as that found
 * in SNMPv1 and SNMPv2c.
 */
u_char *
snmp_comstr_parse(u_char *data,
		  size_t *length,
		  u_char *psid,
		  size_t *slen,
		  long *version)
{
    u_char   	type;
    long	ver;


    /* Message is an ASN.1 SEQUENCE.
     */
    data = asn_parse_sequence(data, length, &type,
                        (ASN_SEQUENCE | ASN_CONSTRUCTOR), "auth message");
    if (data == NULL){
        return NULL;
    }

    /* First field is the version.
     */
    DEBUGDUMPHEADER("recv", "SNMP version");
    data = asn_parse_int(data, length, &type, &ver, sizeof(ver));
    DEBUGINDENTLESS();
    *version = ver;
    if (data == NULL){
        ERROR_MSG("bad parse of version");
        return NULL;
    }

    /* second field is the community string for SNMPv1 & SNMPv2c */
    DEBUGDUMPHEADER("recv", "community string");
    data = asn_parse_string(data, length, &type, psid, slen);
    DEBUGINDENTLESS();
    if (data == NULL){
        ERROR_MSG("bad parse of community");
        return NULL;
    }
    psid[*slen] = '\0';
    return (u_char *)data;

}  /* end snmp_comstr_parse() */
