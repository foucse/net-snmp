/*******************************
 *
 *      community/cinfo.c
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
cinfo_create(char *cstring, int len)
{
    netsnmp_comminfo *cinfo;

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

    cinfo = (netsnmp_comminfo*) calloc(1, sizeof(netsnmp_comminfo));

    if (NULL != cinfo) {
	cinfo->ref_count++;
	if (0 > cinfo_set(cinfo, cstring, len)) {
	     free( cinfo );
	     cinfo = NULL;
	}
    }
    return cinfo;
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
cinfo_copy(netsnmp_comminfo *cinfo)
{
    if (NULL == cinfo) {
	return NULL;
    }

	/*
	 * Rather than copying the memory,
	 *  point to the same structure, keeping
	 *  a count of the number of references.
	 */
    cinfo->ref_count++;
    return cinfo;
}


   /**
    *
    *  Set the community string to the given value
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
cinfo_set(netsnmp_comminfo *cinfo, char *cstring, int cstr_len)
{
		/*
		 * XXX - this can't cope with setting
		 *   a new value for a shared structure.
		 *   Is this a problem?
		 *
		 * If so, this routine could return a
		 *   pointer to the 'same' cinfo structure
		 *   (or NULL), and create a new one if
		 *   necessary.
		 */
    if ((NULL == cinfo) || (NULL == cstring)) {
        return -1;
    }


    if (cinfo->string && (0 == strcmp(cinfo->string, cstring))) {
	return 0;	/* Already correct */
    }
    if (1 != cinfo->ref_count) {
	return -1;	/* Can't change this if someone else is using it */
    }

    if (cinfo->string && (cinfo->string != cinfo->buf)) {
	free(cinfo->string);	/* Free any previously alloc'ed memory */
	cinfo->string = NULL;
    }

    if (NETSNMP_VALBUF_LEN > cstr_len+1) {
	cinfo->string = cinfo->buf;	/* Use the internal buffer */
    } else {
	cinfo->string = (u_char *)calloc(cstr_len+1, 1);
	if (NULL == cinfo->string) {
	    return -1;
	}
    }
    memcpy(cinfo->string, cstring, cstr_len);
    cinfo->string[cstr_len] = '\0';
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
cinfo_free(netsnmp_comminfo *cinfo)
{

    if (NULL == cinfo) {
	return;
    }
    if (0 < --(cinfo->ref_count)) {
	return;		/* Someone else is still using this */
    }

    if (cinfo->string && (cinfo->string != cinfo->buf)) {
	free(cinfo->string);	/* Free any alloc'ed memory */
    }
    cinfo->string = NULL;
    free( cinfo );
    return;
}


   /**
    *
    *  Print a community-info structure in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
cinfo_bprint(netsnmp_buf *buf, netsnmp_comminfo *cinfo)
{
    if (NULL == buf) {
	return -1;
    }
    if (NULL == cinfo) {
	return 0;
    }

    __B(buffer_append_string(buf, cinfo->string))
    return 0;
}


   /**
    *
    *  Print a community-info structure in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
cinfo_sprint(char *str_buf, int len, netsnmp_comminfo *cinfo)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == cinfo_bprint(buf, cinfo)) {
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
cinfo_fprint(FILE * fp, netsnmp_comminfo *cinfo)
{
    netsnmp_buf    *buf;

    if (NULL == cinfo) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == cinfo_bprint(buf, cinfo)) {
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
cinfo_print(netsnmp_comminfo *cinfo)
{
    cinfo_fprint(stdout, cinfo);
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
cinfo_encode(netsnmp_buf *buf, netsnmp_comminfo *cinfo)
{
    int cstr_len;

    if ((NULL == buf) || (NULL == cinfo)) {
	return -1;
    }
    if (cinfo->string) {
	cstr_len = strlen(cinfo->string);
    } else {
        cstr_len = 0;
    }
    return encode_string(buf, ASN_OCTET_STR, cinfo->string, cstr_len);
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

