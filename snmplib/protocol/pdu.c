/*******************************
 *
 *      protocol/pdu.c
 *
 *      Net-SNMP library - Version-independent SNMP interface
 *
 *      Version-independent PDU-handling routines
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
#include <net-snmp/community_api.h>
#include <net-snmp/protocol_api.h>
#include <net-snmp/snmpv3.h>
#include <net-snmp/utils.h>

#include "protocol/decode.h"
#include "community/community.h"
#include "snmpv3/snmpv3.h"
#include "ucd/ucd_convert.h"



                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/protocol_api.h>)
                 *
                 **************************************/
                /** @package protocol_api */


   /**
    *
    *  Create a new PDU structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_pdu *
pdu_create(int version, int command)
{
    netsnmp_pdu *pdu;

    pdu = (netsnmp_pdu*) calloc(1, sizeof(netsnmp_pdu));
    if (NULL != pdu) {
	pdu->version = version;
	pdu->command = command;
    }
    pdu->request = snmp_get_next_reqid();
    return pdu;
}


netsnmp_pdu *
pdu_copy(netsnmp_pdu *pdu)
{
    netsnmp_varbind *vb;
    netsnmp_pdu     *copy;

    if (NULL == pdu) {
        return NULL;
    }

    copy = pdu_create(pdu->version, pdu->command);
    if (NULL == copy) {
        return NULL;
    }

    memcpy((void*)copy, (void*)pdu, sizeof(netsnmp_pdu));

    if (pdu->community) {
	copy->community = comminfo_copy(pdu->community);
    }
    if (pdu->v3info) {
	copy->v3info = v3info_copy(pdu->v3info);
    }
    if (pdu->userinfo) {
	copy->userinfo = user_copy(pdu->userinfo);
    }

    copy->varbind_list = NULL;
    for (vb = pdu->varbind_list; NULL != vb; vb=vb->next) {
        (void)pdu_add_varbind(copy, var_copy_varbind(vb));
    }
    return copy;
}


   /**
    *
    *  Free a PDU structure
    *
    *  The pointer should not be regarded as valid
    *  once this routine has been called.
    */
void
pdu_free(netsnmp_pdu *pdu)
{
    if (pdu->community) {
	comminfo_free(pdu->community);
	pdu->community = NULL;
    }

    if (pdu->v3info) {
	v3info_free(pdu->v3info);
	pdu->v3info = NULL;
    }
    if (pdu->userinfo) {
	user_free(pdu->userinfo);
	pdu->userinfo = NULL;
    }

    vblist_free(pdu->varbind_list);
    pdu->varbind_list = NULL;

    free( pdu );
    return;
}


   /**
    *
    *  Add the specified varbind to the given PDU
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
pdu_add_varbind(netsnmp_pdu *pdu, netsnmp_varbind *varbind)
{
    if ((NULL == varbind) || (NULL == pdu)) {
        return -1;
    }

    if (NULL == pdu->varbind_list) {
        pdu->varbind_list = varbind;
        return 0;
    }
    return vblist_add_varbind(pdu->varbind_list, varbind);
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
netsnmp_varbind*
pdu_return_varbind(netsnmp_pdu *pdu, int idx)
{
    int             i;

    if (NULL == pdu) {
        return NULL;
    }

    i = idx;
    if (-1 == idx) {
        i = pdu->errindex;
    }

    return vblist_return_varbind(pdu->varbind_list, i);
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
netsnmp_varbind*
pdu_extract_varbind(netsnmp_pdu *pdu, int idx)
{
    int             i;
    netsnmp_varbind *vb;

    if (NULL == pdu) {
        return NULL;
    }

    i = idx;
    if (-1 == idx) {
        i = pdu->errindex;
    }

    vb = vblist_extract_varbind(pdu->varbind_list, i);
        /* 
         * Adjust if this was the (old) head of the list
         */
    if (vb && (pdu->varbind_list == vb)) {
        pdu->varbind_list = vb->next;
    }
    return vb;
}


   /**
    *
    *  Print a PDU in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
pdu_bprint(netsnmp_buf *buf, netsnmp_pdu *pdu)
{
    if (NULL == buf ) {
	return -1;
    }
    if (NULL == pdu ) {
	return 0;
    }

    /*
     * Print the common PDU header fields....
     */
    __B(buffer_append_string(buf, "PDU:\n Version = "))
    __B(buffer_append_int(   buf, pdu->version))
    __B(buffer_append_string(buf, "\n Command = "))
    __B(buffer_append_int(   buf, pdu->command))
    __B(buffer_append_string(buf, "\n ErrStatus = "))
    __B(buffer_append_int(   buf, pdu->errstatus))
    __B(buffer_append_string(buf, "\n ErrIndex = "))
    __B(buffer_append_int(   buf, pdu->errindex))
    __B(buffer_append_string(buf, "\n RequestID = "))
    __B(buffer_append_int(   buf, pdu->request))
    __B(buffer_append_string(buf, "\n Flags = "))
    __B(buffer_append_int(   buf, pdu->flags))
    __B(buffer_append_char(  buf, '\n'))

    /*
     *  ... the version-specific header information....
     */
    if (pdu->community) {
        __B(comminfo_bprint(buf, pdu->community))
    }
    if (pdu->v3info) {
        __B(v3info_bprint(buf, pdu->v3info))
    }
    if (pdu->userinfo) {
        __B(user_bprint(buf, pdu->userinfo))
    }
    /*
     *  ... and the list of Variable Bindings
     */
    __B(vblist_bprint(buf, pdu->varbind_list))
    return 0;
}


   /**
    *
    *  Print a PDU in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
pdu_sprint(char *str_buf, int len, netsnmp_pdu *pdu)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == pdu_bprint(buf, pdu)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a PDU to the specified file.
    *
    */
void
pdu_fprint(FILE * fp, netsnmp_pdu *pdu)
{
    netsnmp_buf    *buf;

    if (NULL == pdu) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == pdu_bprint(buf, pdu)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a PDU to standard output. 
    *
    */
void
pdu_print(netsnmp_pdu *pdu)
{
    pdu_fprint(stdout, pdu);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package protocol_internals */


#define _SWITCH_VERSION(v, x, y, z )	switch ((v)) { \
				case SNMP_VERSION_1:	\
				case SNMP_VERSION_2c:	\
				case SNMP_VERSION_ANYC:	\
				    return community_build_pdu(x, y, z); \
				case SNMP_VERSION_3:	\
				    return snmpv3_build_pdu(x, y, z); \
				case SNMP_VERSION_ANY:	\
				case SNMP_DEFAULT_VERSION: \
				    break;		\
				default:		\
				    return -1;		\
				}

int
snmp_build_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf)
{
    if ((NULL == sess) ||
        (NULL == pdu)  ||
        (NULL == buf)) {
        return -1;
    }

    _SWITCH_VERSION( pdu->version, sess, pdu, buf);
    _SWITCH_VERSION(sess->version, sess, pdu, buf);

    return -1;
}


   /**
    *  Parse an SNMP PDU from the given input buffer.
    *
    *  blah, blah, returns pointer, blah, release memory, blah blah
    */
netsnmp_pdu*
pdu_parse(netsnmp_buf *buf)
{
    netsnmp_buf *seq  = NULL;
    netsnmp_pdu *pdu = NULL;
    long version;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    seq = decode_sequence(buf);
    if (NULL == seq) {
        return NULL;
    }
    if (NULL == decode_integer(seq, &version)) {
        buffer_free(seq);
        return NULL;
    }

    switch( version ) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
        pdu = community_decode_pdu(seq);
        break;
    case SNMP_VERSION_3:
        pdu = snmpv3_decode_pdu(seq);
        break;
    default:
        /* UNKNOWN VERSION */
        break;
    }

    if (NULL == pdu) {
        buffer_free(seq);
        return NULL;
    }
    if (0 != seq->cur_len) {
        pdu_free(pdu);
        buffer_free(seq);
        return NULL;
    }

    pdu->version = version;
    buffer_free(seq);

    return pdu;
}


#include "ucd/ucd_api.h"

int
_snmp_parse(void *sess, struct snmp_session *session, struct snmp_pdu *pdu, u_char *data, size_t length)
{
    netsnmp_pdu *p;
    struct snmp_pdu *p2;
    netsnmp_buf* buf;

    pdu->transid = snmp_get_next_transid();

    buf = buffer_new(data, length, NETSNMP_BUFFER_NOCOPY|NETSNMP_BUFFER_NOFREE);
    buf->cur_len = buf->max_len;

    p = pdu_parse(buf);
    if (NULL == p) {
        buffer_free(buf);
        return-1;	/* XXX ??? */
    }
    p2 = ucd_revert_pdu( p );
    memcpy(pdu, p2, sizeof(struct snmp_pdu));
/*  free(p2);		*/

/*
    data = buf->string;
    *length = buf->cur_len;
 */
    return 0;		/* XXX ?? */
}
