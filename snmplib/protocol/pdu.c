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
#include <net-snmp/utils.h>




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
    return pdu;
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

		/* XXX - print the PDU header fields */

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

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
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


