/*******************************
 *
 *      community/pdu.c
 *
 *      Net-SNMP library - Community-based SNMP interface
 *
 *      Community-based PDU handling routines
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
#include <net-snmp/protocol_api.h>
#include <net-snmp/community_api.h>

#include "community/community.h"
#include "protocol/encode.h"
#include "protocol/decode.h"

int community_encode_pdu(netsnmp_buf *buf, netsnmp_pdu *pdu);
int community_check_pdu( netsnmp_pdu *pdu);



#define _CHECK_VERSION( v, x )	switch ((v)) { \
				case SNMP_VERSION_1:	\
				case SNMP_VERSION_2c:	\
				case SNMP_VERSION_ANYC:	\
				case SNMP_VERSION_ANY:	\
				case SNMP_DEFAULT_VERSION: \
				    break;		\
				case SNMP_VERSION_3:	\
				default:		\
				    return (x);		\
				}


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/community_api.h>)
                 *
                 **************************************/
                /** @package community_api */


   /**
    *
    *  Create a new community-based PDU with the given version,
    *    command and community string.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is no longer required.
    */
netsnmp_pdu *
community_create_pdu(int version, int command, char *cstring)
{
    netsnmp_pdu      *pdu;

    if (NULL == cstring) {
	return NULL;
    }

    _CHECK_VERSION( version, NULL )

    pdu = pdu_create(version, command);
    if (pdu) {
        if (0 > community_check_pdu(pdu)) {
	    pdu_free(pdu);
	    return NULL;
	}
        pdu->community = comminfo_create( cstring, strlen(cstring));
	if (NULL == pdu->community) {
	    pdu_free(pdu);
	    return NULL;
	}
    }
    return pdu;
}


   /**
    *  Set the PDU's community string to the given value
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
community_set_cstring(netsnmp_pdu *pdu, char *cstring, int len)
{
    if ((NULL == pdu) || (NULL == cstring)) {
        return -1;
    }

    _CHECK_VERSION( pdu->version, -1 )

	/*
	 * If the PDU already has community info,
	 *  then try to set that to the new string.
	 *  If this fails, then release it, and start afresh.
	 */
    if (pdu->community) {
	if (0 == comminfo_set(pdu->community, cstring, len)) {
	    return 0;		/* Success */
	}
	comminfo_free(pdu->community);
	pdu->community = NULL;
    }

	/*
	 * Create a new community info header structure
	 */
    pdu->community = comminfo_create( cstring, len );
    if (NULL == pdu->community) {
	return -1;
    }
    return 0;
}


   /**
    *  Set the PDU's community info header to match the given value
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
community_set_comminfo(netsnmp_pdu *pdu, netsnmp_comminfo *info)
{
    if ((NULL == pdu) || (NULL == info)) {
        return -1;
    }

    _CHECK_VERSION( pdu->version, -1 )

    if (pdu->community) {
	if (pdu->community == info) {
	    return 0;		/* Already set correctly */
	}
	comminfo_free(pdu->community);
	pdu->community = NULL;
    }
	
    pdu->community = comminfo_copy( info );
    if (NULL == pdu->community) {
	return -1;
    }
    return 0;
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package community_internals */


   /**
    *
    *  ASN.1-encode a community-based PDU.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
community_encode_pdu(netsnmp_buf *buf, netsnmp_pdu *pdu)
{
    int start_len;

    if ((NULL == buf) ||
        (NULL == pdu)) {
	return -1;
    }

    switch (pdu->version) {
    case SNMP_VERSION_1:
    case SNMP_VERSION_2c:
	break;			/* OK */

    case SNMP_VERSION_ANYC:
    case SNMP_VERSION_ANY:
    case SNMP_DEFAULT_VERSION:
    case SNMP_VERSION_3:
    default:
	return -1;		/* Must have a real valid version to send */
    }

    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    if (0 > community_check_pdu(pdu)) {
	return -1;
    }

    start_len= buf->cur_len;    /* Remember the length before we start */

    __B(encode_basic_pdu(buf, pdu))
    __B(comminfo_encode(buf, pdu->community))
    __B(encode_integer(buf, ASN_INTEGER, pdu->version))
    __B(encode_sequence(buf, (buf->cur_len - start_len)))
    return 0;
}


int
community_build_pdu(netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf)
{
    if ((NULL == sess) ||
        (NULL == pdu)  ||
        (NULL == buf)) {
        return -1;
    }

    _CHECK_VERSION(sess->version, -1 )
    _CHECK_VERSION( pdu->version, -1 )

    if ((SNMP_VERSION_ANYC    == pdu->version) ||
        (SNMP_VERSION_ANY     == pdu->version) ||
        (SNMP_DEFAULT_VERSION == pdu->version)) {
        pdu->version = sess->version;
    }

    if (NULL == pdu->community) {
        if ((SNMP_MSG_SET == pdu->command) &&
            (NULL != sess->write_community)) {
            pdu->community = comminfo_copy(sess->write_community);
        } else {
            pdu->community = comminfo_copy(sess->read_community);
        }
    }
    return community_encode_pdu(buf, pdu);
}


   /**
    *  Decode the payload of a community-based SNMP PDU
    *   (i.e. community-information, and the core PDU)
    *   from the given input buffer.
    *  Basically, this routine assumes that the SNMP version
    *   identifier has been decoded, and picks up after that.
    *
    *  blah, blah, returns pointer, blah, release memory, blah blah
    */
netsnmp_pdu*
community_decode_pdu(netsnmp_buf *buf)
{
    netsnmp_pdu *pdu = NULL;
    netsnmp_comminfo *comminfo = NULL;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    comminfo = comminfo_decode(buf);
    if (NULL == comminfo) {
        return NULL;
    }
    pdu = decode_basic_pdu(buf, NULL);
    if (NULL == pdu) {
        comminfo_free(comminfo);
        return NULL;
    }
    pdu->community = comminfo;
    return pdu;
}


   /**
    *  Parse a community-based SNMP PDU from the given input buffer.
    *
    *  blah, blah, returns pointer, blah, release memory, blah blah
    */
netsnmp_pdu*
community_parse_pdu(netsnmp_buf *buf)
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

		/*
		 * XXX
		 *   Need to handle SNMPv1 Traps specially
		 *   ?? Look ahead at the 'command' value,
		 *   ?? or push this into 'community_decode_pdu'
		 *	and check for version mismatch later?
		 */
    pdu = community_decode_pdu(seq);
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


int
community_check_pdu(netsnmp_pdu *pdu)
{
    netsnmp_varbind *vb;

    if (NULL == pdu ) {
	return -1;
    }

    _CHECK_VERSION( pdu->version, -1 )

	/*
	 * Check command for compatability with version
	 */
    switch (pdu->command) {

    case SNMP_MSG_RESPONSE:
    case SNMP_MSG_GET:
    case SNMP_MSG_GETNEXT:
    case SNMP_MSG_SET:
	break;			/* Valid in all versions */

    case SNMP_MSG_TRAP:		/* Only valid in (potential) V1 PDUs */
	if (SNMP_VERSION_2c == pdu->version) {
	    return -1;
	}
	break;

    case SNMP_MSG_GETBULK:
    case SNMP_MSG_TRAP2:
    case SNMP_MSG_INFORM:	/* Only valid in (potential) V2c PDUs */
	if (SNMP_VERSION_2c == pdu->version) {
	    return -1;
	}
	break;

    case SNMP_MSG_REPORT:	/* Only possibly valid in 'open' PDUs */
    default:
	if (!((SNMP_VERSION_ANY     == pdu->version)  ||
	      (SNMP_DEFAULT_VERSION == pdu->version))) {
	    return -1;
	}
	break;
    }

	/*
	 *  If this is a V1-style PDU, then
	 *    check the varbind list (if any)
	 *    for v2-style values
	 */
    if ((SNMP_VERSION_1 == pdu->version ) &&
        (NULL != pdu->varbind_list )) {
        for (vb = pdu->varbind_list;  NULL != vb; vb = vb->next ) {
	    if ( vb->value ) {
	        switch (vb->value->type) {
	        case ASN_COUNTER64:
			/* XXX - Convert to ASN_OPAQUE_U64 ? */
	        case SNMP_NOSUCHOBJECT:
	        case SNMP_NOSUCHINSTANCE:
	        case SNMP_ENDOFMIBVIEW:
		    return -1;
		}
	    }
	}
    }
    return 0;
}


