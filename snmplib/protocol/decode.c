/*******************************
 *
 *      protocol/decode.c
 *
 *      Net-SNMP library - Version-independent SNMP interface
 *
 *      Version-independent ASN.1-decoding routines
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

#include <netinet/in.h>

#include <net-snmp/var_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/protocol_api.h>
#include <net-snmp/utils.h>
#include <net-snmp/types.h>

#include "protocol/decode.h"



#define ASN_EXTENSION_ID	(0x1F)
#define ASN_OPAQUE_TAG1		(ASN_CONTEXT | ASN_EXTENSION_ID)
#define ASN_OPAQUE_TAG2		(0x30)

#define ASN_OPAQUE_FLOAT	(ASN_OPAQUE_TAG2 | ASN_FLOAT )
#define ASN_OPAQUE_DOUBLE	(ASN_OPAQUE_TAG2 | ASN_DOUBLE )
#define ASN_OPAQUE_I64		(ASN_OPAQUE_TAG2 | ASN_INTEGER64 )
#define ASN_OPAQUE_U64		(ASN_OPAQUE_TAG2 | ASN_UNSIGNED64 )

#define MAX_OID_LEN	128

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/protocol_api.h>)
                 *
                 **************************************/
                /** @package protocol_api */


netsnmp_value *
decode_value(netsnmp_buf *buf)
{
    netsnmp_value *val;
    netsnmp_buf   *str;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    val = var_create_value(*(buf->string));
    if (NULL == val) {
        return NULL;
    }
    val->val.string = val->valbuf;

    switch (val->type) {
    case ASN_INTEGER:
        if (NULL == decode_integer(buf, val->val.integer)) {
            var_free_value(val);
            return NULL;
        }
        break;
    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
        if (NULL == decode_unsigned_integer(buf, (u_long *)val->val.integer)) {
            var_free_value(val);
            return NULL;
        }
        break;
    case ASN_COUNTER64:
        if (NULL == decode_unsigned_int64(buf, val->val.integer64)) {
            var_free_value(val);
            return NULL;
        }
        break;
    case ASN_OCTET_STR:
    case ASN_BIT_STR:
    case ASN_IPADDRESS:
    case ASN_NSAP:
        str = decode_string(buf, NULL);
        if (NULL == str) {
            buffer_free(str);
            var_free_value(val);
            return NULL;
        }
	val->val.string = str->string;
        val->len        = str->cur_len;
        free(str);
        break;
    case ASN_OBJECT_ID:
        val->val.oid = decode_oid(buf, NULL);
        if (NULL == val->val.oid) {
            var_free_value(val);
            return NULL;
        }
        break;
    case ASN_NULL:
    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
        if (NULL == decode_null(buf)) {
            var_free_value(val);
            return NULL;
        }
        break;
    case ASN_OPAQUE:
		/* XXX - To Do */
        break;
    }
    return val;
}


netsnmp_varbind*
decode_varbind(netsnmp_buf *buf)
{
    netsnmp_buf     *seq = NULL;
    netsnmp_oid     *oid = NULL;
    netsnmp_value   *val = NULL;
    netsnmp_varbind *vb  = NULL;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    seq = decode_sequence(buf);
    if (NULL == seq) {
        return NULL;
    }
    oid = decode_oid(seq, NULL);
    val = decode_value(seq);

    if ((NULL != oid) &&
        (NULL != val) &&
        (0 == seq->cur_len)) {
        vb = var_create_set_varbind(oid, val);
    }

    oid_free(oid);
/*  var_free_value(val);		XXX - crashes out! */
    buffer_free(seq);
    return vb;
}


netsnmp_varbind*
decode_vblist(netsnmp_buf *buf)
{
    netsnmp_buf     *seq  = NULL;
    netsnmp_varbind *head = NULL;
    netsnmp_varbind *vb;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    seq = decode_sequence(buf);
    if (NULL == seq) {
        return NULL;
    }
    while (0 < seq->cur_len) {
        vb = decode_varbind(seq);

        if (NULL == vb) {
            vblist_free(head);
            buffer_free(seq);
            return NULL;
        }

        if (NULL == head) {
            head = vb;
        } else {
            if (0 > vblist_add_varbind(head, vb)) {
                vblist_free(head);
                buffer_free(seq);
                return NULL;
            }
        }
    }

    if (0 != seq->cur_len) {
        vblist_free(head);
        buffer_free(seq);
        return NULL;
    }

    buffer_free(seq);
    return head;
}


netsnmp_pdu*
decode_basic_pdu(netsnmp_buf *buf, netsnmp_pdu *p)
{
    netsnmp_buf *seq  = NULL;
    netsnmp_pdu *pdu = NULL;
    u_char command;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    seq = decode_asn1_header(buf, &command);
    if (NULL == seq) {
        return NULL;
    }

    if (NULL != p) {
        pdu = p;
        pdu->command = command;
    } else {
        pdu = pdu_create(SNMP_VERSION_ANY, command);
        if (NULL == pdu) {
            buffer_free(seq);
            return NULL;
        }
    }

    if (NULL == decode_integer(seq, &(pdu->request))) {
        buffer_free(seq);
        if (NULL == p) {
            pdu_free(pdu);
        }
        return NULL;
    }
    if (NULL == decode_integer(seq, &(pdu->errstatus))) {
        buffer_free(seq);
        if (NULL == p) {
            pdu_free(pdu);
        }
        return NULL;
    }
    if (NULL == decode_integer(seq, &(pdu->errindex))) {
        buffer_free(seq);
        if (NULL == p) {
            pdu_free(pdu);
        }
        return NULL;
    }

/*
    if ((NULL == decode_integer(seq, &(pdu->request)))   ||
        (NULL == decode_integer(seq, &(pdu->errstatus))) ||
        (NULL == decode_integer(seq, &(pdu->errindex)))) {
        buffer_free(seq);
        if (NULL == p) {
            pdu_free(pdu);
        }
        return NULL;
    }
 */

    if (NULL != pdu->varbind_list) {
        vblist_free(pdu->varbind_list);
    }
    pdu->varbind_list = decode_vblist(seq);
    if ((NULL == pdu->varbind_list) ||
        (0 != seq->cur_len)) {
        buffer_free(seq);
        if (NULL == p) {
            pdu_free(pdu);
        }
        return NULL;
    }

    buffer_free(seq);
    return pdu;
}


                /**************************************
                 *
                 *      Internal API
                 *
                 **************************************/
                /** @package protocol_internals */

                /*******************
                 *
                 *      ASN.1 'utility' decoding
                 *
                 *******************/

    /*
     * Begin to decode an ASN.1 sequence from the
     *   given input buffer, updating this input buffer to
     *   point to the data following the sequence.
     *
     * Returns a second buffer structure containing the
     *   (encoded) contents of the sequence (or NULL on failure),
     *   together with an indication of the 'type' of this sequence.
     *
     * It is the responsibility of the calling procedure to
     *   free this structure when it is no longer needed.
     */
netsnmp_buf *
decode_asn1_header(netsnmp_buf *buf, u_char *header_val)
{
    netsnmp_buf *seq_buf;
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    /*
     * Decode the sequence header
     */
    *header_val = *(buf->string);
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }
    if (buf->cur_len < length) {
        return NULL;	/* Not enough data left */
    }

    /*
     * Create a "dummy" buffer for the sequence data.
     * We'll set up the string pointer and the size
     *   ourselves, so use arbitrary values here.
     *
     * Note that the string data is shared with the input
     *   buffer, so shouldn't be freed when the structure is.
     */
    seq_buf = buffer_new(NULL, 0, NETSNMP_BUFFER_NOFREE);
    if (NULL == seq_buf) {
        return NULL;
    }
    seq_buf->cur_len = length;
    seq_buf->string  = buf->string;

    /*
     * We've sort-of-finished decoding this sequence
     *  (at least as far as the input buffer is concerned)
     *  so update the string pointer to skip past this data.
     * The sequence itself can be handled via the new buffer structure.
     */
    buf->string  += length;
    buf->cur_len -= length;

    return seq_buf;
}


    /*
     * Decode an ASN.1 SEQUENCE structure from the
     *   given input buffer, updating this input buffer to
     *   point to the data following the sequence.
     *
     * Returns a second buffer structure containing the
     *   (encoded) contents of the sequence (or NULL on failure),
     *   together with an indication of the 'type' of this sequence.
     *
     * It is the responsibility of the calling procedure to
     *   free this structure when it is no longer needed.
     */
netsnmp_buf *
decode_sequence(netsnmp_buf *buf)
{
    netsnmp_buf *seq;
    u_char type;

    seq = decode_asn1_header(buf, &type);
    if (NULL != seq) {
        if ((ASN_SEQUENCE|ASN_CONSTRUCTOR) != type) {
            buffer_free(seq);
            return NULL;		/* Wrong type */
        }
    }
    return seq;
}


    /*
     *  Decode a length tag from the given input buffer,
     *   updating this to point to the start of the data.
     *
     *  Returns this length, or -1 on failure
     */
long
decode_length(netsnmp_buf *buf)
{
    u_char length_byte;
    long   length;
    u_char ch;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return -1;
    }

    length_byte = *(buf->string);
    buf->string++;
    buf->cur_len--;

    /*
     * If the top bit is set, then this first byte holds
     *  the "length of the length", followed by the length itself.
     */
    if (0x80 & length_byte) {
        length_byte &= 0x7f;	/* Clear the top bit */
        buf->cur_len -= length_byte;
        if (0 > buf->cur_len) {
            return -1;		/* Not enough data left for the length */ 
        }

        length = 0;
        if (0 == length_byte) {
            return -1;		/* Indefinite length not supported */
        }
        if (sizeof(long) < length_byte) {
            return -1;		/* Too long a length */
        }

        /*
         * Build up the actual length from the following data.
         */
        while (0 < length_byte--) {
            ch = *(buf->string++);
            length = (length << 8) + ch;
        }
    }
    /*
     * Otherwise, this first byte holds the length directly.
     *  So we can just use it.
     */
    else {
        length = length_byte;
    }

    if (length > buf->cur_len) {
        return -1;		/* Not this much data left in the buffer */
    }
    return length;
}

u_int
decode_subid(netsnmp_buf *buf)
{
    u_int subid = 0;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return -1;
    }

    /*
     * Object Sub-identifiers are encoded using seven bits
     *  per octet, with the highest bit indicating whether
     *  the subidentifier is complete or not.
     */
    while (*(buf->string) & 0x80) {
        subid = (subid << 7) + (*(buf->string) & 0x7f);
        buf->string++;
        buf->cur_len--;
        if (0 == buf->cur_len) {
            return -1;		/* Except that this returns unsigned :-(  */
        }
    }

    /*
     * Top bit clear indicates the last octet of the subidentifier
     */

    subid = (subid << 7) + (*(buf->string) & 0x7f);
    buf->string++;
    buf->cur_len--;

    return subid;
}


                /*******************
                 *
                 *      ASN.1 types decoding
                 *
                 *******************/

    /*
     * Decode an ASN.1 INTEGER type from the given
     *  input buffer, updating this to point to the
     *  data following the integer value.
     *
     * Return a pointer to this value (optionally using
     *   memory provided by the caller), or NULL on failure.
     *
     * It is the responsibility of the calling procedure to
     *   free this memory when it is no longer needed.
     */
long*
decode_integer(netsnmp_buf *buf, long *int_val)
{
    long *value;
    register long  v;
    long length;
    u_char ch;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if (ASN_INTEGER != *(buf->string)) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }
    if (sizeof(long) < length) {
        return NULL;		/* Too long */
    }

    /*
     * If we've been given somewhere to store
     *   the new integer value, then use that.
     * Otherwise we need to allocate memory ourselves.
     */
    if (NULL == int_val) {
        value = (long *)calloc(1, sizeof(long));
        if (NULL == value) {
            return NULL;
        }
    } else {
        value = int_val;
    }

    /*
     * Now we're ready to actually decode the value.
     */
    if ((0 < length) && (0x80 & *(buf->string))) {
        v = -1;	/* Negative value, so sign-extend the buffer */
    } else {
        v =  0;	/* Clear the buffer */
    }

    buf->cur_len -= length;
    while (0 < length--) {
        ch = *(buf->string++);
        v = (v << 8 ) + ch;
    }

    *value = v;
    return value;
}


    /*
     * Decode an ASN.1 unsigned INTEGER type from the given
     *  input buffer, updating this to point to the
     *  data following the integer value.
     *
     * Return a pointer to this value (optionally using
     *   memory provided by the caller), or NULL on failure.
     *
     * It is the responsibility of the calling procedure to
     *   free this memory when it is no longer needed.
     */
u_long*
decode_unsigned_integer(netsnmp_buf *buf, u_long *int_val)
{
    u_long *value;
    long length;
    u_char ch;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if ((ASN_COUNTER   != *(buf->string)) &&
        (ASN_GAUGE     != *(buf->string)) &&
        (ASN_TIMETICKS != *(buf->string)) &&
        (ASN_UINTEGER  != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }
    if (sizeof(long) < length) {
        return NULL;		/* Too long */
    }

    /*
     * If we've been given somewhere to store
     *   the new integer value, then use that.
     * Otherwise we need to allocate memory ourselves.
     */
    if (NULL == int_val) {
        value = (u_long *)calloc(1, sizeof(long));
        if (NULL == value) {
            return NULL;
        }
    } else {
        value = int_val;
    }

    /*
     * Now we're ready to actually decode the value.
     */
    *value = 0;
    if ((0 < length) && (0x80 & *(buf->string))) {
        *value = ~(*value);	/* Negative value ??? */
    }

    buf->cur_len -= length;
    while (0 < length--) {
        ch = *(buf->string++);
        *value = (*value << 8 ) + ch;
    }

    return value;
}

int64*
decode_int64(netsnmp_buf *buf, int64 *int_val)
{
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if (ASN_OPAQUE_I64 != *(buf->string)) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }

	/* XXX - still to handle properly! */
    buf->string  += length;
    buf->cur_len -= length;
    return NULL;
}


int64*
decode_unsigned_int64(netsnmp_buf *buf, int64 *int_val)
{
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if ((ASN_COUNTER64  != *(buf->string)) &&
        (ASN_OPAQUE_U64 != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }

	/* XXX - still to handle properly! */
    buf->string  += length;
    buf->cur_len -= length;
    return NULL;
}


int*
decode_null(netsnmp_buf *buf)
{
    static int dummy_val;
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    if ((ASN_NULL            != *(buf->string)) &&
        (SNMP_NOSUCHOBJECT   != *(buf->string)) &&
        (SNMP_NOSUCHINSTANCE != *(buf->string)) &&
        (SNMP_ENDOFMIBVIEW   != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (0 != length) {
        return NULL;
    }

    return &dummy_val;		/* Non-NULL pointer */
}


netsnmp_buf*
decode_string(netsnmp_buf *buf, netsnmp_buf *str_val)
{
    netsnmp_buf *string;
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }

    if ((ASN_OCTET_STR != *(buf->string)) &&
        (ASN_BIT_STR   != *(buf->string)) &&
        (ASN_IPADDRESS != *(buf->string)) &&
        (ASN_NSAP      != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }

    /*
     * If we've been given somewhere to store
     *   the new OID value, then use that.
     * Otherwise we need to allocate memory ourselves.
     */
    if (NULL != str_val) {
        string = str_val;
    } else {
        string = buffer_new(NULL, length, 0);
    }

    buffer_set_string(string, buf->string, length);
    buf->cur_len -= length;
    buf->string  += length;
    return string;
}


netsnmp_oid*
decode_oid(netsnmp_buf *buf, netsnmp_oid *oid_val)
{
    netsnmp_oid *oid;
    u_int subids[MAX_OID_LEN];
    long length, oid_len, i;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if (ASN_OBJECT_ID != *(buf->string)) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }
    if (MAX_OID_LEN < length+1) {
        return NULL;		/* Too long */
    }

    /*
     * If we've been given somewhere to store
     *   the new OID value, then use that.
     * Otherwise we need to allocate memory ourselves.
     */
    if (NULL == oid_val) {
        oid = oid_create();
        if (NULL == oid) {
            return NULL;
        }
    } else {
        oid = oid_val;
    }

    if (0 == length) {
        oid_len   = 2;
        subids[0] = 0;        
        subids[1] = 0;        
    } else {
        oid_len = length+1;
        for (i = 1;  0 < length;  i++, length--) {
            subids[i] = decode_subid(buf);
        }
        /*
         * The first two subidentifiers are encoded as one,
         *  so expand them out.
         */
        subids[0] = subids[1]/40;        
        subids[1] = subids[1]%40;        
    }

    if (0 > oid_set_value(oid, subids, oid_len)) {
        if (NULL == oid_val) {
            oid_free(oid);
        }
        return NULL;
    }
    return oid;
}


float*
decode_float(netsnmp_buf *buf, float *float_val)
{
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if ((ASN_OPAQUE_FLOAT != *(buf->string)) &&
        (ASN_FLOAT        != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }

	/* XXX - still to handle properly! */
    buf->string  += length;
    buf->cur_len -= length;
    return NULL;
}
double*
decode_double(netsnmp_buf *buf, double *double_val)
{
    long length;

    if ((NULL == buf)          ||
        (NULL == buf->string)  ||
        (0    == buf->cur_len)) {
        return NULL;
    }
    if ((ASN_OPAQUE_DOUBLE != *(buf->string)) &&
        (ASN_DOUBLE        != *(buf->string))) {
        return NULL;		/* Wrong type */
    }
    buf->string++;
    buf->cur_len--;

    length = decode_length( buf );
    if (-1 == length) {
        return NULL;
    }

	/* XXX - still to handle properly! */
    buf->string  += length;
    buf->cur_len -= length;
    return NULL;
}
