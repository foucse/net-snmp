/*******************************
 *
 *      protocol/encode.c
 *
 *      Net-SNMP library - Version-independent SNMP interface
 *
 *      Version-independent ASN.1-encoding routines
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
#include <net-snmp/utils.h>
#include <net-snmp/types.h>



int encode_length(netsnmp_buf *buf, int length);
int encode_asn1_header(netsnmp_buf *buf, u_char type, int length);
int encode_sequence(netsnmp_buf *buf, int length);

int encode_integer(netsnmp_buf *buf, u_char type, long val);
int encode_unsigned_integer(netsnmp_buf *buf, u_char type, u_long val);
int encode_unsigned_int64(netsnmp_buf *buf, u_char type, int64 *i64_val);
int encode_int64(netsnmp_buf *buf, u_char type, int64 *i64_val);
int encode_null(netsnmp_buf *buf, u_char type, void *dummy);
int encode_string(netsnmp_buf *buf, u_char type, u_char *string, int len);
int encode_oid(netsnmp_buf *buf, netsnmp_oid *oid);
int encode_float(netsnmp_buf *buf, float f_val);
int encode_double(netsnmp_buf *buf, double d_val);


#define ASN_EXTENSION_ID	(0x1F)
#define ASN_OPAQUE_TAG1		(ASN_CONTEXT | ASN_EXTENSION_ID)
#define ASN_OPAQUE_TAG2		(0x30)

#define ASN_OPAQUE_FLOAT	(ASN_OPAQUE_TAG2 | ASN_FLOAT )
#define ASN_OPAQUE_DOUBLE	(ASN_OPAQUE_TAG2 | ASN_DOUBLE )
#define ASN_OPAQUE_I64		(ASN_OPAQUE_TAG2 | ASN_INTEGER64 )
#define ASN_OPAQUE_U64		(ASN_OPAQUE_TAG2 | ASN_UNSIGNED64 )


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/protocol_api.h>)
                 *
                 **************************************/
                /** @package protocol_api */


                /**************************************
                 *
                 *      Internal API
                 *
                 **************************************/
                /** @package protocol_internals */


   /**
    *
    *  Encode a value into the specified (expandable) buffer
    *  Return 0 on success, -ve on failure.
    *
    */
int
encode_value(netsnmp_buf *buf, netsnmp_value *value)
{
    if ((NULL == buf) || (NULL == value)) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    switch(value->type) {
    case ASN_BOOLEAN:
    case ASN_INTEGER:
	__B( encode_integer(buf, value->type, *(value->val.integer)))
	break;

    case ASN_COUNTER:
    case ASN_GAUGE:
    case ASN_TIMETICKS:
    case ASN_UINTEGER:
	__B( encode_unsigned_integer(buf, value->type, (u_int)*(value->val.integer)))
	break;

    case ASN_COUNTER64:
	__B( encode_unsigned_int64(buf, value->type, value->val.integer64))
	break;

    case ASN_OPAQUE_U64:
    case ASN_UNSIGNED64:
	__B( encode_unsigned_int64(buf, ASN_OPAQUE_U64, value->val.integer64))
	break;

    case ASN_OPAQUE_I64:
    case ASN_INTEGER64:
	__B( encode_int64(buf, ASN_OPAQUE_I64, value->val.integer64))
	break;

    case ASN_OCTET_STR:
    case ASN_IPADDRESS:
    case ASN_OPAQUE:
    case ASN_NSAP:
    case ASN_BIT_STR:
	__B( encode_string(buf, value->type, value->val.string, value->len))
	break;

    case ASN_NULL:
    case SNMP_NOSUCHOBJECT:
    case SNMP_NOSUCHINSTANCE:
    case SNMP_ENDOFMIBVIEW:
	__B( encode_null(buf, value->type, NULL))
	break;

    case ASN_OBJECT_ID:
	__B( encode_oid(buf, value->val.oid))
	break;

    case ASN_OPAQUE_FLOAT:
    case ASN_FLOAT:
	__B( encode_float(buf, *(value->val.floatVal)))
	break;

    case ASN_OPAQUE_DOUBLE:
    case ASN_DOUBLE:
	__B( encode_double(buf, *(value->val.doubleVal)))
	break;

    default:
	/* Print error */
	return -1;
    }   
    return 0;
}


   /**
    *
    *  Encode a Varbind into the specified (expandable) buffer
    *  Return 0 on success, -ve on failure.
    *
    */
int
encode_varbind(netsnmp_buf *buf, netsnmp_varbind *vb)
{
    int start_len;

    if ((NULL == buf) || (NULL == vb)) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    start_len= buf->cur_len;	/* Remember the length before we start */

    __B( encode_value(buf, vb->value))
    __B( encode_oid(  buf, vb->oid))
    __B( encode_sequence(buf, (buf->cur_len - start_len)))
    return 0;
}


   /**
    *
    *  Encode a Varbind list into the specified (expandable) buffer
    *  Return 0 on success, -ve on failure.
    *
    */
int
encode_vblist(netsnmp_buf *buf, netsnmp_varbind *vblist)
{
    netsnmp_varbind *vb;
    int start_len;

    if (NULL == buf) {
	return -1;
    }
    if (NULL == vblist ) {
	return 0;	/* Nothing to do */
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    start_len= buf->cur_len;	/* Remember the length before we start */

	/* Find the end of the varbind list */
    for (vb = vblist;  NULL != vb->next;  vb = vb->next ) {
	;
    }

	/*
	 * Work backwards through the list,
	 *  encoding each varbind in turn.
         * Then add the SEQUENCE header for the list.
	 */
    for ( ; NULL != vb; vb = vb->prev ) {
	__B( encode_varbind(buf, vb))
    }
    __B( encode_sequence(buf, (buf->cur_len - start_len)))

    return 0;
}


   /**
    *
    *  Encode a PDU into the specified (expandable) buffer
    *  Return 0 on success, -ve on failure.
    *
    */
int
encode_basic_pdu(netsnmp_buf *buf, netsnmp_pdu *pdu)
{
    int start_len;

    if ((NULL == buf) || (NULL == pdu )) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    start_len= buf->cur_len;	/* Remember the length before we start */

	/*
	 * Encode the varbind list (working backwards)
	 */
    if ( pdu->varbind_list ) {
	__B( encode_vblist( buf, pdu->varbind_list ))
    }

	/*
	 * Now add the standard 'header' fields, again in reverse order,
	 *  followed by the SEQUENCE header for the PDU as a whole
	 */
    __B( encode_integer( buf, ASN_INTEGER, pdu->errindex  ))
    __B( encode_integer( buf, ASN_INTEGER, pdu->errstatus ))
    __B( encode_integer( buf, ASN_INTEGER, pdu->request   ))
    __B( encode_asn1_header( buf, pdu->command, (buf->cur_len - start_len)))
    return 0;
}


                /*******************
                 *
                 *      ASN.1 'utility' encoding
                 *
                 *******************/


int
encode_length(netsnmp_buf *buf, int length)
{
    int start_len;
    int length_len;

    if (NULL == buf) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    start_len= buf->cur_len;	/* Remember the length before we start */

	/*
	 * Short lengths (<127) can be encoded
	 *  in a single byte.
	 */
    if (0x7f > length) {
	return buffer_append_char(buf, (u_char)length&0xff);
    }    

	/*
	 * Longer lengths use the first byte to encode the
	 *  "length of the length" - i.e. the number of octets
	 *  that should be interpreted as the length value.
	 *
	 * So encode the length itself (working backwards)...
	 */
    while (0xff < length) {
	__B( buffer_append_char(buf, (u_char)length&0xff))
	length >>= 8;
    }
    __B( buffer_append_char(buf, (u_char)length&0xff))

	/*
	 * ... followed by the "length of the length"
	 * Note that the top bit is set to indicate
	 *   this "long form" encoding.
	 */
    length_len = buf->cur_len - start_len;
    __B( encode_sequence(buf, length_len | 0x80 ))
    return 0;
}


int
encode_asn1_header(netsnmp_buf *buf, u_char type, int length)
{
    if (NULL == buf) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    __B( encode_length( buf, length ))
    __B( buffer_append_char( buf, type ))
    return 0;
}


int
encode_sequence(netsnmp_buf *buf, int length)
{
    if (NULL == buf) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    return encode_asn1_header( buf, ASN_SEQUENCE|ASN_CONSTRUCTOR, length );
}


int
encode_opaque_wrapper(netsnmp_buf *buf, int start_len )
{
    if (NULL == buf) {
	return -1;
    }
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE)) {
	return -1;	/* XXX - or set the flag ? */
    }

    __B( buffer_append_char(buf, ASN_OPAQUE_TAG1))
    __B( encode_asn1_header(buf, ASN_OPAQUE, (buf->cur_len - start_len)))
    return 0;
}


int
encode_subid(netsnmp_buf *buf, int subid)
{
    __B( buffer_append_char(buf, (u_char)(subid & 0x7f)))
    subid >>= 7;

    while (0 < subid) {
        __B( buffer_append_char(buf, (u_char)(0x80 | (subid & 0x7f))))
        subid >>= 7;
    }
    return 0;
}


                /*******************
                 *
                 *      ASN.1 types encoding
                 *
                 *******************/


int
encode_integer(netsnmp_buf *buf, u_char type, long val)
{
    int start_len;
    int stop_val;
    int offset;
    char *cp;

    if (NULL == buf) {
	return -1;
    }
    start_len= buf->cur_len;	/* Remember the length before we start */

	/*
	 * What will repeatedly right-shifting this value
	 *    eventually result in?
	 */
    if (0 > val ) {
	stop_val = -1;
    } else {
	stop_val =  0;
    }

    do {
        __B( buffer_append_char(buf, (u_char)val&0xff))
        val >>= 8;
    } while (stop_val != val);

	/*
	 * Check that the top-most bit of the encoding is appropriate
	 *  for this value (set implies negative, clear implies positive).
	 * If it isn't, add another octet (0xff or 0x00 respectively)
	 *  which doesn't change the numeric value,
	 *  but ensures this will be correctly interpreted.
	 */
    offset = buf->max_len - buf->cur_len;
    cp = buf->string + offset;
    if ((stop_val & 0x80) != (*cp & 0x80)) {
        __B( buffer_append_char(buf, (u_char)stop_val&0xff))
    }

    __B( encode_asn1_header(buf, type, (buf->cur_len - start_len)))
    return 0;
}


int
encode_unsigned_integer(netsnmp_buf *buf, u_char type, u_long val)
{
    int start_len;
    int stop_val;
    int offset;
    char *cp;

    if (NULL == buf) {
	return -1;
    }
    start_len = buf->cur_len;      /* Remember the length before we start */
    stop_val  = 0;		   /* Repeated right-shift results in 0 */

    do {
        __B( buffer_append_char(buf, (u_char)val&0xff))
        val >>= 8;
    } while (stop_val != val);

	/*
	 * Check that the top-most bit of the encoding is appropriate
	 *  for this value (i.e. 0, since it's positive)
	 * If it isn't, add another octet (0x00)
	 *  which doesn't change the numeric value,
	 *  but ensures this will be correctly interpreted.
	 */
    offset = buf->max_len - buf->cur_len;
    cp = buf->string + offset;
    if ((stop_val & 0x80) != (*cp & 0x80)) {
        __B( buffer_append_char(buf, (u_char)stop_val&0xff))
    }

    __B( encode_asn1_header(buf, type, (buf->cur_len - start_len)))
    return 0;
}


int
encode_int64(netsnmp_buf *buf, u_char type, int64 *i64_val)
{
    int start_len;
    int stop_val;
    int offset, i;
    char *cp;
    u_long high, low;

    if ((NULL == buf) || (NULL == i64_val)) {
	return -1;
    }
    high = i64_val->high;
    low  = i64_val->low;
    start_len = buf->cur_len;      /* Remember the length before we start */
	/*
	 * What will repeatedly right-shifting this value
	 *    eventually result in?
	 */
    if (0 > high ) {
	stop_val = -1;
    } else {
	stop_val =  0;
    }


	/*
	 * If the value being encoded is within the range
	 *   of a 32-bit signed integer, then the basic
	 *   encoding is the same as the Integer32 case
	 *   (apart from the 'type' tag)
	 * So use that routine to encode it.
	 */
    if (stop_val == high) {
	__B(encode_integer(buf, type, low))
    }
    else {
	    /*
	     * Otherwise, encode the four bytes of the lower half,
	     *   followed by the minimum necessary representation
	     *   of the upper half, just as for the 32-bit case.
	     */
	for (i = 4;  0 < i;  i--) {
	    __B(buffer_append_char(buf, (u_char)low&0xff))
	    low >>= 8;
	}
	do {
	    __B( buffer_append_char(buf, (u_char)high&0xff))
	    high >>= 8;
	 } while (stop_val != high );

	    /* check the top bit (as before) */
         offset = buf->max_len - buf->cur_len;
         cp = buf->string + offset;
         if ((stop_val & 0x80) != (*cp & 0x80)) {
             __B( buffer_append_char(buf, (u_char)stop_val&0xff))
         }

         __B( encode_asn1_header(buf, type, (buf->cur_len - start_len)))
    }

	/*
	 * If this is an 'Opaque-wrapped' type, apply the wrapping
	 * Note that this needs to know the overall length of the
	 *   wrapped data, so give it the original starting length.
	 */
    if (ASN_OPAQUE_I64 == type) {
	__B( encode_opaque_wrapper( buf, start_len ))
    }

    return 0;
}


int
encode_unsigned_int64(netsnmp_buf *buf, u_char type, int64 *i64_val)
{
    int start_len;
    int stop_val;
    int offset, i;
    char *cp;
    long high, low;

    if ((NULL == buf) || (NULL == i64_val)) {
	return -1;
    }
    start_len = buf->cur_len;      /* Remember the length before we start */
    stop_val  = 0;		   /* Repeated right-shift results in 0 */
    high = i64_val->high;
    low  = i64_val->low;

	/*
	 * If the value being encoded is within the range
	 *   of a 32-bit unsigned integer, then the basic
	 *   encoding is the same as the UInteger32 case
	 *   (apart from the 'type' tag)
	 * So use that routine to encode it.
	 */
    if (0 == high) {
	__B(encode_unsigned_integer(buf, type, low))
    }
    else {
	    /*
	     * Otherwise, encode the four bytes of the lower half,
	     *   followed by the minimum necessary representation
	     *   of the upper half, just as for the 32-bit case.
	     */
	for (i = 4;  0 < i;  i--) {
	    __B(buffer_append_char(buf, (u_char)low&0xff))
	    low >>= 8;
	}
	do {
	    __B( buffer_append_char(buf, (u_char)high&0xff))
	    high >>= 8;
	 } while (stop_val != high );

	    /* check the top bit (as before) */
         offset = buf->max_len - buf->cur_len;
         cp = buf->string + offset;
         if ((stop_val & 0x80) != (*cp & 0x80)) {
             __B( buffer_append_char(buf, (u_char)stop_val&0xff))
         }

         __B( encode_asn1_header(buf, type, (buf->cur_len - start_len)))
    }

	/*
	 * If this is an 'Opaque-wrapped' type, apply the wrapping
	 * Note that this needs to know the overall length of the
	 *   wrapped data, so give it the original starting length.
	 */
    if (ASN_OPAQUE_U64 == type) {
	__B( encode_opaque_wrapper( buf, start_len ))
    }

    return 0;
}


int
encode_null(netsnmp_buf *buf, u_char type, void *dummy)
{
	/* ASN.1 NULL = 0x05 0x00 */
    return encode_asn1_header( buf, type, 0 );
}


int
encode_string(netsnmp_buf *buf, u_char type, u_char *string, int len)
{
	/* ASN.1 OCTET STRING = 0x04 len byte {byte}* */
	/* ASN.1 BIT STRING   = 0x03 len byte {byte}* */
    __B( buffer_append(buf, string, len))
    return encode_asn1_header( buf, type, len );
}


int
encode_oid(netsnmp_buf *buf, netsnmp_oid *oid)
{
    int start_len, i, n;

    if ((NULL == buf) || (NULL == oid)) {
	return -1;
    }
    start_len = buf->cur_len;   /* Remember the length before we start */

	/*
	 * Check for invalid values in the first two subidentifiers
	 */
    if (((1 <= oid->len) && ( 2 < oid->name[0])) ||
        ((2 <= oid->len) && (40 < oid->name[1]))) {
	return -1;
    }

	/*
	 * There should really be at least 2 subidentifiers in an OID.
	 * Fudge short OIDs by turning an empty OID into '.0.0'
	 *   and '.N' (N=0,1,2) into '.N.0'
	 */
    if (0 == oid->len) {
	__B(buffer_append_char(buf, 0))
    } else if (1 == oid->len) {
	__B(buffer_append_char(buf, (u_char)oid->name[0]*40))
    }
    else {
	    /*
	     * Otherwise work backwards, encoding the other subidentifiers,
	     *  ending up with the first two (combined into one octet).
	     */
	for (i = oid->len; 2<i; i--) {
	    __B(encode_subid(buf, oid->name[i-1]))
	}
	n = oid->name[0]*40 + oid->name[1];
	__B(buffer_append_char(buf, (u_char)n))
    }

    __B( encode_asn1_header(buf, ASN_OBJECT_ID, (buf->cur_len - start_len)))
    return 0;
}


int
encode_float(netsnmp_buf *buf, float f_val)
{
    int start_len;
    union {
	float    floatVal;
	int      intVal;
	u_char   c[sizeof(float)];
    } fu;
    
    if (NULL == buf) {
	return -1;
    }
    start_len = buf->cur_len;      /* Remember the length before we start */

	/*
	 * Correct for endian differences,
	 *   copy the data into the encoded PDU,
	 *   and add the type tag and opaque wrapper
	 */
    fu.floatVal = f_val;
    fu.intVal   = htonl(fu.intVal);
    __B(buffer_append(buf, fu.c, sizeof(float)))
    __B(encode_asn1_header(buf, ASN_OPAQUE_FLOAT, (buf->cur_len - start_len)))
    __B( encode_opaque_wrapper( buf, start_len ))
    return 0;
}


int
encode_double(netsnmp_buf *buf, double d_val)
{
    int start_len;
    long tmp;
    union {
	double   doubleVal;
	int      intVal[2];
	u_char   c[sizeof(double)];
    } du;
    
    if (NULL == buf) {
	return -1;
    }
    start_len = buf->cur_len;      /* Remember the length before we start */

	/*
	 * Correct for endian differences,
	 *   copy the data into the encoded PDU,
	 *   and add the type tag and opaque wrapper
	 */
    du.doubleVal = d_val;
    if ( 0x01 != htonl(0x01)) {
        tmp          = htonl(du.intVal[0]);
        du.intVal[0] = htonl(du.intVal[1]);
        du.intVal[1] = tmp;
    }
    __B(buffer_append(buf, du.c, sizeof(double)))
    __B(encode_asn1_header(buf, ASN_OPAQUE_DOUBLE, (buf->cur_len - start_len)))
    __B( encode_opaque_wrapper( buf, start_len ))
    return 0;
}


                /**************************************
                 *
                 *      Temporary - hijacked from snmp_api.c
                 *
                 **************************************/



#include <ucd/ucd_api.h>
#include <ucd/ucd_convert.h>

int
snmp_pdu_realloc_rbuild(u_char **pkt, size_t *pkt_len, size_t *offset,
                        struct snmp_pdu *pdu)
{
    netsnmp_pdu *p;
    netsnmp_buf *buf;

    p = ucd_convert_pdu( pdu );
    if (NULL == p) {
	return 0;	/* Error */
    }
    memset( *pkt, 0, *pkt_len );	/* clear the buffer! */
    buf = buffer_new( *pkt, *pkt_len,
			NETSNMP_BUFFER_RESIZE|NETSNMP_BUFFER_REVERSE );


    if (0 > encode_basic_pdu( buf, p )) {
	return 0;
    }

/*
    *pkt = buffer_string(buf);
    *pkt_len = buf->cur_len;
 */

    *pkt     = buf->string;	/* I think this is right? */
    *pkt_len = buf->max_len;
    *offset  = buf->cur_len;
    buf->flags |= NETSNMP_BUFFER_NOFREE;

    pdu_free( p );
    buffer_free( buf );
    return 1;
}



