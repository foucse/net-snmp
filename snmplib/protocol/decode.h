#ifndef _PROTOCOL_DECODE_H
#define _PROTOCOL_DECODE_H

#include <net-snmp/utils.h>
#include <net-snmp/types.h>


netsnmp_buf* decode_asn1_header(netsnmp_buf *buf, u_char *header_val);
netsnmp_buf* decode_sequence(netsnmp_buf *buf);
long         decode_length(  netsnmp_buf *buf);
u_int        decode_subid(   netsnmp_buf *buf);

long*        decode_integer(         netsnmp_buf *buf, long *int_val);
u_long*      decode_unsigned_integer(netsnmp_buf *buf, u_long *int_val);
int64*       decode_int64(           netsnmp_buf *buf, int64 *int_val);
int64*       decode_unsigned_int64(  netsnmp_buf *buf, int64 *int_val);
int*         decode_null(            netsnmp_buf *buf);
netsnmp_buf* decode_string(          netsnmp_buf *buf, netsnmp_buf *str_val);
netsnmp_oid* decode_oid(             netsnmp_buf *buf, netsnmp_oid *oid_val);
float*       decode_float(           netsnmp_buf *buf, float *float_val);
double*      decode_double(          netsnmp_buf *buf, double *double_val);

#define ASN_EXTENSION_ID	(0x1F)
#define ASN_OPAQUE_TAG1		(ASN_CONTEXT | ASN_EXTENSION_ID)
#define ASN_OPAQUE_TAG2		(0x30)

#define ASN_OPAQUE_FLOAT	(ASN_OPAQUE_TAG2 | ASN_FLOAT )
#define ASN_OPAQUE_DOUBLE	(ASN_OPAQUE_TAG2 | ASN_DOUBLE )
#define ASN_OPAQUE_I64		(ASN_OPAQUE_TAG2 | ASN_INTEGER64 )

#endif /* _PROTOCOL_DECODE_H */
