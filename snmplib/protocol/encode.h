#ifndef _PROTOCOL_ENCODE_H
#define _PROTOCOL_ENCODE_H

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

#endif /* _PROTOCOL_ENCODE_H */
