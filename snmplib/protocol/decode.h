#ifndef _PROTOCOL_DECODE_H
#define _PROTOCOL_DECODE_H

netsnmp_value *  decode_value(           netsnmp_buf *buf);
netsnmp_varbind* decode_varbind(         netsnmp_buf *buf);
netsnmp_varbind* decode_vblist(          netsnmp_buf *buf);
netsnmp_pdu*     decode_basic_pdu(       netsnmp_buf *buf, netsnmp_pdu *p);
netsnmp_buf *    decode_sequence(        netsnmp_buf *buf);
long             decode_length(          netsnmp_buf *buf);
u_int            decode_subid(           netsnmp_buf *buf);
long*            decode_integer(         netsnmp_buf *buf, long *int_val);
u_long*          decode_unsigned_integer(netsnmp_buf *buf, u_long *int_val);
int64*           decode_int64(           netsnmp_buf *buf, int64 *int_val);
int64*           decode_unsigned_int64(  netsnmp_buf *buf, int64 *int_val);
int*             decode_null(            netsnmp_buf *buf);
netsnmp_buf*     decode_string(          netsnmp_buf *buf, netsnmp_buf *str_val);
netsnmp_oid*     decode_oid(             netsnmp_buf *buf, netsnmp_oid *oid_val);
float*           decode_float(           netsnmp_buf *buf, float *float_val);
double*          decode_double(          netsnmp_buf *buf, double *double_val);

#endif /* _PROTOCOL_DECODE_H */

