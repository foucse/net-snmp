int asn_check_packet (u_char *pkt, size_t len);
u_char * asn_parse_int(u_char *data,
              size_t *datalength,
              u_char *type,
              long *intp,
              size_t intsize);
u_char * asn_parse_unsigned_int(u_char *data,
                       size_t *datalength,
                       u_char *type,
                       u_long *intp,
                       size_t intsize);
u_char * asn_parse_string(u_char *data,
                 size_t *datalength,
                 u_char *type,
                 u_char *string,
                 size_t *strlength);
u_char * asn_parse_header(u_char *data,
                 size_t *datalength,
                 u_char *type);
u_char * asn_parse_sequence(u_char *data,
                 size_t *datalength,
                 u_char *type,
                 u_char expected_type,
                 const char *estr);
u_char * asn_parse_length(u_char  *data,
                 u_long  *length);
u_char * asn_parse_objid(u_char *data,
                size_t *datalength,
                u_char *type,
                oid *objid,
                size_t *objidlength);
u_char * asn_parse_null(u_char *data,
               size_t *datalength,
               u_char *type);
u_char * asn_parse_bitstring(u_char *data,
                    size_t *datalength,
                    u_char *type,
                    u_char *string,
                    size_t *strlength);
u_char * asn_parse_unsigned_int64(u_char *data,
                         size_t *datalength,
                         u_char *type,
                         struct counter64 *cp,
                         size_t countersize);
u_char * asn_parse_signed_int64(u_char *data,
                       size_t *datalength,
                       u_char *type,
                       struct counter64 *cp,
                       size_t countersize);
u_char *asn_parse_float(u_char *data,
                size_t *datalength,
                u_char *type,
                float *floatp,
                size_t floatsize);
u_char *asn_parse_double(u_char *data,
                 size_t *datalength,
                 u_char *type,
                 double *doublep,
                 size_t doublesize);

