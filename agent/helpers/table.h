/* testhandler.h */

#ifdef __cplusplus
extern "C" {
#endif

/* The table helper is designed to simplify the task of writing a
 * table handler for the net-snmp agent.  You should create a normal
 * handler and register it using the register_table() function instead
 * of the register_handler() function.
 */

/*
 * Notes:
 *
 *   1) illegal indexes automatically get handled for get/set cases.
 *      Simply check to make sure the value is type ASN_NULL before
 *      you answer a request.
 */

/*
 * column info struct.  OVERLAPPING RANGES ARE NOT SUPPORTED.
 */
typedef struct column_info_t {
  char isRange;
  char list_count; /* only useful if isRange == 0 */

  union {
	unsigned int range[2];
	unsigned int *list;
  } details;

  struct column_info_t *next;

} column_info;

typedef struct _table_registration_info {
   struct variable_list *indexes; /* list of varbinds with only 'type' set */
   unsigned int number_indexes;   /* calculated automatically */

  /* the minimum and maximum columns numbers. If there are columns
   * in-between which are not valid, use valid_columns to get
   * automatic column range checking.
   */
   unsigned int min_column;
   unsigned int max_column;

   column_info *valid_columns;    /* more details on columns */

   /* get_first_index *() */
  /* unsigned int auto_getnext; */
} table_registration_info;

typedef struct _table_request_info {
   unsigned int colnum;            /* 0 if OID not long enough */
   unsigned int number_indexes;    /* 0 if failure to parse any */
   struct variable_list *indexes; /* contents freed by helper upon exit */
  oid original_index_oid[MAX_OID_LEN];
  size_t original_index_oid_len;
  oid full_index_oid[MAX_OID_LEN];
  size_t full_index_oid_len;
} table_request_info;

mib_handler *get_table_handler(table_registration_info *tabreq);
int register_table(handler_registration *reginfo,
                   table_registration_info *tabreq);
int table_build_oid(handler_registration *reginfo,
					request_info *reqinfo,
					table_request_info *table_info);
int table_build_result(handler_registration *reginfo,
                       request_info *reqinfo,
                       table_request_info *table_info, u_char type,
                       u_char *result, size_t result_len);

NodeHandler table_helper_handler;

#ifdef __cplusplus
};
#endif


