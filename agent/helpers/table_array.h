/* table_array.h */
#ifndef _TABLE_ARRAY_HANDLER_H_
#define _TABLE_ARRAY_HANDLER_H_

#ifdef __cplusplus
extern "C" {
#endif

/* The table array helper is designed to simplify the task of
   writing a table handler for the net-snmp agent when the data being
   accessed is in an oid sorted form and must be accessed externally.

   Functionally, it is a specialized version of the more
   generic table helper but easies the burden of GETNEXT processing by
   retrieving the appropriate row for ead index through
   function calls which should be supplied by the module that wishes
   help.  The module the table_array helps should, afterwards,
   never be called for the case of "MODE_GETNEXT" and only for the GET
   and SET related modes instead.
 */

#define TABLE_ARRAY_NAME "table_array"

    /*
     * structure for holding important info for each table.
     */
typedef struct table_array_data_s {
    table_registration_info * tblreg_info;
    oid_array                 array;
} table_array_data;


mib_handler *get_table_array_handler(table_registration_info *tabreq);
int register_table_array(handler_registration *reginfo,
                            table_registration_info *tabreq);

oid_array *extract_array_context(request_info *);

NodeHandler table_array_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ARRAY_HANDLER_H_ */
