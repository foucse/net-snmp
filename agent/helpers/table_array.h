/*
 * table_array.h
 * $Id$
 */
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
 * group_item is to allow us to keep a list of requests without
 * disrupting the actual request_info list.
 */
typedef struct array_group_item_s {
    request_info              *ri;
    table_request_info        *tri;
    struct array_group_item_s *next;
} array_group_item;

/*
 * structure to keep a list of requests for each unique index
 */
typedef struct array_group_s {
    oid_array_header   *row;
    array_group_item   *list;
} array_group;


typedef int (UserGetProcessor)(request_info *, oid_array_header *,
                               table_request_info *);
typedef int (UserSetProcessor)( array_group * );


mib_handler *
get_table_array_handler(table_registration_info *tabreq,
                        UserGetProcessor        *get_value,
                        UserSetProcessor        *set_reserve1,
                        UserSetProcessor        *set_reserve2,
                        UserSetProcessor        *set_action,
                        UserSetProcessor        *set_commit,
                        UserSetProcessor        *set_free,
                        UserSetProcessor        *set_undo,
                        int                     group_rows);

int register_table_array(handler_registration *reginfo,
                         table_registration_info *tabreq,
                         UserGetProcessor        *get_value,
                         UserSetProcessor        *set_reserve1,
                         UserSetProcessor        *set_reserve2,
                         UserSetProcessor        *set_action,
                         UserSetProcessor        *set_commit,
                         UserSetProcessor        *set_free,
                         UserSetProcessor        *set_undo,
                         int                     group_rows);

oid_array *extract_array_context(request_info *);

NodeHandler table_array_helper_handler;

#ifdef __cplusplus
};
#endif

#endif /* _TABLE_ARRAY_HANDLER_H_ */
