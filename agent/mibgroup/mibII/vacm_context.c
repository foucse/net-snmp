#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "vacm_context.h"
#include "snmp_agent.h"

#include "snmp_api.h"
#include "snmp_client.h"
#include "helpers/table.h"

static oid vacm_context_oid[] = {1,3,6,1,6,3,16,1,1};

#define CONTEXTNAME_COLUMN 1

void
init_vacm_context(void) {
    /*
     * table vacm_context
     */
    handler_registration *my_handler;
    table_registration_info *table_info;

    my_handler = create_handler_registration("vacm_context",
                                          vacm_context_handler,
                                          vacm_context_oid,
                                          sizeof(vacm_context_oid)/sizeof(oid));
    
    if (!my_handler)
        return;

    table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);

    if (!table_info)
        return;

    table_helper_add_index(table_info, ASN_OCTET_STR)
    table_info->min_column = 1;
    table_info->max_column = 1;
    register_table(my_handler, table_info);
}

/*
 * returns a list of known context names
 */

int
vacm_context_handler(mib_handler               *handler,
                     handler_registration      *reginfo,
                     agent_request_info        *reqinfo,
                     request_info              *requests) {

    table_registration_info
        *handler_reg_info = (table_registration_info *) handler->prev->myvoid;
    table_request_info *table_info;
    u_long result;
    size_t result_len;
    int x, y;
    const char *index_string;
    int index_string_len;
    int best_candidate_len;
    subtree_context_cache *context_ptr;
    
    while(requests) {
        struct variable_list *var = requests->requestvb;

        if (requests->processed != 0)
            continue;

        table_info = (table_request_info *) requests->parent_data;
        if (table_info==NULL) {
            requests = requests->next;
            continue;
        }

        switch(reqinfo->mode) {
            case MODE_GETNEXT:
                /* beyond our search range? */
                if (table_info->colnum > CONTEXTNAME_COLUMN)
                    break;

                /* below our minimum column? */
                if (table_info->colnum < CONTEXTNAME_COLUMN ||
                    /* or no index specified */
                    table_info->indexes->val.string == 0) {
                    table_info->colnum = CONTEXTNAME_COLUMN;
                    index_string = "";
                } else {
                    index_string = table_info->indexes->val.string;
                }
                index_string_len = strlen(index_string);

                for(context_ptr = get_top_context_cache();
                    context_ptr;
                    context_ptr = context_ptr->next) {
                    /* find something just greater than our current index */
                    oid result[MAX_OID_LEN];
                    struct variable_list *var = NULL;
                    snmp_varlist_add_variable(&var, NULL, 0, ASN_OCTET_STR,
                                              context_ptr->context_name,
                                              strlen(context_ptr->context_name));
                    build_oid_noalloc(result, MAX_OID_LEN, &result_len,
                                      NULL, 0, var);
/*                     if (snmp_oid_compare(table_info->indexes->name, */
/*                                          table_info->indexes->name_length, */
/*                                          result->name, result->name_length) > 0) { */
/*                         if (best_candidate */
/*                     int name_len = strlen(context_ptr->context_name); */
/*                     if (name_len >= index_string_len && */
/*                         strncmp(index_string, context_ptr->context_name, */
/*                                 index_string_len) < 0 */
/*                         (!best_candidate || */
/*                          (name_len >=  */

/* strcmp(context_ptr->context_name */

/*                     *(table_info->indexes->val.integer) = x; */
/*                     *(table_info->indexes->next_variable->val.integer) = y; */
/*                     table_build_result(reginfo, requests, */
/*                                        table_info, ASN_INTEGER, */
/*                                        (u_char *) &result, */
/*                                        sizeof(result)); */
                }
                
                break;
                
            case MODE_GET:
                if (var->type == ASN_NULL) { /* valid request if ASN_NULL */
                    /* is it the right column? */
                    if (table_info->colnum == CONTEXTNAME_COLUMN) {
                        if (find_first_subtree(table_info->indexes->val.string)) {
                            if (table_info->indexes->val.string)
                                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                                         table_info->indexes->val.string,
                                                         strlen(table_info->indexes->val.string));
                            else
                                snmp_set_var_typed_value(var, ASN_OCTET_STR,
                                                         "", 0);
                            
                        }
                    }
                }
                break;

        }

        requests = requests->next;
    }

    return SNMP_ERR_NOERROR;
}
