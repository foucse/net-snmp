#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "testhandler.h"
#include "snmp_agent.h"

#include "snmp_api.h"
#include "helpers/table.h"
#include "helpers/instance.h"

static oid my_test_oid[4] = {1,2,3,4};
static oid my_table_oid[4] = {1,2,3,5};
static oid my_instance_oid[5] = {1,2,3,6,1};

void
init_testhandler(void) {
    /* we're registering at .1.2.3.4 */
    handler_registration *my_test;
    table_registration_info *table_info;

    DEBUGMSGTL(("testhandler", "initializing\n"));

    /*
     * basic handler test
     */
    my_test = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!my_test)
        return;

    my_test->handler = create_handler("myTest", my_test_handler);
    my_test->rootoid = my_test_oid;
    my_test->rootoid_len = 4;

    register_handler(my_test);

    /*
     * instance handler test
     */
    my_test = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!my_test)
        return;

    my_test->rootoid = my_instance_oid;
    my_test->rootoid_len = 5;
    my_test->handler = create_handler("myInstance", my_test_instance_handler);

    register_instance(my_test);

    /*
     * table helper test
     */

    my_test = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!my_test)
        return;

    my_test->rootoid = my_table_oid;
    my_test->rootoid_len = sizeof(my_table_oid)/sizeof(oid);
    my_test->handler = create_handler("myTable", my_test_table_handler);

    table_info = SNMP_MALLOC_TYPEDEF(table_registration_info);
    table_info->indexes = SNMP_MALLOC_STRUCT(variable_list);
    table_info->indexes->type = ASN_INTEGER;
    table_info->indexes->next_variable = SNMP_MALLOC_STRUCT(variable_list);
    table_info->indexes->next_variable->type = ASN_INTEGER;
    table_info->min_column = 3;
    table_info->max_column = 3;
    register_table(my_test, table_info);
}

int
my_test_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    oid myoid1[] = {1,2,3,4,5,6};
    static u_long accesses = 0;

    DEBUGMSGTL(("testhandler", "Got request:\n"));
    /* loop through requests */
    while(requests) {
        struct variable_list *var = requests->requestvb;

        DEBUGMSGTL(("testhandler", "  oid:"));
        DEBUGMSGOID(("testhandler", var->name,
                     var->name_length));
        DEBUGMSG(("testhandler", "\n"));

        switch(reqinfo->mode) {
            case MODE_GET:
                if (snmp_oid_compare(var->name, var->name_length, myoid1, 6)
                    == 0) {
                    snmp_set_var_typed_value(var, ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                    return SNMP_ERR_NOERROR;
                }
                break;

            case MODE_GETNEXT:
                if (snmp_oid_compare(var->name, var->name_length, myoid1, 6)
                    < 0) {
                    snmp_set_var_objid(var, myoid1, 6);
                    snmp_set_var_typed_value(var, ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                    return SNMP_ERR_NOERROR;
                }
                break;
                
            default:
                return SNMPERR_GENERR;
        }

        requests = requests->next;
    }
    return SNMP_ERR_NOERROR;
}

/*
 * functionally this is a simply a multiplication table for 12x12
 */

#define MAX_COLONE 12
#define MAX_COLTWO 12
#define RESULT_COLUMN 3
int
my_test_table_handler(mib_handler               *handler,
                      handler_registration      *reginfo,
                      agent_request_info        *reqinfo,
                      request_info              *requests) {

    table_registration_info   *handler_reg_info = (table_registration_info *) handler->prev->myvoid;
    table_request_info *table_info;
    u_long result;
    int x, y;
    
    
    while(requests) {
        struct variable_list *var = requests->requestvb;

        DEBUGMSGTL(("testhandler_table", "Got request:\n"));
        DEBUGMSGTL(("testhandler_table", "  oid:"));
        DEBUGMSGOID(("testhandler_table", var->name, var->name_length));
        DEBUGMSG(("testhandler_table", "\n"));

        table_info = (table_request_info *) requests->parent_data;
		if (table_info==NULL) {
		  requests = requests->next;
		  continue;
		}

        switch(reqinfo->mode) {
            case MODE_GETNEXT:
                /* beyond our search range? */
                if (table_info->colnum > RESULT_COLUMN)
                    break;

                /* below our minimum column? */
                if (table_info->colnum < RESULT_COLUMN ||
                    /* or no index specified */
                    table_info->indexes->val.integer == 0) {
                    table_info->colnum = RESULT_COLUMN;
                    x = 0;
                    y = 0;
                } else {
                    x = *(table_info->indexes->val.integer);
                    y = *(table_info->indexes->next_variable->val.integer);
                }

				if (table_info->number_indexes == handler_reg_info->number_indexes) {
                y++; /* GETNEXT is basically just y+1 for this table */
                if (y > MAX_COLTWO) { /* (with wrapping) */
                    y = 0;
                    x++;
                }
				}
                if (x <= MAX_COLONE) {
                    result = x * y;

                    *(table_info->indexes->val.integer) = x;
                    *(table_info->indexes->next_variable->val.integer) = y;
                    table_build_result(reginfo, requests,
                                       table_info, ASN_INTEGER,
                                       (u_char *) &result,
                                       sizeof(result));
                }
                
                break;
                
            case MODE_GET:
                if (var->type == ASN_NULL) { /* valid request if ASN_NULL */
                    /* is it the right column? */
                    if (table_info->colnum == RESULT_COLUMN &&
                        /* and within the max boundries? */
                        *(table_info->indexes->val.integer) <= MAX_COLONE &&
                        *(table_info->indexes->next_variable->val.integer)
                        <= MAX_COLTWO) {

                        /* then, the result is column1 * column2 */
                        result = *(table_info->indexes->val.integer) *
                            *(table_info->indexes->next_variable->val.integer);
                        snmp_set_var_typed_value(var, ASN_INTEGER,
                                                 (u_char *) &result,
                                                 sizeof(result));
                    }
                }
                break;

        }

        requests = requests->next;
    }

    return SNMP_ERR_NOERROR;
}

int
my_test_instance_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    static u_long accesses = 0;

    DEBUGMSGTL(("testhandler", "Got request:\n"));

    snmp_set_var_typed_value(requests->requestvb, ASN_INTEGER,
                             (u_char *) &accesses,
                             sizeof(accesses));
    accesses++;
    return SNMP_ERR_NOERROR;
}
