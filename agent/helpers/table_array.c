/* table_iterator.c */

#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <assert.h>

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "table.h"
#include "oid_array.h"
#include "table_array.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif


oid_array *
extract_array_context(request_info *request) 
{
    return request_get_list_data(request, TABLE_ARRAY_NAME);
}

mib_handler *
get_table_array_handler(table_registration_info *tabreg) {
    /*
     * create a handler
     */
    mib_handler *me=
        create_handler(TABLE_ARRAY_NAME, table_array_helper_handler);

    /*
     * keep track of table registration info; create an oid_array
     * for this table.
     */
    table_array_data * tad = SNMP_MALLOC_TYPEDEF(table_array_data);
    tad->tblreg_info = tabreg; /* we need it too, but it really is not ours */
    tad->array = Initialise_oid_array( sizeof(void*) );
    me->myvoid = tad;

    return me;
}

    
int
register_table_array(handler_registration *reginfo,
                        table_registration_info *tabreg) {
    inject_handler(reginfo, get_table_array_handler(tabreg));
    return register_table(reginfo, tabreg);
}

/*
 * Section 3
 *
 * table_array_helper_handler()
 */
int
table_array_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {
  
    request_info * current;
    /*
     * 3.1 Setup
     *
     * First off, get our pointer from the handler. This
     * lets us get to the table registration information we
     * saved in get_table_array_handler(), as well as the
     * oid_array where the actual table data is stored.
     *
     * We also save the request mode. For GETNEXT and GETBULK
     * processing, we temporarily change the mode of the
     * request so that the next handler only has to worry
     * about GET and SET cases.
     */
    int rc = SNMP_ERR_NOERROR;
    table_array_data * tad = (table_array_data*)handler->myvoid;
    int mode_save = reqinfo->mode;

    DEBUGMSGTL(("helper:table_array", "Mode %d, Got request:\n",
                reqinfo->mode));

    /*
     * 3.2 Iteration
     *
     * Next we are going to loop through each of the requests, and
     * try to find the appropriate row from the oid_array.
     */
    for( current = requests; current; current = current->next) {

        /* 3.2.1 Setup and paranoia
         *
         * Get pointer to the table information for this request. This
         * information was saved by table_helper_handler. When
         * debugging, we double check a few assumptions. For example,
         * the table_helper_handler should enforce column boundaries.
         */
        oid_header *row = NULL;
        oid_header index;
        oid coloid[MAX_OID_LEN];
        int coloid_len;        
        table_request_info *tblreq_info = extract_table_info(current);
        struct variable_list * var = current->requestvb;
        assert(tblreq_info->colnum <= tad->tblreg_info->max_column);
        
        DEBUGMSGTL(("helper:table_array", "  oid:"));
        DEBUGMSGOID(("helper:table_array", var->name, var->name_length));
        DEBUGMSG(("helper:table_array", "\n"));

        /*
         * skip anything that doesn't need processing.
         */
        if (current->processed != 0)
            continue;

        switch(reqinfo->mode) {
        case MODE_GETNEXT:
        case MODE_GETBULK:
            /*
             * below our minimum column?
             */
            if (tblreq_info->colnum < tad->tblreg_info->min_column) {
                row = Get_oid_data( tad->array, NULL, 0 );
            }
            else {
                index.idx = tblreq_info->index_oid;
                index.idx_len = tblreq_info->index_oid_len;
                row = Get_oid_data( tad->array, &index, 0 );
                /*
                 * we don't have a row, but we might be at the end of a
                 * column, so try the next one.
                 */
                if (!row) {
                    ++tblreq_info->colnum;
                    if(tad->tblreg_info->valid_columns) {
                        tblreq_info->colnum = closest_column
                            (tblreq_info->colnum,
                             tad->tblreg_info->valid_columns);
                    }
                    else if(tblreq_info->colnum > tad->tblreg_info->max_column)
                        tblreq_info->colnum = 0;

                    if(tblreq_info->colnum != 0)
                        row = Get_oid_data( tad->array, NULL, 0 );
                }
            }

            if (!row) {
                /*
                 * no results found.
                 *
                 * xxx-rks: so, how do we skip this entry for the next
                 * handler, but still allow it a chance to hit
                 * another handler?
                 */
                continue;
            }
        
			/*
             * if data was found, make sure it has the column we want
             */
#warning "xxx-rks: add suport for sparse tables"

            /*
             * build new oid
             */
            coloid_len = reginfo->rootoid_len+2;
            memcpy(coloid, reginfo->rootoid,
                   reginfo->rootoid_len * sizeof(oid));
            /** table.entry */
            coloid[reginfo->rootoid_len] = 1;
            /** table.entry.column */
            coloid[reginfo->rootoid_len+1] = tblreq_info->colnum;
            /** table.entry.column.index */
            memcpy(&coloid[reginfo->rootoid_len+2], row->idx,
                   row->idx_len * sizeof(oid));
            snmp_set_var_objid(current->requestvb, coloid,
                               reginfo->rootoid_len + 1 + row->idx_len);

            /*
             * fudge the mode for our client.
             */
            reqinfo->mode = MODE_GET;
            break;
            
            
        default: /** GET, SET, all the same...  exact search */
            index.idx = tblreq_info->index_oid;
            index.idx_len = tblreq_info->index_oid_len;
            row = Get_oid_data( tad->array, &index, 1 );
            if((!row) && ! MODE_IS_SET(reqinfo->mode)) {
                set_request_error(reqinfo, current, SNMP_ERR_NOSUCHNAME);
                current->processed = 1;
                continue;
            }
            break;

        } /** switch(mode) */

        /*
         * save row.
         */
        request_add_list_data(current,
                              create_data_list(TABLE_ARRAY_NAME, row, NULL));
        
    } /** for( current ... ) */


    /*
     * 3.3 Recursion
     *
     * Now we should have row pointers for each request. Call the
     * next handler to process the row.
     */
    rc = call_next_handler(handler, reginfo, reqinfo, requests);

    /*
     * 3.4 Cleanup
     *
     * As noted in 3.1, we may have changed the mode. Here we restore
     * the mode to the saved value.
     */
    reqinfo->mode = mode_save;

    return rc;
}
