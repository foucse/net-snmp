/* 
 * table_array.c
 * $Id$
 */

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

/*
 * structure for holding important info for each table.
 */
typedef struct table_array_data_s {
    table_registration_info * tblreg_info;
    oid_array                 array;
    
    int                       group_rows;

    UserGetProcessor          *get_value;

    UserSetProcessor          *set_reserve1;
    UserSetProcessor          *set_reserve2;
    UserSetProcessor          *set_action;
    UserSetProcessor          *set_commit;
    UserSetProcessor          *set_free;
    UserSetProcessor          *set_undo;

} table_array_data;

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * PUBLIC Registration functions                                      *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
mib_handler *
get_table_array_handler(table_registration_info *tabreg,
                        UserGetProcessor        *get_value,
                        UserSetProcessor        *set_reserve1,
                        UserSetProcessor        *set_reserve2,
                        UserSetProcessor        *set_action,
                        UserSetProcessor        *set_commit,
                        UserSetProcessor        *set_free,
                        UserSetProcessor        *set_undo,
                        int                     group_rows)
{
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
    tad->get_value = get_value;
    tad->set_reserve1 = set_reserve1;
    tad->set_reserve2 = set_reserve2;
    tad->set_action = set_action;
    tad->set_commit = set_commit;
    tad->set_free = set_free;
    tad->set_undo = set_undo;
    me->myvoid = tad;

    return me;
}

int
register_table_array(handler_registration *reginfo,
                     table_registration_info *tabreg,
                     UserGetProcessor        *get_value,
                     UserSetProcessor        *set_reserve1,
                     UserSetProcessor        *set_reserve2,
                     UserSetProcessor        *set_action,
                     UserSetProcessor        *set_commit,
                     UserSetProcessor        *set_free,
                     UserSetProcessor        *set_undo,
                     int                     group_rows)
{
    inject_handler(reginfo,
                   get_table_array_handler(tabreg, get_value, set_reserve1,
                                           set_reserve2, set_action,
                                           set_commit, set_free,
                                           set_undo, group_rows));
    return register_table(reginfo, tabreg);
}

oid_array *
extract_array_context(request_info *request) 
{
    return request_get_list_data(request, TABLE_ARRAY_NAME);
}

/**********************************************************************
 **********************************************************************
 **********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 * EVERYTHING BELOW THIS IS PRIVATE IMPLEMENTATION DETAILS.           *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************
 **********************************************************************
 **********************************************************************/


/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * Structures, Utility/convenience functions                          *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
/*
 * context info for SET requests
 */
typedef struct set_context_s {
    agent_request_info *agtreq_info;
    table_array_data   *tad;
    int                status;
} set_context;

static void
release_array_group( oid_array_header * g, void *v )
{
    array_group_item *tmp;
    array_group * group = (array_group*)g;

    while(group->list) {
        tmp = group->list;
        group->list = tmp->next;
        free(tmp);
    }

    free( group );
}

static void
release_array_groups( void * vp )
{
    oid_array a = (oid_array)vp;
    For_each_oid_data( a, release_array_group, NULL, 0 );
}

inline oid_array_header *
find_next_row( table_request_info *tblreq_info, table_array_data *tad)
{
    oid_array_header *row = NULL;
    oid_array_header index;

    /*
     * below our minimum column?
     */
    if (tblreq_info->colnum < tad->tblreg_info->min_column) {
        tblreq_info->colnum = tad->tblreg_info->min_column;
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

    return row;
}

inline void
build_new_oid( handler_registration *reginfo,
               table_request_info   *tblreq_info,
               oid_array_header     *row,
               request_info         *current )
{
    oid coloid[MAX_OID_LEN];
    int coloid_len;        

    coloid_len = reginfo->rootoid_len+2;
    memcpy(coloid, reginfo->rootoid, reginfo->rootoid_len * sizeof(oid));

    /** table.entry */
    coloid[reginfo->rootoid_len] = 1;

    /** table.entry.column */
    coloid[reginfo->rootoid_len+1] = tblreq_info->colnum;

    /** table.entry.column.index */
    memcpy(&coloid[reginfo->rootoid_len+2], row->idx,
           row->idx_len * sizeof(oid));

    snmp_set_var_objid(current->requestvb, coloid,
                       reginfo->rootoid_len + 1 + row->idx_len);
}

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * GET procession functions                                           *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
inline int
process_get_requests(handler_registration  *reginfo,
                     agent_request_info    *agtreq_info,
                     request_info          *requests,
                     table_array_data      *tad )
{
    int rc = SNMP_ERR_NOERROR;
    request_info * current;
    oid_array_header *row = NULL;

    /*
     * Loop through each of the requests, and
     * try to find the appropriate row from the oid_array.
     */
    for( current = requests; current; current = current->next) {

        /* 
         * Get pointer to the table information for this request. This
         * information was saved by table_helper_handler. When
         * debugging, we double check a few assumptions. For example,
         * the table_helper_handler should enforce column boundaries.
         */
        table_request_info *tblreq_info = extract_table_info(current);
        struct variable_list * var = current->requestvb;
        assert(tblreq_info->colnum <= tad->tblreg_info->max_column);
        
        DEBUGMSGTL(("helper:table_array:get", "  process_get_request oid:"));
        DEBUGMSGOID(("helper:table_array:get", var->name, var->name_length));
        DEBUGMSG(("helper:table_array:get", "\n"));

        /*
         * skip anything that doesn't need processing.
         */
        if (current->processed != 0) {
            DEBUGMSGTL(("helper:table_array:get", "already processed\n"));
            continue;
        }

        if((agtreq_info->mode == MODE_GETNEXT) ||
           (agtreq_info->mode == MODE_GETBULK)) {
            /*
             * find the row
             */
            row = find_next_row(tblreq_info, tad);
            if (!row) {
                /*
                 * no results found.
                 *
                 * xxx-rks: how do we skip this entry for the next handler,
                 * but still allow it a chance to hit another handler?
                 */
                DEBUGMSGTL(("helper:table_array:get", "no row found\n"));
                continue;
            }
        
			/*
             * if data was found, make sure it has the column we want
             */
#warning "xxx-rks: add suport for sparse tables"

            /*
             * build new oid
             */
            build_new_oid( reginfo, tblreq_info, row, current );

        } /** GETNEXT/GETBULK */
        else {
            oid_array_header index;
            index.idx = tblreq_info->index_oid;
            index.idx_len = tblreq_info->index_oid_len;

            row = Get_oid_data( tad->array, &index, 1 );
            if(!row) {
                DEBUGMSGTL(("helper:table_array:get", "no row found\n"));
                set_request_error(agtreq_info, current, SNMP_ERR_NOSUCHNAME);
                continue;
            }
        } /** GET */

        /*
         * get the data
         */
        tad->get_value( current, row, tblreq_info );

    } /** for ( ... requests ... ) */

    return rc;
}

/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * SET procession functions                                           *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
inline void
group_requests( agent_request_info *agtreq_info, request_info * requests,
                oid_array array_group_tbl, table_array_data *tad )
{
    table_request_info *tblreq_info;
    struct variable_list * var;
    oid_array_header *row, *tmp, index;
    request_info * current;
    array_group * g;
    array_group_item * i;

    for( current = requests; current; current = current->next) {
            
        /* 3.2.1 Setup and paranoia
         *
         * Get pointer to the table information for this request. This
         * information was saved by table_helper_handler. When
         * debugging, we double check a few assumptions. For example,
         * the table_helper_handler should enforce column boundaries.
         */
        row = NULL;
        var = current->requestvb;
        tblreq_info = extract_table_info(current);
        assert(tblreq_info->colnum <= tad->tblreg_info->max_column);
        
        DEBUGMSGTL(("helper:table_array:group", "  oid:"));
        DEBUGMSGOID(("helper:table_array:group", var->name, var->name_length));
        DEBUGMSG(("helper:table_array:group", "\n"));

        /*
         * skip anything that doesn't need processing.
         */
        if (current->processed != 0) {
            DEBUGMSGTL(("helper:table_array:group", "already processed\n"));
            continue;
        }

        /*
         * search for index
         */
        index.idx = tblreq_info->index_oid;
        index.idx_len = tblreq_info->index_oid_len;
        tmp = Get_oid_data( array_group_tbl, &index, 1);
        if(tmp) {
            g = (array_group*)tmp;
            i = SNMP_MALLOC_TYPEDEF(array_group_item);
            i->ri = current;
            i->tri = tblreq_info;
            i->next = g->list;
            g->list = i;
            continue;
        }

        /*
         * search for row
         */
        row = Get_oid_data( tad->array, &index, 1 );
        if(!row){
            set_request_error(agtreq_info, current, SNMP_ERR_NOSUCHNAME);
            continue;
        }

        g = SNMP_MALLOC_TYPEDEF(array_group);
        i = SNMP_MALLOC_TYPEDEF(array_group_item);
        g->row = row;
        g->list = i;
        i->ri = current;
        i->tri = tblreq_info;
        Add_oid_data( tad->array, g );

    } /** for( current ... ) */
}

void
process_set_group( oid_array_header* o, void *c )
{
#warning "should we continue processing after an error??"
    set_context * context = (set_context *)c;
    array_group * ag = (array_group *)o;

    if(context->status != SNMP_ERR_NOERROR)
        return;

    switch(context->agtreq_info->mode) {

    case MODE_SET_RESERVE1:
        context->status = context->tad->set_reserve1( ag );
        break;
        
    case MODE_SET_RESERVE2:
        context->status = context->tad->set_reserve2( ag );
        break;
        
    case MODE_SET_ACTION:
        context->status = context->tad->set_action( ag );
        break;
        
    case MODE_SET_COMMIT:
        context->status = context->tad->set_commit( ag );
        break;
        
    case MODE_SET_FREE:
        context->status = context->tad->set_free( ag );
        break;
        
    case MODE_SET_UNDO:
        /** status already set - don't change it now */
        context->tad->set_undo( ag );
        break;
        
    default:
        snmp_log(LOG_ERR, "unknown mode processing SET for "
                 "table_array_helper_handler\n");
        context->status = SNMP_ERR_GENERR;
        break;
    }

}

inline int
process_set_requests( agent_request_info *agtreq_info,
                      request_info       *requests,
                      table_array_data   *tad,
                      char               *handler_name)
{
    set_context context;
    oid_array array_group_tbl;

    DEBUGMSGTL(("helper:table_array", "Grouping requests by oid\n"));

    /*
     * create and save structure for set info
     */
    array_group_tbl = (oid_array)agent_get_list_data
        (agtreq_info, handler_name);
    if(array_group_tbl == NULL) {
        data_list *tmp;
        array_group_tbl = Initialise_oid_array( sizeof(void*) );
        tmp = create_data_list(handler_name,
                               array_group_tbl,
                               release_array_groups);
        agent_add_list_data(agtreq_info, tmp);
        /*
         * group requests.
         */
        group_requests( agtreq_info, requests, array_group_tbl, tad );
    }

    /*
     * process each group one at a time
     */
    context.agtreq_info = agtreq_info;
    context.tad = tad;
    context.status = SNMP_ERR_NOERROR;
    For_each_oid_data( array_group_tbl, process_set_group, &context, 0 );

    return context.status;
}


/**********************************************************************
 **********************************************************************
 *                                                                    *
 *                                                                    *
 * table_array_helper_handler()                                       *
 *                                                                    *
 *                                                                    *
 **********************************************************************
 **********************************************************************/
int
table_array_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *agtreq_info,
    request_info              *requests) {
  
    /*
     * First off, get our pointer from the handler. This
     * lets us get to the table registration information we
     * saved in get_table_array_handler(), as well as the
     * oid_array where the actual table data is stored.
     */
    int rc = SNMP_ERR_NOERROR;
    table_array_data * tad = (table_array_data*)handler->myvoid;

    DEBUGMSGTL(("helper:table_array", "Mode %d, Got request:\n",
                agtreq_info->mode));

    /*
     * 3.1.1
     *
     * This handler will be called 1 time for any type of GET
     * request, but will be called multiple times for SET
     * requests. We don't need to find each row for every
     * pass of the SET processing, so we'll cache results.
     */
    if(MODE_IS_SET(agtreq_info->mode))
        rc = process_set_requests( agtreq_info, requests,
                                   tad, handler->handler_name );
    else
        rc = process_get_requests( reginfo, agtreq_info, requests, tad );

    /*
     * Now we should have row pointers for each request. Call the
     * next handler to process the row.
     *
     * rc = call_next_handler(handler, reginfo, agtreq_info, requests);
     */

    return rc;
}
