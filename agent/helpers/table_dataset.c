#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "table.h"
#include "table_data.h"
#include "table_dataset.h"

typedef struct data_set_cache_s {
   void *data;
   size_t data_len;
} data_set_cache;

table_data_set *
create_table_data_set(table_data *table) 
{
    table_data_set *table_set = SNMP_MALLOC_TYPEDEF(table_data_set);
    table_set->table = table;
    return table_set;
}

mib_handler *
get_table_data_set_handler(table_data_set *data_set)
{
    mib_handler *ret = NULL;

    if (!data_set) {
        snmp_log(LOG_INFO, "get_table_data_set_handler(NULL) called\n");
        return NULL;
    }
    
    ret = create_handler(TABLE_DATA_SET_NAME, table_data_set_helper_handler);
    if (ret) {
        ret->myvoid = (void *) data_set;
    }
    return ret;
}


int
register_table_data_set(handler_registration *reginfo, table_data_set *data_set,
                        table_registration_info *table_info)
{
    inject_handler(reginfo, get_table_data_set_handler(data_set));
    return register_table_data(reginfo, data_set->table, table_info);
}

table_data_set_storage *
table_data_set_find_column(table_data_set_storage *start, int column) 
{
    while(start && start->column != column)
        start = start->next;
    return start;
}

/**
 * marks a given column in a row as writable or not
 */
int
mark_row_column_writable(table_row *row, int column, int writable) 
{
    table_data_set_storage *data = (table_data_set_storage *) row->data;
    data = table_data_set_find_column(data, column);

    if (!data) {
        /* create it */
        data = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
        if (!data) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        data->column = column;
        data->writable = writable;
        data->next = row->data;
        row->data = data;
    } else {
        data->writable = writable;
    }
}


/**
 * sets a given column in a row with data given a type, value, and
 * length.  Data is memdup'ed by the function.
 */
int
set_row_column(table_row *row, unsigned int column, int type,
               const char *value, size_t value_len) 
{
    table_data_set_storage *data = (table_data_set_storage *) row->data;
    data = table_data_set_find_column(data, column);

    if (!data) {
        /* create it */
        data = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
        if (!data) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        
        data->column = column;
        data->type = type;
        data->next = row->data;
        row->data = data;
    }
    
    if (data) {
        if (data->type != type)
            return SNMPERR_GENERR;
        
        SNMP_FREE(data->data);
        if (memdup(&data->data, value, value_len) != SNMPERR_SUCCESS) {
            snmp_log(LOG_CRIT, "no memory in set_row_column");
            return SNMPERR_MALLOC;
        }
        data->data_len = value_len;
    }
    return SNMPERR_SUCCESS;
}

/**
 * adds a new default row to a table_set.
 * returns SNMPERR_SUCCESS or SNMPERR_FAILURE
 */
int
table_set_add_default_row(table_data_set *table_set, unsigned int column,
                          int type, int writable) 
{
    
    table_data_set_storage *new_col;

    /* double check */
    new_col = table_data_set_find_column(table_set->default_row, column);
    if (new_col != NULL) {
        if (new_col->type == type &&
            new_col->writable == writable)
            return SNMPERR_SUCCESS;
        return SNMPERR_GENERR;
    }

    new_col = SNMP_MALLOC_TYPEDEF(table_data_set_storage);
    new_col->type = type;
    new_col->writable = writable;
    new_col->column = column;
    new_col->next = table_set->default_row;
    table_set->default_row = new_col;
    return SNMPERR_SUCCESS;
}

int
table_data_set_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    table_data_set_storage *data = NULL;
    table_row *row;
    table_request_info *table_info;
    data_set_cache *cache;

    for(; requests; requests = requests->next) {
        if (requests->processed)
            continue;

        /* extract our stored data and table info */
        row = extract_table_row(requests);
        table_info = extract_table_info(requests);

        if (row)
            data = (table_data_set_storage *) row->data;
        if (!row || !table_info || !data)
            continue;

        data = table_data_set_find_column(data, table_info->colnum);
        
        switch(reqinfo->mode) {
            case MODE_GET:
            case MODE_GETNEXT:
            case MODE_GETBULK: /* XXXWWW */
                if (data)
                    table_data_build_result(reginfo, reqinfo, requests, row,
                                            table_info->colnum,
                                            data->type,
                                            data->data, data->data_len);
                break;

            case MODE_SET_RESERVE1:
                if (data) {
                    /* modify existing */
                    if (!data->writable) {
                        set_request_error(reqinfo, requests,
                                          SNMP_ERR_NOTWRITABLE);
                    } else if (requests->requestvb->type != data->type) {
                        set_request_error(reqinfo, requests,
                                          SNMP_ERR_WRONGTYPE);
                    }
                } else {
                    /* create data, possibly new row */
                }
                break;

            case MODE_SET_RESERVE2:
                if (data) {
                    /* cache old data for later undo */
                    cache = SNMP_MALLOC_TYPEDEF(data_set_cache);
                    if (!cache) {
                        set_request_error(reqinfo, requests,
                                          SNMP_ERR_RESOURCEUNAVAILABLE);
                    } else {
                        cache->data = data->data;
                        cache->data_len = data->data_len;
                        request_add_list_data(requests, create_data_list(TABLE_DATA_SET_NAME, cache, free));
                    }
                } else {
                    /* XXXWWW */
                }
                break;

            case MODE_SET_ACTION:
                if (data) {
                    memdup(&data->data, requests->requestvb->val.string,
                           requests->requestvb->val_len);
                    data->data_len = requests->requestvb->val_len;
                } else {
                    /* XXXWWW */
                }
                break;
                
            case MODE_SET_UNDO:
                SNMP_FREE(data->data);
                
                cache = (data_set_cache *)
                    request_get_list_data(requests, TABLE_DATA_SET_NAME);
                data->data = cache->data;
                data->data_len = cache->data_len;
                /* the cache itself is automatically freed by the
                   data_list routines */
                break;

            case MODE_SET_COMMIT:
                cache = (data_set_cache *)
                    request_get_list_data(requests, TABLE_DATA_SET_NAME);
                SNMP_FREE(cache->data);
                break;

            case MODE_SET_FREE:
                /* nothing to do */
                break;
        }
    }

    if (handler->next && handler->next->access_method)
        call_next_handler(handler, reginfo, reqinfo, requests);
    return SNMP_ERR_NOERROR;
}
