/*
 * util_funcs.c
 * $Id$
 *
 * see comments in header file.
 *
 */

#include <config.h>

#if HAVE_IO_H
#include <io.h>
#endif
#include <stdio.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_MALLOC_H
#include <malloc.h>
#endif

#include "oid_array.h"
#include "snmp_api.h"

typedef struct oid_array_table_s {
    int             max_size;   /* Size of the current data table */
    int             count;      /* Index of the next free entry */
    int             dirty;
    int             data_size;  /* Size of an individual entry */
    void           *data;       /* The table itself */
} oid_array_table;

#define TABLE_ADD( x, y )	((oid_header*)((char*)(x) + y))
#define TABLE_INDEX(t, i)	(TABLE_ADD(t->data, i * t->data_size))
#define TABLE_START(t)		(TABLE_INDEX(t, 0))
#define TABLE_NEXT(t)		(TABLE_INDEX(t, t->count))

int
array_compare(const void *lhs, const void *rhs)
{
    return snmp_oid_compare(((const oid_header *) lhs)->idx,
                            ((const oid_header *) lhs)->idx_len,
                            ((const oid_header *) rhs)->idx,
                            ((const oid_header *) rhs)->idx_len);
}

static int
Sort_Array(oid_array_table * table)
{
    if (table->dirty) {
        /*
         * Sort the table 
         */
        qsort(TABLE_START(table), table->count, table->data_size,
              array_compare);
        table->dirty = 0;
    }

    return 1;
}

static int
binary_search(oid_header * val, oid_array_table * t, int exact)
{
    int             len = t->count;
    int             half;
    int             middle;
    int             first = 0;

    if (t->dirty)
        Sort_Array(t);

    while (len > 0) {
        half = len >> 1;
        middle = first;
        middle += half;
        if (array_compare(TABLE_INDEX(t, middle), val)) {
            first = middle;
            ++first;
            len = len - half - 1;
        } else
            len = half;
    }

    if (exact) {
        if (first != t->count
            && !array_compare(TABLE_INDEX(t, first), val))
            return first;
        else
            return -1;
    }

    return first;
}

oid_array
Initialise_oid_array(int size)
{
    oid_array_table *t;

    t = (oid_array_table *) malloc(sizeof(oid_array_table));
    if (t == NULL)
        return NULL;

    t->max_size = 0;
    t->count = 0;
    t->dirty = 0;
    t->data_size = size;
    t->data = NULL;

    return (oid_array) t;
}

void           *
get_oid_data(oid_array t, void *key, int exact)
{
    oid_array_table *table = (oid_array_table *) t;
    int             index;

    if (table->dirty)
        Sort_Array(t);

    index = binary_search(key, table, exact);

    if (exact && index == -1)
        return 0;

    return TABLE_INDEX(table, index);
}

int
Add_Entry(oid_array t, void *entry)
{
    oid_array_table *table = (oid_array_table *) t;
    int             new_max;
    void           *new_data;   /* Used for * a) extending the data table
                                 * * b) the next entry to use */

    if (table->max_size <= table->count) {
        /*
         * Table is full, so extend it to double the size
         */
        new_max = 2 * table->max_size;
        if (new_max == 0)
            new_max = 10;       /* Start with 10 entries */

        new_data = (void *) malloc(new_max * table->data_size);
        if (new_data == NULL)
            return -1;

        if (table->data) {
            memcpy(new_data, table->data,
                   table->max_size * table->data_size);
            free(table->data);
        }
        table->data = new_data;
        table->max_size = new_max;
    }

    /*
     * Insert the new entry into the data array
     */
    new_data = TABLE_NEXT(table);
    memcpy(new_data, entry, table->data_size);
    table->count++;
    table->dirty = 1;
    return 0;
}

void           *
Retrieve_Table_Data(oid_array t, int *max_idx)
{
    oid_array_table *table = (oid_array_table *) t;

    if (table->dirty)
        Sort_Array(t);

    *max_idx = table->count;
    return table->data;
}
