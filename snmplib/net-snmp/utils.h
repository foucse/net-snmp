/*******************************
 *
 *      net-snmp/utils.h
 *
 *      Net-SNMP library - General utilities
 *
 *******************************/

#ifndef _NET_SNMP_UTILS_H
#define _NET_SNMP_UTILS_H

#include <stdio.h>
#include <net-snmp/struct.h>

        /* Buffer handling */

#define NETSNMP_BUFFER_RESIZE            0x1
#define NETSNMP_BUFFER_NOFREE            0x2
#define NETSNMP_BUFFER_NULLTERM          0x4
#define NETSNMP_BUFFER_REVERSE           0x8

typedef struct netsnmp_buf_s {
    char *string;
    int   cur_len;
    int   max_len;
    int   flags;
} netsnmp_buf;

netsnmp_buf* buffer_new( char *string, unsigned int len, unsigned int flags);
int          buffer_append(        netsnmp_buf *buf, char *string, int len  );
int          buffer_append_string( netsnmp_buf *buf, char *string           );
int          buffer_append_char(   netsnmp_buf *buf, char  ch               );
char*        buffer_string(        netsnmp_buf *buf                         );
void         buffer_free(          netsnmp_buf *buf                         );

        /*
         * The 'buffer_append' calls are frequently used within routines
         *   that similarly return a -ve value to indicate failure.
         * The following "convenience macro" can be used to propogate this
         *   error indication, without detracting from the code readability.
         */
#define __B( x )        if ( x < 0 ) { return -1; }

char* list_add_token(     char *list, char *token,  char sep );
char* list_remove_token(  char *list, char *token,  char sep );
char* list_remove_tokens( char *list, char *remove, char sep );

#endif /* _NET_SNMP_UTILS_H */
