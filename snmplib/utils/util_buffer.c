/*******************************
 *
 *      util_buffer.c
 *
 *      Net-SNMP library - General utilities
 *
 *      General-purpose buffer handling
 *        (including bound checking, and dynamic re-allocation)
 *
 *******************************/

#include <config.h>

#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <sys/types.h>

#include <net-snmp/utils.h>

int _buffer_extend(netsnmp_buf * buf, int increase);

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/utils.h>)
                 *
                 **************************************/
                 /** @package utils */

        /**
         *
         * Creates a new buffer structure.
         *
         * If an string value is provided,
         *    this is used for the initial buffer contents.
         * Otherwise, memory is dynamically allocated.
         *
         * The flag parameter indicates whether this buffer can
         *    be re-sized if necessary..
         *
         * The calling routine should invoke 'buffer_free()'
         *      when this structure is no longer required.
         *
         */
netsnmp_buf*
buffer_new(char *string, unsigned int len, unsigned int flags)
{
    netsnmp_buf    *buf;

    buf = (netsnmp_buf *)calloc(1, sizeof(netsnmp_buf));
    if (NULL == buf) {
        return NULL;
    }
        /*
         * If we've been given a string, use that.
         * This is assumed to be of the length specified,
         *    and either empty or completely full
         *   (depending on the value of the first character).
         *
         * If a length hasn't been given, then assume this is
         *   C-style string, and calculate the length accordingly.
         */
    if (string) {
        buf->string = string;
        buf->max_len = (len ? len : strlen(string));
        buf->cur_len = (string[0] == '\0' ? 0 : buf->max_len);
    }
        /*
         * Otherwise, create a new (empty) buffer of the length requested
         */
    else if (len) {
        buf->string = (char *)calloc(len, 1);
        if (NULL == buf->string) {
            free(buf);
            return NULL;
        }
        buf->max_len = len;
        buf->cur_len = 0;
    }
        /*
         * If neither an initial string nor a length have been specified,
         *    then we have a new zero-length buffer, ready for extending
         *    as strings are added to it.
         * If the flag settings forbid re-sizing, then this is pretty
         *    pointless, so don't bother.
         */
    else {
        if (!(flags & NETSNMP_BUFFER_RESIZE)) {
            free(buf);
            return NULL;
        }
    }


    buf->flags = flags;
    return buf;
}


        /**
         *
         * Appends the given arbitrary string to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append(netsnmp_buf *buf, char *string, int len)
{
    int             len_left;

    if (NULL == buf) {
        return -1;
    }
    if ((NULL == string) ||
        (0 == len)) {
        return 0;
    }
        /*
         * Is there room in the buffer to append the new string?
         * If not, then extend it (if allowed) or report failure.
         */
    len_left = buf->max_len - buf->cur_len;
    if (len_left < len) {
        if (_buffer_extend(buf, len - len_left) < 0) {
            return -1;
        }
    }
    memcpy(buf->string + buf->cur_len, string, len);
    buf->cur_len += len;
    return 0;
}


        /**
         *
         * Appends the given null-terminated string to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_string(netsnmp_buf *buf, char *string)
{
    if (NULL == string) {
        return 0;
    }
    return buffer_append(buf, string, strlen(string));
}


        /**
         *
         * Appends the given single character to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_char(netsnmp_buf *buf, char ch)
{
    char            ch2 = ch;   /* So we can take the address!  */

    return buffer_append(buf, &ch2, 1);
}


        /**
         *
         * Returns the current value of the buffer.
         *
         * Calling this routine transfers responsibility for freeing
         *   the memory used by this string from 'buffer_free()' to
         *   the calling procedure.
         * This should be done *after* calling 'buffer_free()'
         */
char*
buffer_string(netsnmp_buf *buf)
{
    if (NULL == buf) {
        return NULL;
    }
    buf->flags |= NETSNMP_BUFFER_NOFREE;
    return buf->string;
}


        /**
         *
         * Releases the memory used by this buffer.
         *
         */
void 
buffer_free(netsnmp_buf *buf)
{
    if (NULL == buf) {
        return;
    }
    if (!(buf->flags & NETSNMP_BUFFER_NOFREE)) {
        free(buf->string);
    }
    free(buf);
    return;
}


                /**************************************
                 *
                 *      Internal utility routines
                 *
                 **************************************/
                 /** @package util_internals */

int 
_buffer_extend(netsnmp_buf *buf, int increase)
{
    char           *new_buf;
    int             new_buf_len;

        /*
         * Check the parameters
         */
    if (NULL == buf) {
        return -1;
    }
    if (0 == increase) {
        return 0;
    }
    if (!(buf->flags & NETSNMP_BUFFER_RESIZE)) {
        return -1;
    }
        /*
         * Current buffer re-allocation policy is to increase to 256 bytes,
         *   or by doubling the current buffer size (whichever is the greater),
         *   up to a maximum increase of 8192 bytes.
         *
         * This is repeated as many times as necessary to accomodate
         *   the requested increase.
         */
    new_buf_len = buf->max_len;
    while ((new_buf_len - buf->max_len) < increase) {

        if (256 > new_buf_len) {
            new_buf_len = 256;
        } else if (8192 > new_buf_len) {
            new_buf_len = new_buf_len * 2;
        } else {
            new_buf_len = new_buf_len + 8192;
        }
    }

        /*
         * Allocate (or reallocate) new memory accordingly.
         */
    if (buf->string) {
        new_buf = (char *)realloc(buf->string, new_buf_len);
    } else {
        new_buf = (char *)calloc(new_buf_len, 1);
    }
    if (NULL == new_buf) {
        return -1;
    }
    buf->string = new_buf;
    buf->max_len = new_buf_len;
    return 0;
}
