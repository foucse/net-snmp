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

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/var_api.h>	/* for 'oid_sprint' */

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
    int max_len;

    buf = (netsnmp_buf *)calloc(1, sizeof(netsnmp_buf));
    if (NULL == buf) {
        return NULL;
    }
        /*
         * If we've been given a string, take a copy of that
         *   (or use it directly if so indicated)
         *
         * This is assumed to be of the length specified,
         *    and either empty or completely full
         *   (depending on the value of the first character).
         *
         * If a length hasn't been given, then assume this is
         *   C-style string, and calculate the length accordingly.
         */
    if (string) {
        buf->max_len = (len ? len : strlen(string));
        
	if (NETSNMP_BUFFER_NOCOPY & flags) {
            buf->string = string;
        } else {
            buf->string = calloc(1, buf->max_len);
            if (NULL == buf->string) {
                free(buf);
                return NULL;
            }
            memcpy(buf->string, string, buf->max_len);
        }
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
         *    then we have a new zero-length buffer.
         * Typically, this will be extended as strings are added to it,
         *    but in some circumstances, a NULL string is what is wanted.
         * This seems moderately pointless, but who are we to argue?
         */
    else {
        buf->string = NULL;
        buf->max_len = 0;
        buf->cur_len = 0;
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
    char           *cp;

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
    if ( buf->flags & NETSNMP_BUFFER_REVERSE ) {
	    /*
	     * If building backwards, find where the buffer
	     * current ends, and count back 'len' bytes.
	     */
        cp  = buf->string + (buf->max_len-buf->cur_len);
	cp -= len;
        memcpy(cp, string, len);
    } else {
        memcpy(buf->string + buf->cur_len, string, len);
    }
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
#undef buffer_append_string
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
         * Appends a Hex representation of the given string to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_hexstr(netsnmp_buf *buf, char *string, int len)
{
    char            tmp_buf[BUFSIZ];
    int             i;
    char           *cp;

    if (NULL == string) {
        return 0;
    }

    if ( len*2 > BUFSIZ ) {
        return -1;		/* XXX - Lazy, Dave! */
    }

    for (i=0, cp=tmp_buf; i<len; i++, cp+=2) {
        sprintf(cp, "%2x", string[i]);
    }

    return buffer_append(buf, tmp_buf, 2*len);
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
         * Appends one buffer structure to another
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_bufstr(netsnmp_buf *buf, netsnmp_buf *str)
{
    int offset;

    if (NULL == str) {
        return 0;		/* Trivially succeeds */
    }

    if (str->flags & NETSNMP_BUFFER_REVERSE) {
	offset = str->max_len - str->cur_len;
        return buffer_append(buf, (str->string + offset), str->cur_len);
    } else {
        return buffer_append(buf,  str->string,           str->cur_len);
    }
}


        /**
         *
         * Appends the given integer to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_int(netsnmp_buf *buf, int i)
{
    char            tmp_buf[BUFSIZ];

    sprintf(tmp_buf, "%d", i);
    return buffer_append(buf, tmp_buf, strlen(tmp_buf));
}


        /**
         *
         * Appends the given OID to the buffer.
         *
         *  Return 0 on success, -ve on failure
         *
         */
int 
buffer_append_oid(netsnmp_buf *buf, netsnmp_oid *oid)
{
    char            tmp_buf[BUFSIZ];

    oid_sprint(tmp_buf, BUFSIZ, oid);
    return buffer_append(buf, tmp_buf, strlen(tmp_buf));
}


        /**
         *
         * Returns the current value of the buffer.
         *
         * The calling procedure is responsible for freeing
         *   this memory when it is no longer required.
         * This should be done *after* calling 'buffer_free()'
         */
char*
buffer_string(netsnmp_buf *buf)
{
    int offset;
    char *cp, *ret;

    if (NULL == buf) {
        return NULL;
    }

    if (buf->flags & NETSNMP_BUFFER_REVERSE) {
	offset = buf->max_len - buf->cur_len;
	cp = (buf->string + offset);
    } else {
        cp =  buf->string;
    }

    if ( buf->flags & NETSNMP_BUFFER_NOFREE ) {
        ret = calloc(buf->cur_len, 1);
        memcpy(ret, cp, buf->cur_len);
    } else {
        buf->flags |= NETSNMP_BUFFER_NOFREE;
        ret = cp;
    }

    return ret;
}


int
buffer_set_string(netsnmp_buf *buf, char *string, int len)
{
    if ((NULL == buf)    ||
        (NULL == string) ||
        (0    == len)) {
        return -1;
    }

    if (!(buf->flags & NETSNMP_BUFFER_NOFREE)) {
        free(buf->string);
    }
 
    buf->string = string;	/* XXX - or make a copy? */
    if ((0 == len) && ('\0' != *string)) {
        buf->max_len = strlen(string);
    } else {
        buf->max_len = len;
    }
    buf->cur_len = buf->max_len;
    return 0;
}


        /**
         *
         * Creates a copy of a buffer structure.
         *
         * The calling routine should invoke 'buffer_free()'
         *      when this structure is no longer required.
         *
         */
netsnmp_buf*
buffer_copy(netsnmp_buf *buf)
{
    netsnmp_buf    *copy;

    if (NULL == buf ) {
        return NULL;
    }
    copy = buffer_new(NULL, buf->max_len, buf->flags);
    if (NULL == copy) {
        return NULL;
    }
    memcpy(copy->string, buf->string, buf->max_len);
    copy->cur_len = buf->cur_len;

    return copy;
}


        /**
         *
         * Releases the memory used by this buffer.
         *
         */
void 
buffer_free(netsnmp_buf *buf)
{
return;			/* XXX - Temp.... */
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
    char           *current_start;
    char           *new_start;

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
	 * If building forwards, we can 'realloc' an existing buffer.
	 * Otherwise, allocate the new memory normally.
         */
    if (!(buf->flags & NETSNMP_BUFFER_REVERSE) && (0 != buf->cur_len)) {
        new_buf = (char *)realloc(buf->string, new_buf_len);
    } else {
        new_buf = (char *)calloc(new_buf_len, 1);
    }
    if (NULL == new_buf) {
        return -1;
    }

        /*
	 * If building backwards, copy the existing contents of the buffer
         *   across to the end of the new memory.
         */
    if ((buf->flags & NETSNMP_BUFFER_REVERSE) && (0 != buf->cur_len)) {
	current_start = buf->string + (buf->max_len - buf->cur_len);
	new_start     = new_buf + (new_buf_len - buf->cur_len);
	memcpy(new_start, current_start, buf->cur_len);
    }
    buf->string  = new_buf;
    buf->max_len = new_buf_len;
    return 0;
}


int 
buffer_compare(netsnmp_buf *one, netsnmp_buf *two)
{
    int compare;

    if ((NULL == one) || (NULL == two)) {
        return 0;		/* Not really, but.... */
    }

    compare = (one->cur_len - two->cur_len);
    if (0 == compare) {
        compare = memcmp(one->string, two->string, one->cur_len);
    }
    return compare;
}
