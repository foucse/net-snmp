/*******************************
 *
 *      varbind/oid.c
 *
 *      Net-SNMP library - Variable-handling interface
 *
 *      OID-handling routines
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

#include <net-snmp/var_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/utils.h>

#include "default_store.h"

int _var_append_subids(netsnmp_oid *oid, char *name, netsnmp_mib *mib);


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/varbind_api.h>)
                 *
                 **************************************/
                /** @package varbind_api */


   /**
    *
    *  Set the OID to the name specified.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
oid_set_name(netsnmp_oid *oid, char *name)
{
    netsnmp_mib     *mib;

    if ((NULL == oid) || (NULL == name) || ('\0' == *name)) {
        return -1;
    }

        /* 
         * This OID structure previously contained a
         * "long" name, so release those resources.
         */
    if (oid->name && (oid->name != oid->namebuf)) {
        free(oid->name);
        oid->name = NULL;
    }

        /* 
         * Find the MIB object for this name,
         * and use the internal subid list
         * to initialise this OID structure.
         */
    mib = mib_find(name);
    if (NULL != mib) {
        (void) oid_set_value(oid, mib->oid, mib->oidlen);
    }

        /* 
         * Append any remaining subids
         */
    return _var_append_subids(oid, name, mib);
}


   /**
    *
    *  Set the OID to the list of subidentifier values specified.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
oid_set_value(netsnmp_oid *oid, u_int *name, int len)
{
    int             i;

    if (NULL == oid) {
        return -1;
    }
        /* 
         * This OID structure previously contained a
         * "long" name, so release those resources.
         */
    if (oid->name && (oid->name != oid->namebuf)) {
        free(oid->name);
        oid->name = NULL;
    }

        /* 
         * Will the new name fit into the in-line buffer ?
         */
    if (NETSNMP_NAMEBUF_LEN < len) {
        oid->name = (unsigned int *) calloc(len, sizeof(unsigned int));
        if (NULL == oid->name) {
            return -1;
        }
    } else {
        oid->name = oid->namebuf;
    }

        /* Set up the new values */
    for (i = 0; i < len; i++) {
        oid->name[i] = name[i];
    }
    oid->len = len;
    return 0;
}


   /**
    *
    *  Create a new (empty) OID structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid*
oid_create(void)
{
    return (netsnmp_oid*) calloc(1, sizeof(netsnmp_oid));
}


   /**
    *
    *  Create a new OID structure and set it to the name specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid*
oid_create_name(char *name)
{
    netsnmp_oid     *oid;

    oid = oid_create();

    if (0 > oid_set_name(oid, name)) {
        if (oid) {
            free(oid);
        }
        oid = NULL;
    }
    return oid;
}


   /**
    *
    *  Create a new OID structure and set it to the values specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid*
oid_create_value(u_int * name, int len)
{
    netsnmp_oid     *oid;

    oid = oid_create();

    if (0 > oid_set_value(oid, name, len)) {
        if (oid) {
            free(oid);
        }
        oid = NULL;
    }
    return oid;
}


   /**
    *
    *  Create a copy of an OID structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_oid*
oid_copy(netsnmp_oid *oid)
{
    if (NULL == oid) {
        return NULL;
    }
    return oid_create_value(oid->name, oid->len);
}


   /**
    *
    *  Free an OID structure
    *
    *  The oid structure should not be regarded as valid
    *  once this routine has been called.
    */
void
oid_free(netsnmp_oid *oid)
{
    if (NULL == oid) {
        return;
    }
    if (oid->name && (oid->name != oid->namebuf)) {
        free(oid->name);
        oid->name = NULL;
    }
    memset((void *) oid, 0, sizeof(netsnmp_oid));
    free(oid);
    return;
}


   /**
    *
    *  Print the name of an OID in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
oid_bprint(netsnmp_buf *buf, netsnmp_oid *oid)
{
    netsnmp_mib    *mib;
    int             ret = -1;
    int             len2 = 0;
    int             i;
    char            tmpbuf[SPRINT_MAX_LEN];

    if ((NULL == oid) || (NULL == buf)) {
        return -1;
    }

    if (!(ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_OIDS))) {
        mib = mib_find_by_oid(oid);
        if (NULL != mib) {
            ret = mib_bprint(buf, mib);
        }
        if (0 == ret) {
            len2 = mib->oidlen;   /* This much has been handled already */
        }
    }

        /* Append any remaining subidentifiers */
    for (i = len2; i < oid->len; i++) {
        sprintf(tmpbuf, ".%d", oid->name[i]);
        __B(buffer_append_string(buf, tmpbuf))
    }

    return 0;
}


   /**
    *
    *  Print the name of an OID in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char *
oid_sprint(char *str_buf, int len, netsnmp_oid *oid)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == oid_bprint(buf, oid)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print the name of an OID to the specified file.
    *
    */
void
oid_fprint(FILE *fp, netsnmp_oid *oid)
{
    netsnmp_buf    *buf;

    if (NULL == oid) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == oid_bprint(buf, oid)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print the name of an OID to standard output.
    *
    */
void
oid_print(netsnmp_oid *oid)
{
    oid_fprint(stdout, oid);
}



                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package varbind_internals */

   /* 
    *  The libSMI 'smiGetNode' routine discards any trailing
    *  subidentifiers, and returns the node for the longest prefix
    *  that it recognises.
    *    We need to append these extra subids when setting up an
    *  OID structure.
    *
    *  In the absence of a libSMI routine to provide this information,
    *  all we can do is search for the point where 'smiGetNode' first
    *  returns the given node.  Everything following that should be
    *  regarded as numeric subidentifiers, and added to the OID.
    *  If this assumption is false (i.e. 'atoi()' returns 0 for
    *  anything other than '0') then give up in disgust.
    *
    *  This approach isn't particularly efficient or elegant,
    *  but it seems to work quite reliably.  It'll do for now
    *  until we develop something more flexible - either within
    *  the net-snmp library, or perhaps an extension to libSMI.
    */
int
_var_append_subids(netsnmp_oid *oid, char *name, netsnmp_mib *mib)
{
    netsnmp_mib    *mib2;
    char           *copy;
    char           *cp;
    int             i, len;

    if ('.' == *name) {
        copy = strdup(name + 1);
    } else {
        copy = strdup(name);
    }
    if (NULL == copy) {
        return -1;
    }

    for (cp = strchr(copy, '.'); NULL != cp; cp = strchr(cp + 1, '.')) {
        *cp = '\0';
        mib2 = mib_find(copy);
        *cp = '.';
        if (mib == mib2) {      /* Found where the 'mib' object OID ends */
            break;
        }
    }

    if (cp) {
        len = oid->len;
        for (; NULL != cp; cp = strchr(cp + 1, '.')) {
            i = atoi(cp + 1);
            if ((0 == i) && ('0' != *(cp + 1))) {
                return -1;      /* atoi translation failed */
            }
            oid->name[len] = i; /* XXX - could overrun alloced memory */
            len++;
        }
        oid->len = len;
    }
    return 0;
}
