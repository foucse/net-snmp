/*******************************
 *
 *      varbind/vblist.c
 *
 *      Net-SNMP library - Variable-handling interface
 *
 *      Variable-binding list-handling routines
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




                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/varbind_api.h>)
                 *
                 **************************************/
                /** @package varbind_api */


   /**
    *
    *  Add the specified varbind to the end of the given list
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
vblist_add_varbind(netsnmp_varbind *vblist, netsnmp_varbind *varbind)
{
    netsnmp_varbind *vb;

    if ((NULL == varbind) && (NULL == vblist)) {
        return -1;
    }

    for (vb = vblist; NULL != vb->next; vb = vb->next) {
        ;                       /* Find the end of the list */
    }

    vb->next = varbind;
    varbind->prev = vb;
    varbind->pdu = vb->pdu;

    return 0;
}


   /**
    *
    *  Identify the specified varbind from the given list.
    *   (indexing from 1)
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind*
vblist_return_varbind(netsnmp_varbind *vblist, int idx)
{
    netsnmp_varbind *vb;
    int             i;

    if ((NULL == vblist) || (0 >= idx)) {
        return NULL;
    }

    vb = vblist;
    for (i = idx; 0 < i; i--) {
        if (NULL == vb) {
            return NULL;
        }
        vb = vb->next;
    }
    return vb;
}


   /**
    *
    *  Extract the specified varbind from the given list,
    *   (indexing from 1) and remove it from the list.
    *
    *  Returns a pointer to the varbind structure if found,
    *  NULL otherwise.
    *
    */
netsnmp_varbind*
vblist_extract_varbind(netsnmp_varbind *vblist, int idx)
{
    netsnmp_varbind *vb;

    vb = vblist_return_varbind(vblist, idx);

        /* 
         * Unlink it from the list
         */
    if (vb) {
        if (vb->prev) {
            vb->prev->next = vb->next;
        }
        if (vb->next) {
            vb->next->prev = vb->prev;
        }
    }
    return vb;
}


   /**
    *
    *  Free a varbind list
    *
    *  The list should not be regarded as valid
    *  once this routine has been called.
    */
void
vblist_free(netsnmp_varbind *vblist)
{
    netsnmp_varbind *vb, *vbnext;

    if (NULL == vblist) {
        return;
    }

    for (vb = vblist; NULL != vb; vb = vbnext) {
        vbnext = vb->next;
        var_free_varbind(vb);
    }
    return;
}


   /**
    *
    *  Print a varbind list in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
vblist_bprint(netsnmp_buf *buf, netsnmp_varbind *vblist)
{
    netsnmp_varbind *vb;

    for (vb = vblist; NULL != vb; vb = vb->next) {
        __B(var_bprint_varbind(buf, vb))
        __B(buffer_append_char(buf, '\n'))
    }

    return 0;
}


   /**
    *
    *  Print a varbind list in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
vblist_sprint(char *str_buf, int len, netsnmp_varbind *vblist)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == vblist_bprint(buf, vblist)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a varbind list to the specified file.
    *
    */
void
vblist_fprint(FILE * fp, netsnmp_varbind *vblist)
{
    netsnmp_buf    *buf;

    if (NULL == vblist) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == vblist_bprint(buf, vblist)) {
        fprintf(fp, "%s", buf->string);
    }
    buffer_free(buf);
}


   /**
    *
    *  Print a variable binding to standard output. 
    *
    */
void
vblist_print(netsnmp_varbind *vblist)
{
    vblist_fprint(stdout, vblist);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package varbind_internals */

