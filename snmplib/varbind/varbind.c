/*******************************
 *
 *      varbind/varbind.c
 *
 *      Net-SNMP library - Variable-handling interface
 *
 *      Variable-binding handling routines
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
    *  Assign the specified name and value to the given structure
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int
var_set_varbind(netsnmp_varbind *vb, netsnmp_oid *oid, netsnmp_value *value)
{
    if (NULL == vb) {
        return -1;
    }
    if ((NULL == oid) && (NULL == value)) {
        return -1;
    }

    if (NULL != vb->oid) {
        oid_free(vb->oid);
    }
    vb->oid = oid_copy(oid);
    if (NULL == vb->oid) {
        return -1;
    }

    if (NULL != vb->value) {
        var_free_value(vb->value);
    }
    vb->value = var_copy_value(value);
    if (NULL == vb->value) {
        return -1;
    }
    return 0;
}


   /**
    *
    *  Create a new (empty) varbind structure
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_varbind*
var_create_varbind(void)
{
    netsnmp_varbind *varbind;

    varbind = (netsnmp_varbind*) calloc(1, sizeof(netsnmp_varbind));

    if (NULL != varbind) {
        varbind->oid   = oid_create();
        varbind->value = var_create_value(ASN_NULL);

        if ((NULL == varbind->oid) || (NULL == varbind->value)) {

            if (NULL != varbind->oid) {
                free(varbind->oid);
                varbind->oid = NULL;
            }
            if (NULL != varbind->value) {
                free(varbind->value);
                varbind->value = NULL;
            }
            free(varbind);
            varbind = NULL;
        }
    }
    return varbind;
}


   /**
    *
    *  Create a new varbind structure and set it to the values specified.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_varbind*
var_create_set_varbind(netsnmp_oid *oid, netsnmp_value *value)
{
    netsnmp_varbind *varbind;

    varbind = var_create_varbind();

    if (varbind && (0 > var_set_varbind(varbind, oid, value))) {
        free(varbind);
        varbind = NULL;
    }
    return varbind;
}


   /**
    *
    *  Create a copy of the given varbind structure.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    *  The calling routine is responsible for freeing this memory
    *  when it is not longer required.
    */
netsnmp_varbind*
var_copy_varbind(netsnmp_varbind *vb)
{
    if (NULL == vb) {
        return NULL;
    }
    return (var_create_set_varbind(vb->oid, vb->value));
}


   /**
    *
    *  Free a varbind structure
    *
    *  The varbind structure should not be regarded as valid
    *  once this routine has been called.
    */
void
var_free_varbind(netsnmp_varbind *vb)
{
    if (NULL == vb) {
        return;
    }
    oid_free(  vb->oid);
    var_free_value(vb->value);
    memset((void *) vb, 0, sizeof(netsnmp_varbind));
    free(vb);
    return;
}


   /**
    *
    *  Print a variable binding in the expandable buffer provided.
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
var_bprint_varbind(netsnmp_buf *buf, netsnmp_varbind *varbind)
{
    netsnmp_mib     *mib;

    if ((NULL == varbind) || (NULL == buf)) {
        return -1;
    }

    mib = mib_find_by_oid(varbind->oid);

    __B(oid_bprint(buf, varbind->oid))
    __B(buffer_append_string(buf, " = "))
    __B(var_bprint_value(buf, varbind->value, mib))

    return 0;
}


   /**
    *
    *  Print a variable binding in the string buffer provided.
    *  Returns a pointer to this name if successful, NULL otherwise.
    *
    */
char*
var_sprint_varbind(char *str_buf, int len, netsnmp_varbind *varbind)
{
    netsnmp_buf    *buf;
    char           *cp = NULL;

    buf = buffer_new(str_buf, len, NETSNMP_BUFFER_NOFREE);
    if (NULL == buf) {
        return NULL;
    }
    if (0 == var_bprint_varbind(buf, varbind)) {
        cp = buffer_string(buf);
    }
    buffer_free(buf);
    return cp;
}


   /**
    *
    *  Print a variable binding to the specified file.
    *
    */
void
var_fprint_varbind(FILE *fp, netsnmp_varbind *varbind)
{
    netsnmp_buf    *buf;

    if (NULL == varbind) {
        return;
    }
    buf = buffer_new(NULL, 0, NETSNMP_BUFFER_RESIZE);
    if (NULL == buf) {
        return;
    }
    if (0 == var_bprint_varbind(buf, varbind)) {
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
var_print_varbind(netsnmp_varbind *varbind)
{
    var_fprint_varbind(stdout, varbind);
}


                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package varbind_internals */
