/*******************************
 *
 *      sec_model/secmod.c
 *
 *      Net-SNMP library - Security Model interface
 *
 *      SecModel registry routines
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

#include <net-snmp/struct.h>
#include <net-snmp/error.h>
#include "sec_model/secmod.h"


netsnmp_secmod *secmod_head = NULL;
netsnmp_secmod *secmod_tail = NULL;


void
secmod_init(void)
{

}


netsnmp_secmod *secmod_new(int model)
{
    netsnmp_secmod *sptr;

    sptr = (netsnmp_secmod*)calloc(1, sizeof(netsnmp_secmod));
    if (NULL == sptr) {
        return NULL;
    }

	/*
	 * XXX - fill in the values
	 */
    sptr->sec_model = model;
    return sptr;
}


int
secmod_register(int model, const char *name, netsnmp_secmod *newdef)
{
    netsnmp_secmod *sptr;

    if (NULL == newdef) {
        return SNMPERR_GENERR;
    }

    /*
     * Search the list of registered Security Model entries
     *   for where this one should go.
     */
    for (sptr = secmod_head; NULL != sptr; sptr = sptr->next) {
        if (model == sptr->sec_model) {
            return SNMPERR_GENERR;		/* Duplicate registration */
        }
        if (model > sptr->sec_model) {
            break;			/* Found the insertion point */
        }
    }

    /*
     * If there isn't a 'later' entry, add this to the end of the list.
     */
    if (NULL == sptr) {
        newdef->prev = secmod_tail;
        newdef->next = NULL;
        if (NULL == secmod_tail) {
            secmod_tail = newdef;
            secmod_head = newdef;
        } else {
            secmod_tail->next = newdef;
        }

    /*
     * Otherwise, insert this registration just before the point found.
     */
    } else {
        newdef->prev = sptr->prev;
        newdef->next = sptr;
        if (NULL == sptr->prev) {
            secmod_head = newdef;
        } else {
            sptr->prev->next = newdef;
        }
    }
    return SNMPERR_SUCCESS;
}


netsnmp_secmod *secmod_find(int model)
{
    netsnmp_secmod *sptr;

    for (sptr = secmod_head; NULL != sptr; sptr = sptr->next) {
        if (model == sptr->sec_model) {
            return sptr;
        }
    }

    return NULL;
}


void secmod_free(netsnmp_secmod *sptr)
{
    if (NULL == sptr) {
        return;
    }

    /*
     *  Unlink this entry from the list
     */
    if (NULL == sptr->prev) {
        secmod_head = sptr->next;
    } else {
        sptr->prev->next = sptr->next;
    }
    if (NULL == sptr->next) {
        secmod_tail = sptr->prev;
    } else {
        sptr->next->prev = sptr->prev;
    }
    sptr->prev = NULL;
    sptr->next = NULL;
    free(sptr);
    return;
}


int secmod_unregister(int model)
{
    netsnmp_secmod *sptr;

    sptr = secmod_find(model); 
    if (NULL == sptr) {
        return SNMPERR_GENERR;		/* Not registered */
    }
    secmod_free(sptr);
    return SNMPERR_SUCCESS;
}

