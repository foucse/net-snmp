/*******************************
 *
 *      mib_api.c
 *
 *      Net-SNMP library - MIB-handling interface
 *
 *      General routines
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

#include <net-snmp/mib_api.h>


                /* 
                 * Temporary stuff....
                 */
int tags_match(char *taglist, const char *tag);

extern char    *confmibdir;
extern char    *confmibs;

char*
conf_read_string(char *tag)
{
    char       *env_var;

    if (0 == strcmp(tag, "mibdirs")) {
        env_var = getenv("MIBDIRS");

        if (env_var != NULL) {
            return strdup(env_var);
        } else if (confmibdir != NULL) {
            return strdup(confmibdir);
        } else {
            return strdup(DEFAULT_MIBDIRS);
        }
    }

    if (0 == strcmp(tag, "mibs")) {
        env_var = getenv("MIBS");

        if (env_var != NULL) {
            return strdup(env_var);
        } else if (confmibdir != NULL) {
            return strdup(confmibs);
        } else {
            return strdup(DEFAULT_MIBS);
        }
    }

    return NULL;
}


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/mib_api.h>)
                 *
                 **************************************/
                /** @package mib_api */


   /**
    *
    *  Initialise the MIB-handling subsystem
    *
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
mib_init(char *tags)
{
    char      *cp;

    if (!tags_match(tags, "mib")) {
        return -1;
    }

    (void) smiExit();
    (void) smiInit(NULL);

        /* 
         * ToDo:  Handle this via config settings instead
         */

        /* Set up the list of directories to search */
    cp = conf_read_string("mibdirs");
    if (NULL != cp) {
        mib_set_directories(cp);
        free(cp);
    }

        /* Read in the appropriate MIB modules */
    cp = conf_read_string("mibs");
    if (NULL != cp) {
        if (0 == strcmp(cp, "ALL")) {
            (void) mib_load_all();
        } else {
            (void) mib_load_modules(cp);
        }
        free(cp);
    }

    return 0;
}


   /**
    *
    *  Close down the MIB-handling subsystem
    *
    *  Returns 0 if successful, -ve otherwise
    *
    */
int
mib_close_down(char *tags)
{
    if (!tags_match(tags, "mib")) {
        return -1;
    }

    (void) smiExit();
    (void) mib_set_directories(NULL);   /* Clear the directory list */


    return 0;
}



                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package mib_internals */

   /* 
    *  int tags_match()
    *
    *  Should this initialisation routine be called?
    *
    *  Returns 1 if true, 0 if not
    */
#define YES 1
#define NO  0

#ifndef PATH_MAX
#define PATH_MAX 512
#endif

        /* 
         * XXX - this belongs in a more general utility subsystem
         */
int
tags_match(char *taglist, const char *tag)
{
    char        listbuf[PATH_MAX];
    char        tagbuf[ PATH_MAX];

        /* Nothing to check - default to YES */
    if ((NULL == taglist) || ('\0' == *taglist)) {
        return YES;
    }

        /* List of subsystems to skip */
    if (('!' == *taglist) || ('-' == *taglist)) {
        return 1 - tags_match(taglist + 1, tag);
    }

        /* Too many tags to check, so assume OK */
    if (PATH_MAX <= (strlen(taglist) + 2)) {
        return YES;
    }

        /* This tag is too long to check, so fail */
    if (PATH_MAX <= (strlen(tag) + 2)) {
        return NO;
    }

    snprintf(tagbuf,  PATH_MAX, ",%s,", tag);
    snprintf(listbuf, PATH_MAX, ",%s,", taglist);

    if (NULL != strstr(listbuf, tagbuf)) {
        return YES;
    } else {
        return NO;
    }
}
