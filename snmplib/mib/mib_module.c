/*******************************
 *
 *      mib_dir.c
 *
 *      Net-SNMP library - MIB-handling interface
 *
 *      Module-related routines
 *
 *******************************/

#ifndef linux
#define HAVE_SYS_SYSLIMITS_H  1 /* XXX - until we tweak configure to check
                                 * for this */
#endif

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
#ifdef HAVE_SYS_SYSLIMITS_H
#include <sys/syslimits.h>
#endif

/* Wow.  This is still ugly.  -- Wes  */
/* Do we need all of this?    -- Dave */
#if HAVE_DIRENT_H
# include <dirent.h>
# define NAMLEN(dirent) strlen((dirent)->d_name)
#else
# define dirent direct
# define NAMLEN(dirent) (dirent)->d_namlen
# if HAVE_SYS_NDIR_H
#  include <sys/ndir.h>
# endif
# if HAVE_SYS_DIR_H
#  include <sys/dir.h>
# endif
# if HAVE_NDIR_H
#  include <ndir.h>
# endif
#endif

#include <net-snmp/mib_api.h>
#include <net-snmp/utils.h>
#include <smi.h>

static int      _mib_load_dir(char *dir);


                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/mib_api.h>)
                 *
                 **************************************/
                /** @package mib_api */

   /**
    *
    * Returns the list of modules currently loaded
    *
    * The calling routine is responsible for freeing
    *   this memory when no longer required.
    *
    */
char*
mib_list_modules()
{
    SmiModule      *mod;
    char           *list, *cp;

    mod = smiGetFirstModule();
    if (NULL == mod) {
        return NULL;
    }

    list = strdup(mod->name);
    if (NULL == list) {
        return NULL;
    }

    while (NULL != (mod = smiGetNextModule(mod))) {
        cp = list_add_token(list, mod->name, PATH_SEPARATOR);
        if (NULL == cp) {
            free(list);
            return NULL;
        }
        list = cp;
    }
    return list;
}


   /**
    *
    * Load the specified module(s) or file(s)
    *
    *  Return 0 on success, -ve on failure
    *
    */
int
mib_load_modules(char *list)
{
    char       *copy;
    char       *token;
    char       *s;
    char        sep[2];
    char       *res;

    if ((NULL == list) || ('\0' == *list)) {
        return -1;
    }

    copy = strdup(list);
    s = copy;
    if (NULL == copy) {
        return -1;
    }

    sep[0] = PATH_SEPARATOR;
    sep[1] = '\0';
    while (NULL != (token = strsep(&s, sep))) {
        res = smiLoadModule(token);
        if (NULL == res) {
            free(copy);
            return -1;
        }
        /* s = NULL;       */
    }

    free(copy);
    return 0;
}


   /**
    *
    * Load all modules on the current search list
    *
    *  Return 0 on success, -ve on failure
    *
    */
int
mib_load_all(void)
{
    char       *list;
    char       *token;
    char       *s;
    char        sep[2];

    list = smiGetPath();
    s = list;
    if ((NULL == list) || ('\0' == *list)) {
        return -1;
    }

    sep[0] = PATH_SEPARATOR;
    sep[1] = '\0';
    while (NULL != (token = strsep(&s, sep))) {
            /* 
             *  Load the contents of 'token' directory
             */
        (void) _mib_load_dir(token);
        /* s = NULL;       */
    }

    free(list);
    return 0;
}


   /**
    *
    * Unload the specified module (or file?)
    *
    *  Return 0 on success, -ve on failure
    *
    */
int
mib_unload_modules(char *list)
{
    char       *old_list, *new_list;
    int         res;

    old_list = mib_list_modules();
    if (NULL == old_list) {
        return -1;
    }
    new_list = list_remove_tokens(old_list, list, PATH_SEPARATOR);
    if (NULL == new_list) {
        free(old_list);
        return -1;
    }

    res = mib_load_modules(new_list);
    free(old_list);
    free(new_list);
    return res;
}


   /**
    *
    * Unload all loaded modules
    *
    *  Return 0 on success, -ve on failure
    *
    */
int
mib_unload_all(void)
{
    char       *list;
    int         res;

    list = mib_list_modules();
    if (NULL == list) {
        return 0;
    }
    res = mib_unload_modules(list);
    free(list);
    return res;
}


   /**
    *
    * Return the name of the file defining a particular module
    *
    * The calling routine is responsible for freeing
    *   this memory when no longer required.
    */
char*
mib_module_to_file(char *name)
{
    SmiModule  *mod;

    mod = smiGetModule(name);
    if (NULL != mod) {
        return strdup(mod->path);
    }
    return NULL;
}


                /**************************************
                 *
                 *      Internal utility routines
                 *
                 **************************************/

#ifndef DIR_SEPARATOR
#define DIR_SEPARATOR '/'
#endif

   /* 
    *
    * Load all the modules in the specified directory
    *
    *  Return 0 on success, -ve on failure
    *
    */
static int
_mib_load_dir(char *dir)
{
    DIR            *dir_ptr, *d2;
    struct dirent  *dir_ent;
    char            tmpname[PATH_MAX];

    dir_ptr = opendir(dir);
    if (NULL == dir_ptr) {
        return -1;
    }

    while (NULL != (dir_ent = readdir(dir_ptr))) {

        if ((       !dir_ent->d_name)    ||     /* No name     */
            ('\0' == dir_ent->d_name[0]) ||     /* Null name   */
            ('.'  == dir_ent->d_name[0])) {     /* Hidden file */
            continue;
        }

        memset(tmpname, 0, PATH_MAX);
        snprintf(tmpname, PATH_MAX, "%s%c%s",
                 dir, DIR_SEPARATOR, dir_ent->d_name);

        d2 = opendir(tmpname);          /* Skip subdirectories */
        if (NULL != d2) {
            closedir(d2);
            continue;
        }
        (void) smiLoadModule(tmpname);  /* Load the file */
    }

    (void) closedir(dir_ptr);
    return 0;
}
