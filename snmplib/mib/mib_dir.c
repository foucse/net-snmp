/*******************************
 *
 *	mib_dir.c
 *
 *	Net-SNMP library - MIB-handling interface
 *
 *	Directory-related routines
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

#include <net-snmp/mib_api.h>
#include <smi.h>


extern char* util_remove_token( char *old_list, char *token,    char sep);
extern char* util_remove_list(  char *old_list, char *rem_list, char sep);

		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/mib_api.h>)
		 *
		 **************************************/
		/** @package mib_api */

   /**
    *
    * Returns the current list of directories to search for MIB files
    *
    * The calling routine is responsible for freeing
    *	this memory when no longer required.
    *
    */
char *mib_list_directories()
{
    return smiGetPath();
}


   /**
    *
    * Sets the MIB directory search list to that specified,
    *	replacing the current list of directories to search.
    *	The new directories are not validated for existance,
    *	accessibility, duplicates, etc.
    *
    *  Return 0 on success, -ve on failure
    *
    */
int   mib_set_directories( char *dirs )
{
    if ( dirs && *dirs =='+' ) {
	return mib_add_directories( dirs );
    }
    else {
	return smiSetPath( dirs );
    }
}


   /**
    *
    * Adds the specified directory (or directories) to the
    *	current search list.
    *	A value of the form "+dir" will prepend the new entries
    *	to the current list.  Otherwise they will be appended.
    *	The additional directories are not validated for existance,
    *	accessibility, duplicates, etc.
    *
    *  Return 0 on success, -ve on failure
    *
    */
int   mib_add_directories( char *dirs )
{
    char *old_list;
    char *new_list;
    int   prepend;
    int   new_len;
    int   ret;

    if (( dirs == NULL ) ||
	(*dirs == '\0' ) ||
	( strcmp(dirs, "+" ) == 0 )) {

	return 0;	/* Trivial to add nothing to the list */
    }

    prepend = ( *dirs == '+' );
    old_list = smiGetPath();

    if (( old_list == NULL ) ||
	(*old_list == '\0' )) {
			/* 'Add' to an empty list */
	return smiSetPath( prepend ? dirs+1 : dirs );
    }


			/* Construct the new list */
    new_len = strlen( old_list ) + strlen( dirs );
    if ( !prepend ) {
	++new_len;
    }
    new_list = (char*)calloc( new_len+1, 1 );
    if ( new_list == NULL ) {
	free( old_list );
	return -1;
    }

    if ( prepend ) {
	sprintf( new_list, "%s%c%s", dirs+1, PATH_SEPARATOR, old_list );
    }
    else {
	sprintf( new_list, "%s%c%s", old_list, PATH_SEPARATOR, dirs );
    }

    ret = smiSetPath( new_list );
    free( old_list );
    free( new_list );
    return ret;
}


   /**
    *
    *	removes the specified directory or directories from the
    *	current search list.
    *
    *  If multiple directories are specified, this routine is called
    *	recursively, to remove them individually.
    *
    *  Return 0 on success, -ve on failure
    *	If multiple directories are specified, then a failure will
    *	leave the search list unchanged.
    */
int   mib_remove_directories( char *dirs )
{
    char *old_list;
    char *new_list;
    int   ret;

    if (( dirs == NULL ) ||
	(*dirs == '\0' )) {
	return 0;	/* Trivial to remove nothing to the list */
    }

    old_list = smiGetPath();

    if (( old_list == NULL ) ||
	(*old_list == '\0' )) {

	return -1;	/* Can't remove anything from an empty list */
    }

    new_list = util_remove_list( old_list, dirs, PATH_SEPARATOR);

		/* Apply the new list, and tidy up */
    ret = -1;
    if ( new_list != NULL ) {
	ret = smiSetPath( new_list );
	free( new_list );
    }
    free( old_list );
    return ret;
}
