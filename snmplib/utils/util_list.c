/*******************************
 *
 *	util_list.c
 *
 *	Net-SNMP library - General utilities
 *
 *	Handle lists of tokens
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


#include <net-snmp/utils.h>

		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/utils.h>)
		 *
		 **************************************/
		/** @package utils */

	/**
	 *
	 *  Add the specified token to the list
	 *
	 *  Returns a pointer to the new list if successful.
	 *
	 *  The calling routine is responsible for freeing
	 *  both old and new lists when no longer required.
	 */
char *list_add_token( char *list, char *token, char sep )
{
    char *new_list;
    int   len;

    if (( token == NULL ) ||
	(*token == '\0' )) {

	return strdup(list);	/* Trivial to add an empty token ... */
    }

    if (( list == NULL ) ||
	(*list == '\0' )) {

	return strdup(token);	/* .. or add to an empty list */
    }

    len = strlen( list ) + strlen( token ) + 1;
    new_list = (char*)calloc( len+1, 1 );
    if ( new_list != NULL ) {
	sprintf( new_list, "%s%c%s", list, sep, token );
    }
    return new_list;
}


	/**
	 *
	 *  Remove the specified token from the list, if present
	 *
	 *  Returns a pointer to the new list if successful.
	 *  Returns NULL if the token was not found,
	 *    or something went wrong
	 *
	 *  The calling routine is responsible for freeing
	 *  both old and new lists when no longer required.
	 */
char *list_remove_token( char *list, char *token, char sep )
{
    char *new_list = NULL;
    char *delimited_token;
    char *cp;

    int  token_len;
    int  new_len;

    if (( token == NULL ) ||
	(*token == '\0' )) {

	return strdup(list);	/* Trivial to remove an empty token */
    }

    if (( list == NULL ) ||
	(*list == '\0' )) {

	return NULL;	/* Can't remove a token from an empty list */
    }

    token_len    = strlen( token );
    if ( token_len > strlen( list )) {
	return NULL;	/* List too short to contain the token */
    }

		/*
		 * Does the token appear as the first (or only)
		 *   entry in the list ?
		 */
    if ( strncmp( list, token, token_len) == 0 ) {

	if ( list[token_len] == '\0' ) {	/* Only entry */
	    new_list = strdup( "" );
	    return new_list;
	}

	if ( list[token_len] == sep ) {		/* First entry */
	    new_list = strdup( list+token_len+1 );
	    return new_list;
	}

	/* The token matched a substring - which doesn't count */
    }
		    

    new_len = strlen( list ) - (token_len+1);

		/*
		 * Does the token appear as the final entry in the list ?
		 */
    if (( list[new_len] == sep ) &&
	( strcmp( list+new_len+1, token ) == 0 )) {

	new_list = (char*)calloc( new_len+1, 1 );
	if ( new_list != NULL ) {
	    strncpy( new_list, list, new_len );
	    new_list[ new_len ] = '\0';
	}
	return new_list;
    }


		/*
		 * Does the token appear in the middle of the list ?
		 */
    delimited_token = (char*)calloc( token_len+2+1, 1 );
    if ( delimited_token == NULL ){
	return NULL;
    }
    sprintf( delimited_token, "%c%s%c", sep, token, sep );
    cp = strstr( list, delimited_token );
    if ( cp == NULL ) {
	free( delimited_token );
	return NULL;
    }

		/* Yes - so construct a new list without it */
    new_list = (char*)calloc( new_len+1, 1 );
    if ( new_list == NULL ) {
	free( delimited_token );
	return NULL;
    }
    new_len = cp-list;
    strncpy( new_list, list, new_len );
    strcpy(  new_list+new_len, cp+token_len+1 );

    return new_list;
}


	/**
	 *
	 *  Remove the specified tokens from the list.
	 *
	 *  Returns a pointer to the new list if successful.
	 *  Returns NULL if any of the tokens were found,
	 *    or something went wrong
	 *
	 *  The calling routine is responsible for freeing
	 *  both old and new lists, and the list of tokens,
	 *  when no longer required.
	 */
char *list_remove_tokens(  char *list, char *remove, char sep )
{
    char *new_list;
    char *copy;		/* A working copy of the list to remove */
    char *token;	/* Individual entries from this list */
    char *s;		/* For use with 'strtok()' */
    char *cp;
    char sep_list[2];


    if (( remove == NULL ) ||
        (*remove == '\0' )) {

	return strdup( list );
    }
    if (( list == NULL ) ||
	(*list == '\0' )) {

	return NULL;
    }

		/*
		 * Prepare a copy of the list of entries to remove,
		 * ready for picking apart by 'strtok()'
		 */
    copy = strdup( remove );
    s    = copy;
    if ( copy == NULL ) {
	return NULL;
    }
    sep_list[0] = sep;
    sep_list[1] = '\0';
    new_list    = list;


		/*
		 * Remove each entry in turn from the local list
		 */
    while (( token = strtok( s, sep_list )) != NULL ) {
	cp = list_remove_token( new_list, token, sep );
	if ( cp == NULL ) {
	    if ( new_list != list ) {
		free( new_list );
	    }
	    free( copy );
	    return NULL;
	}
	new_list = cp;
	s        = NULL;
    }

    free( copy );
    return new_list;
}


		/**************************************
		 *
		 *	Test Harness
		 *
		 **************************************/
		/** @package util_internals */

#ifdef TESTING
void test( char *list, char *token, char *expected )
{
    char *res = util_remove_token( list, token, ':' );

    if ( res == NULL ) {
	if ( expected != NULL ) {
	     printf( "Removing '%s' from '%s' failed\n", token, list );
	}
	return;
    }
    if ( expected == NULL ) {
	printf( "Removing '%s' from '%s' returned '%s'\n", token, list, res );
	free( res );
	return;
    }

    if ( strcmp( res, expected ) != 0 ) {
	printf( "Removing '%s' from '%s' failed\n", token, list );
	printf( "\t('%s' not '%s')\n", res, expected );
    }
    free( res );
    return;
}

main()
{
    test( NULL,  NULL,  NULL   );
    test( NULL,  "any", NULL   );
    test( "any", NULL,  "any"  );
    test( "any", "any", ""     );

    test( "one:two:three", "one",   "two:three" );
    test( "one:two:three", "two",   "one:three" );
    test( "one:two:three", "three", "one:two"   );
    test( "one:two:three", "four",   NULL       );

    test( "one:two:three", "on",     NULL       );
    test( "one:two:three", "tw",     NULL       );
    test( "one:two:three", "wo",     NULL       );
    test( "one:two:three", "thre",   NULL       );
    test( "one:two:three", "hree",   NULL       );
}

#endif
