/*******************************
 *
 *      util_list.c
 *
 *      Net-SNMP library - General utilities
 *
 *      Handle lists of tokens
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

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/utils.h>)
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
char*
list_add_token(char *list, char *token, char sep)
{
    char           *new_list;
    int             len;

    if ((NULL == token) ||
        ('\0' == *token)) {
        return strdup(list);    /* Trivial to add an empty token ...  */
    }
    if ((NULL == list) ||
        ('\0' == *list)) {
        return strdup(token);   /* .. or add to an empty list */
    }
    len = strlen(list) + strlen(token) + 1;
    new_list = (char *) calloc(len + 1, 1);
    if (NULL != new_list) {
        sprintf(new_list, "%s%c%s", list, sep, token);
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
char*
list_remove_token(char *list, char *token, char sep)
{
    char           *new_list = NULL;
    char           *delimited_token;
    char           *cp;

    int             token_len;
    int             new_len;

    if ((NULL == token) ||
        ('\0' == *token)) {
        return strdup(list);    /* Trivial to remove an empty token */
    }
    if ((NULL == list) ||
        ('\0' == *list)) {
        return NULL;            /* Can't remove a token from an empty list */
    }
    token_len = strlen(token);
    if (strlen(list) < token_len) {
        return NULL;            /* List too short to contain the token */
    }
        /*
         * Does the token appear as the first (or only)
         *   entry in the list ?
         */
    if (0 == strncmp(list, token, token_len)) {

        if ('\0' == list[token_len]) {  /* Only entry */
            new_list = strdup("");
            return new_list;
        }
        if (sep == list[token_len]) {   /* First entry */
            new_list = strdup(list + token_len + 1);
            return new_list;
        }
        /* Otherwise, the token matched a substring - which doesn't count */
    }
    new_len = strlen(list) - (token_len + 1);

        /*
         * Does the token appear as the final entry in the list ?
         */
    if ((sep == list[new_len]) &&
        (0 == strcmp(list + new_len + 1, token))) {

        new_list = (char *) calloc(new_len + 1, 1);
        if (NULL != new_list) {
            strncpy(new_list, list, new_len);
            new_list[new_len] = '\0';
        }
        return new_list;
    }
        /*
         * Does the token appear in the middle of the list ?
         */
    delimited_token = (char *) calloc(token_len + 2 + 1, 1);
    if (NULL == delimited_token) {
        return NULL;
    }
    sprintf(delimited_token, "%c%s%c", sep, token, sep);
    cp = strstr(list, delimited_token);
    if (NULL == cp) {
        free(delimited_token);
        return NULL;
    }
        /*
         * Yes - so construct a new list without it 
         */
    new_list = (char *) calloc(new_len + 1, 1);
    if (NULL == new_list) {
        free(delimited_token);
        return NULL;
    }
    new_len = cp - list;
    strncpy(new_list, list, new_len);
    strcpy(new_list + new_len, cp + token_len + 1);

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
char*
list_remove_tokens(char *list, char *remove, char sep)
{
    char           *new_list;
    char           *copy;       /* A working copy of the list to remove */
    char           *token;      /* Individual entries from this list */
    char           *s;          /* For use with 'strtok()' */
    char           *cp;
    char            sep_list[2];


    if ((NULL == remove) ||
        ('\0' == *remove)) {
        return strdup(list);
    }
    if ((NULL == list) ||
        ('\0' == *list)) {
        return NULL;
    }
        /*
         * Prepare a copy of the list of entries to remove,
         * ready for picking apart by 'strtok()'
         */
    copy = strdup(remove);
    s = copy;
    if (NULL == copy) {
        return NULL;
    }
    sep_list[0] = sep;
    sep_list[1] = '\0';
    new_list = list;


        /*
         * Remove each entry in turn from the local list
         */
    token = strtok(s, sep_list);
    while (NULL != token) {
        cp = list_remove_token(new_list, token, sep);
        if (NULL == cp) {
            if (new_list != list) {
                free(new_list);
            }
            free(copy);
            return NULL;
        }
        new_list = cp;
        s = NULL;
        token = strtok(s, sep_list);
    }

    free(copy);
    return new_list;
}


                /**************************************
                 *
                 *      Test Harness
                 *
                 **************************************/
                /** @package util_internals */

#ifdef TESTING
void 
test(char *list, char *token, char *expected)
{
    char           *res = util_remove_token(list, token, ':');

    if (NULL == res) {
        if (NULL != expected) {
            printf("Removing '%s' from '%s' failed\n", token, list);
        }
        return;
    }
    if (NULL == expected) {
        printf("Removing '%s' from '%s' returned '%s'\n", token, list, res);
        free(res);
        return;
    }
    if (0 != strcmp(res, expected)) {
        printf("Removing '%s' from '%s' failed\n", token, list);
        printf("\t('%s' not '%s')\n", res, expected);
    }
    free(res);
    return;
}

main()
{
    test(NULL,  NULL,  NULL);
    test(NULL,  "any", NULL);
    test("any", NULL,  "any");
    test("any", "any", "");

    test("one:two:three", "one",   "two:three");
    test("one:two:three", "two",   "one:three");
    test("one:two:three", "three", "one:two");
    test("one:two:three", "four",  NULL);

    test("one:two:three", "on",    NULL);
    test("one:two:three", "tw",    NULL);
    test("one:two:three", "wo",    NULL);
    test("one:two:three", "thre",  NULL);
    test("one:two:three", "hree",  NULL);
}

#endif
