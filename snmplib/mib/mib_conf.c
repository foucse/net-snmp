/*******************************
 *
 *      mib_conf.c
 *
 *      Net-SNMP library - MIB-handling interface
 *
 *      Configuration handling routines
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

#include "ucd/ucd_api.h"
#include "read_config.h"
#include "snmp_debug.h"
#include "default_store.h"



                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/mib_api.h>)
                 *
                 **************************************/
                /** @package mib_api */



                /**************************************
                 *
                 *      internal utility routines
                 *
                 **************************************/
                /** @package mib_internals */


char           *confmibdir = NULL;
char           *confmibs = NULL;

void
handle_mibdirs_conf(const char *token, char *line)
{
    char       *ctmp;

    if (confmibdir) {
        ctmp = (char *) malloc(strlen(confmibdir) + strlen(line) + 1);
        if ('+' == *line)
            line++;
        sprintf(ctmp, "%s%c%s", confmibdir, ENV_SEPARATOR_CHAR, line);
        free(confmibdir);
        confmibdir = ctmp;
    } else {
        confmibdir = strdup(line);
    }
    DEBUGMSGTL(("read_config:initmib", "using mibdirs: %s\n", confmibdir));
}

void
handle_mibs_conf(const char *token, char *line)
{
    char       *ctmp;

    if (confmibs) {
        ctmp = (char *) malloc(strlen(confmibs) + strlen(line) + 1);
        if ('+' == *line)
            line++;
        sprintf(ctmp, "%s%c%s", confmibs, ENV_SEPARATOR_CHAR, line);
        free(confmibs);
        confmibs = ctmp;
    } else {
        confmibs = strdup(line);
    }
    DEBUGMSGTL(("read_config:initmib", "using mibs: %s\n", confmibs));
}

void
handle_mibfile_conf(const char *token, char *line)
{
    DEBUGMSGTL(("read_config:initmib", "reading mibfile: %s\n", line));
    mib_load_modules(line);
}


void
register_mib_handlers(void)
{
    register_premib_handler("snmp", "mibdirs",
                            handle_mibdirs_conf, NULL,
                            "[mib-dirs|+mib-dirs]");
    register_premib_handler("snmp", "mibs",
                            handle_mibs_conf, NULL,
                            "[mib-tokens|+mib-tokens]");
    register_config_handler("snmp", "mibfile",
                            handle_mibfile_conf, NULL,
                            "mibfile-to-read");

        /*
         *  register the snmp.conf configuration handler
         *  for default parsing behaviour
         */

    ds_register_premib(ASN_BOOLEAN, "snmp", "showMibErrors",
                       DS_LIBRARY_ID, DS_LIB_MIB_ERRORS);
    ds_register_premib(ASN_BOOLEAN, "snmp", "strictCommentTerm",
                       DS_LIBRARY_ID, DS_LIB_MIB_COMMENT_TERM);
    ds_register_premib(ASN_BOOLEAN, "snmp", "mibAllowUnderline",
                       DS_LIBRARY_ID, DS_LIB_MIB_PARSE_LABEL);
    ds_register_premib(ASN_INTEGER, "snmp", "mibWarningLevel",
                       DS_LIBRARY_ID, DS_LIB_MIB_WARNINGS);
    ds_register_premib(ASN_BOOLEAN, "snmp", "mibReplaceWithLatest",
                       DS_LIBRARY_ID, DS_LIB_MIB_REPLACE);

    ds_register_premib(ASN_BOOLEAN, "snmp", "printNumericEnums",
                       DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM);
    ds_register_premib(ASN_BOOLEAN, "snmp", "printNumericOids",
                       DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_OIDS);
    ds_register_premib(ASN_BOOLEAN, "snmp", "escapeQuotes",
                       DS_LIBRARY_ID, DS_LIB_ESCAPE_QUOTES);
    ds_register_premib(ASN_BOOLEAN, "snmp", "dontBreakdownOids",
                       DS_LIBRARY_ID, DS_LIB_DONT_BREAKDOWN_OIDS);
    ds_register_premib(ASN_BOOLEAN, "snmp", "quickPrinting",
                       DS_LIBRARY_ID, DS_LIB_QUICK_PRINT);
    ds_register_premib(ASN_BOOLEAN, "snmp", "numericTimeticks",
                       DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS);
    ds_register_premib(ASN_INTEGER, "snmp", "suffixPrinting",
                       DS_LIBRARY_ID, DS_LIB_PRINT_SUFFIX_ONLY);
    ds_register_premib(ASN_BOOLEAN, "snmp", "extendedIndex",
                       DS_LIBRARY_ID, DS_LIB_EXTENDED_INDEX);
    ds_register_premib(ASN_BOOLEAN, "snmp", "printHexText",
                       DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT);
}
