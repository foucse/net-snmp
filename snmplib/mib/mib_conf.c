/*******************************
 *
 *	mib_conf.c
 *
 *	Net-SNMP library - MIB-handling interface
 *
 *	Configuration handling routines
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

#include "asn1.h"
#include "read_config.h"
#include "snmp_debug.h"



		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/mib_api.h>)
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
static
void mib_zzz_TEMPLATE( void  )
{
}



		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package mib internals */


char *confmibdir=NULL;
char *confmibs=NULL;

void
handle_mibdirs_conf(const char *token,
		    char *line)
{
    char *ctmp;

    if (confmibdir) {
        ctmp = (char *)malloc(strlen(confmibdir) + strlen(line) + 1);
        if (*line == '+')
            line++;
        sprintf(ctmp,"%s%c%s",confmibdir, ENV_SEPARATOR_CHAR, line);
        free(confmibdir);
        confmibdir = ctmp;
    } else {
        confmibdir=strdup(line);
    }
    DEBUGMSGTL(("read_config:initmib", "using mibdirs: %s\n", confmibdir));
}

void
handle_mibs_conf(const char *token,
		 char *line)
{
    char *ctmp;

    if (confmibs) {
        ctmp = (char *)malloc(strlen(confmibs) + strlen(line) + 1);
        if (*line == '+')
            line++;
        sprintf(ctmp,"%s%c%s",confmibs, ENV_SEPARATOR_CHAR, line);
        free(confmibs);
        confmibs = ctmp;
    } else {
        confmibs=strdup(line);
    }
    DEBUGMSGTL(("read_config:initmib", "using mibs: %s\n", confmibs));
}

void
handle_mibfile_conf(const char *token,
		    char *line)
{
  DEBUGMSGTL(("read_config:initmib", "reading mibfile: %s\n", line));
  mib_load_modules(line);
}

void
register_mib_handlers (void)
{
    register_premib_handler("snmp","mibdirs",
					handle_mibdirs_conf, NULL,
					"[mib-dirs|+mib-dirs]");
    register_premib_handler("snmp","mibs",
					handle_mibs_conf, NULL,
					"[mib-tokens|+mib-tokens]");
    register_premib_handler("snmp","mibfile",
					handle_mibfile_conf, NULL,
					"mib-to-read");
}
