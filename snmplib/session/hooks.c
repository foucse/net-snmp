/*******************************
 *
 *      session/hooks.c
 *
 *      Net-SNMP library - SNMP Session interface
 *
 *	Routines for handling 'hook handler' structures
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

#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif

#include <net-snmp/struct.h>
#include <net-snmp/utils.h>
#include <net-snmp/error.h>
#include <net-snmp/protocol_api.h>

#include "session/session.h"

                /**************************************
                 *
                 *      Public API
                 *         (see <net-snmp/session_api.h>)
                 *
                 **************************************/
                /** @package session_api */


netsnmp_hooks*
hooks_new(NetSnmpPreParseHook  *hook_pre,
         NetSnmpParseHook     *hook_parse,
         NetSnmpPostParseHook *hook_post,
         NetSnmpBuildHook     *hook_build,
         NetSnmpCheckHook     *check_packet,
         NetSnmpCallback      *callback,
         void                 *callback_magic)
{
    netsnmp_hooks *hp;

    hp = (netsnmp_hooks *)calloc(1, sizeof(netsnmp_hooks));
    if (NULL != hp) {
        hp->hook_pre     = hook_pre;
        hp->hook_parse   = hook_parse;
        hp->hook_post    = hook_post;
        hp->hook_build   = hook_build;
        hp->check_packet = check_packet;
        hp->callback     = callback;
        hp->callback_magic = callback_magic;
    }
    return hp;
}

netsnmp_hooks*
hooks_copy(netsnmp_hooks *hooks)
{
    if (NULL == hooks) {
        return NULL;
    }
    return hooks_new(hooks->hook_pre,
                    hooks->hook_parse,
                    hooks->hook_post,
                    hooks->hook_build,
                    hooks->check_packet,
                    hooks->callback,
                    hooks->callback_magic);
}
