#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"

#include "null.h"

int register_null(oid *loc, size_t loc_len) {
    handler_registration *reginfo;
    reginfo = SNMP_MALLOC_TYPEDEF(handler_registration);
    reginfo->handlerName = strdup("");
    reginfo->rootoid = loc;
    reginfo->rootoid_len = loc_len;
    reginfo->handler = create_handler("null", null_handler);
    return register_handler(reginfo);
}

int
null_handler(mib_handler               *handler,
             handler_registration      *reginfo,
             agent_request_info        *reqinfo,
             request_info              *requests) {
    DEBUGMSGTL(("helper:read_only", "Got request\n"));

    switch(reqinfo->mode) {
        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            return SNMP_ERR_NOTWRITABLE;
            
        default:
            return SNMP_ERR_NOERROR;
    }
}
