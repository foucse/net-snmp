#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "read_only.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

mib_handler *
get_read_only_handler(void) {
    return create_handler("read_only", read_only_helper);
}

int
read_only_helper(
    mib_handler               *handler,
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
            set_all_requests_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
            return SNMP_ERR_NOERROR;
            
        default:
            return call_next_handler(handler, reginfo, reqinfo, requests);
    }
    return SNMP_ERR_GENERR; /* should never get here */
}

