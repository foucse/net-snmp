#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "serialize.h"

#if HAVE_DMALLOC_H
#include <dmalloc.h>
#endif

mib_handler *
get_serialize_handler(void) {
    return create_handler("serialize", serialize_helper_handler);
}

int
register_serialize(handler_registration *reginfo) {
    inject_handler(reginfo, get_serialize_handler());
    return register_handler(reginfo);
}

int
serialize_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    request_info              *request;

    DEBUGMSGTL(("helper:serialize", "Got request:\n"));
    /* loop through requests */
    for(request = requests; request; request = request->next) {
        int ret;
        
        ret = call_next_handler(handler, reginfo, reqinfo, requests);
        if (ret != SNMP_ERR_NOERROR)
            return ret;
    }

    return SNMP_ERR_NOERROR;
}
