#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif

#include "mibincl.h"
#include "tools.h"
#include "snmp_agent.h"
#include "instance.h"
#include "serialize.h"

mib_handler *
get_instance_handler(void) {
    return create_handler("instance", instance_helper_handler);
}

int
register_instance(handler_registration *reginfo) {
    inject_handler(reginfo, get_instance_handler());
    return register_serialize(reginfo);
}

int
instance_helper_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    struct variable_list *var = requests->requestvb;

    int ret, cmp;
    
    DEBUGMSGTL(("helper:instance", "Got request:\n"));
    cmp = snmp_oid_compare(requests->requestvb->name,
                           requests->requestvb->name_length,
                           reginfo->rootoid,
                           reginfo->rootoid_len);
        
    DEBUGMSGTL(("helper:instance", "  oid:", cmp));
    DEBUGMSGOID(("helper:instance", var->name, var->name_length));
    DEBUGMSG(("helper:instance", "\n"));

    switch(reqinfo->mode) {
        case MODE_GET:
            if (cmp != 0) {
                var->type = SNMP_NOSUCHOBJECT;
                return SNMP_ERR_NOERROR;
            } else {
                return call_next_handler(handler, reginfo, reqinfo, requests);
            }
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_UNDO:
        case MODE_SET_FREE:
            if (cmp != 0) {
                return SNMP_NOSUCHOBJECT;
            } else {
                return call_next_handler(handler, reginfo, reqinfo, requests);
            }
            break;
            
        case MODE_GETNEXT:
            if (cmp < 0) {
                reqinfo->mode = MODE_GET;
                snmp_set_var_objid(requests->requestvb, reginfo->rootoid,
                                   reginfo->rootoid_len);
                ret = call_next_handler(handler, reginfo, reqinfo, requests);
                reqinfo->mode = MODE_GETNEXT;
                return ret;
            } else {
                return SNMP_ERR_NOERROR;
            }
            break;
    }
    /* got here only if illegal mode found */
    return SNMP_ERR_GENERR;
}

