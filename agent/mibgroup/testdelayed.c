#include <config.h>

#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#include <unistd.h>

#include "mibincl.h"
#include "testdelayed.h"
#include "snmp_agent.h"
#include "snmp_alarm.h"

#include "snmp_api.h"
#include "helpers/table.h"
#include "helpers/instance.h"
#include "helpers/serialize.h"

static oid my_delayed_oid[5] = {1,2,3,99,1};

static u_long accesses = 0;

void
init_testdelayed(void) {
    /*
     * delayed handler test
     */
    handler_registration *my_test;
    my_test = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!my_test)
        return;

    my_test->rootoid = my_delayed_oid;
    my_test->rootoid_len = 4; /* [sic] */
    my_test->handler = create_handler("myDelayed", my_test_delayed_handler);

    register_serialize(my_test);

}

u_long sleeptime = 1;

void
return_delayed_response(unsigned int clientreg, void *clientarg) {
    delegated_cache *cache = (delegated_cache *) clientarg;
    request_info              *requests = cache->requests;
    agent_request_info        *reqinfo  = cache->reqinfo;
    struct agent_snmp_session *asp      = reqinfo->asp;
    int cmp;
    
    DEBUGMSGTL(("testdelayed", "continuing delayed request, mode = %d\n",
                cache->reqinfo->mode));

    if (!cache) {
        snmp_log(LOG_ERR,"illegal call to return delayed response\n");
        return;
    }
    
    switch(cache->reqinfo->mode) {
        case MODE_GET:
            if (requests->requestvb->name_length == 5 &&
                snmp_oid_compare(requests->requestvb->name, 4,
                                 my_delayed_oid, 4) == 0 &&
                requests->requestvb->name[4] < 5) {
                snmp_set_var_typed_value(cache->requests->requestvb,
                                         ASN_INTEGER,
                                         (u_char *) &accesses,
                                         sizeof(accesses));
            } else {
                requests->requestvb->type = SNMP_NOSUCHOBJECT;
            }
            break;
            
        case MODE_GETNEXT:
            cmp = snmp_oid_compare(requests->requestvb->name, 4,
                                   my_delayed_oid, 4);
            if (cmp == 0) {
                if (requests->requestvb->name_length < 5) {
                    snmp_set_var_objid(requests->requestvb,
                                       my_delayed_oid, 5); /* [sic] */
                    requests->requestvb->name[4] = 1;
                    snmp_set_var_typed_value(requests->requestvb,
                                             ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
                } else {
                    if (requests->requestvb->name[4] < 5) {
                        requests->requestvb->name[4]++;
                        requests->requestvb->name_length = 5;
                        snmp_set_var_typed_value(requests->requestvb,
                                                 ASN_INTEGER,
                                                 (u_char *) &accesses,
                                                 sizeof(accesses));
                    } else {
                        requests->requestvb->type = ASN_NULL;
                    }
                }
            } else if (cmp < 0) {
                    snmp_set_var_objid(requests->requestvb,
                                       my_delayed_oid, 5);
                    requests->requestvb->name[4] = 1;
                    snmp_set_var_typed_value(requests->requestvb,
                                             ASN_INTEGER,
                                             (u_char *) &accesses,
                                             sizeof(accesses));
            } else {
                requests->requestvb->type = ASN_NULL;
            }
            break;

        case MODE_SET_RESERVE1:
            /* check type */
            if (requests->requestvb->type != ASN_INTEGER) {
                asp->status = SNMP_ERR_WRONGTYPE;
                return;
            }
            break;

        case MODE_SET_RESERVE2:
            /* store old info for undo later */
            memdup((u_char **) &requests->state_reference,
                   (u_char *) &sleeptime, sizeof(sleeptime));
            if (requests->state_reference == NULL) {
                asp->status = SNMP_ERR_RESOURCEUNAVAILABLE;
                return;
            }
            break;

        case MODE_SET_ACTION:
            /* update current */
            sleeptime = *(requests->requestvb->val.integer);
            DEBUGMSGTL(("testhandler","updated accesses -> %d\n", accesses));
            break;
            
        case MODE_SET_UNDO:
            sleeptime = *((u_long *) requests->state_reference);
            /* fall through */

        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
            SNMP_FREE(requests->state_reference);
            break;
    }
    accesses++;
}

int
my_test_delayed_handler(
    mib_handler               *handler,
    handler_registration      *reginfo,
    agent_request_info        *reqinfo,
    request_info              *requests) {

    DEBUGMSGTL(("testdelayed", "Got request, mode = %d:\n", reqinfo->mode));

    switch(reqinfo->mode) {
        case MODE_GET:
        case MODE_GETNEXT:
            /* mark this variable as something that can't be handled now */
            requests->requestvb->type = ASN_PRIV_DELEGATED;
            /* register an alarm to update the results at a later time */
            snmp_alarm_register(sleeptime, 0, return_delayed_response,
                                (void *)
                                create_delegated_cache(handler, reginfo,
                                                       reqinfo, requests,
                                                       NULL));
            break;

    }

    return SNMP_ERR_NOERROR;
}
