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

int sleeptime = 1;

void
return_delayed_response(unsigned int clientreg, void *clientarg) {
    delegated_cache *cache = (delegated_cache *) clientarg;
    request_info              *requests = cache->requests;
    int cmp;
    
    DEBUGMSGTL(("testdelayed", "continuing delayed request\n"));

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

        case MODE_SET_RESERVE1:
            /* check type */
            if (requests->requestvb->type != ASN_INTEGER)
                return SNMP_ERR_WRONGTYPE;
            break;

        case MODE_SET_COMMIT:
            /* update sleep time */
            /* XXX: check name */            
            sleeptime = *(requests->requestvb->val.integer);
            break;
            
    }

    return SNMP_ERR_NOERROR;
}
