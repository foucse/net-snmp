#include <config.h>

#include <sys/types.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#include <mibincl.h>
#include <data_list.h>
#include <snmp_agent.h>
#include <agent_registry.h>
#include <agent_handler.h>
/***********************************************************************/
/* New Handler based API */
/***********************************************************************/

/** register a handler, as defined by the handler_registration pointer */ 
int
register_handler(handler_registration *reginfo) {
    mib_handler *handler;
    DEBUGIF("handler::register") {
        DEBUGMSGTL(("handler::register", "Registering"));
        for(handler = reginfo->handler; handler;
            handler = handler->next) {
            DEBUGMSG(("handler::register"," %s", handler->handler_name));
        }
            
        DEBUGMSG(("handler::register", " at "));
        if (reginfo->rootoid) {
            DEBUGMSGOID(("handler::register", reginfo->rootoid,
                         reginfo->rootoid_len));
        } else {
            DEBUGMSG(("handler::register", "[null]"));
        }
        DEBUGMSG(("handler::register", "\n"));
    }

    /* don't let them register for absolutely nothing.  Probably a mistake */
    if (0 == reginfo->modes) {
        reginfo->modes = HANDLER_CAN_DEFAULT;
    }

    return register_mib_context2(reginfo->handler->handler_name,
                         NULL, 0, 0,
                         reginfo->rootoid, reginfo->rootoid_len,
                         reginfo->priority,
                         reginfo->range_subid, reginfo->range_ubound,
                         NULL,
                         reginfo->contextName,
                         reginfo->timeout,
                         0, reginfo);
}

/** inject a new handler into the calling chain of the handlers
   definedy by the handler_registration pointer.  The new handler is
   injected at the top of the list and hence will be the new handler
   to be called first.*/ 
int
inject_handler(handler_registration *reginfo, mib_handler *handler) {
    DEBUGMSGTL(("handler:inject", "injecting %s before %s\n", \
                handler->handler_name, reginfo->handler->handler_name));
    handler->next = reginfo->handler;
    if (reginfo->handler)
        reginfo->handler->prev = handler;
    reginfo->handler = handler;
    return SNMPERR_SUCCESS;
}

int call_handlers(handler_registration *reginfo,
                  agent_request_info   *reqinfo,
                  request_info         *requests) {
    NodeHandler *nh;
    int status;
    
    if (reginfo == NULL || reqinfo == NULL || requests == NULL) {
        snmp_log(LOG_ERR, "call_handlers() called illegally");
        return  SNMP_ERR_GENERR;
    }

    if (reginfo->handler == NULL) {
        snmp_log(LOG_ERR, "no handler specified.");
        return  SNMP_ERR_GENERR;
    }

    switch(reqinfo->mode) {
        case MODE_GET:
        case MODE_GETNEXT:
            if (!(reginfo->modes & HANDLER_CAN_GETANDGETNEXT))
                return SNMP_ERR_NOERROR; /* legal */
            break;

        case MODE_SET_RESERVE1:
        case MODE_SET_RESERVE2:
        case MODE_SET_ACTION:
        case MODE_SET_COMMIT:
        case MODE_SET_FREE:
        case MODE_SET_UNDO:
            if (!(reginfo->modes & HANDLER_CAN_SET)) {
                for(; requests; requests = requests->next) {
                    set_request_error(reqinfo, requests, SNMP_ERR_NOTWRITABLE);
                }
                return SNMP_ERR_NOERROR;
            }
            break;

        case MODE_GETBULK:
            if (!(reginfo->modes & HANDLER_CAN_GETBULK))
                return SNMP_ERR_NOERROR; /* XXXWWW: should never get
                                            here after we force a
                                            getbulk->getnext helper on
                                            them during registration
                                            process. */
            break;
            
        default:
            snmp_log(LOG_ERR, "unknown mode in call_handlers! bug!\n");
            return SNMP_ERR_GENERR;
    }
    DEBUGMSGTL(("handler:calling", "calling main handler %s\n",
                 reginfo->handler->handler_name));
    
    nh = reginfo->handler->access_method;
    if (!nh) {
        snmp_log(LOG_ERR, "no handler access method specified.");
        return SNMP_ERR_GENERR;
    }

    /* XXX: define acceptable return statuses */
    status = (*nh)(reginfo->handler, reginfo, reqinfo, requests);

    return status;
}

/** calls a handler with with appropriate NULL checking, etc. */
inline int call_handler(mib_handler          *next_handler,
                        handler_registration *reginfo,
                        agent_request_info   *reqinfo,
                        request_info         *requests) {
    NodeHandler *nh;
    int ret;
    
    if (next_handler == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        snmp_log(LOG_ERR, "call_next_handler() called illegally");
        return  SNMP_ERR_GENERR;
    }

    nh = next_handler->access_method;
    if (!nh) {
        snmp_log(LOG_ERR, "no access method specified in handler %s.",
                 next_handler->handler_name);
        return SNMP_ERR_GENERR;
    }

    DEBUGMSGTL(("handler:calling", "calling handler %s\n",
                 next_handler->handler_name));

    ret = (*nh)(next_handler, reginfo, reqinfo, requests);

    DEBUGMSGTL(("handler:returned", "handler %s returned %d\n",
                 next_handler->handler_name, ret));

    return ret;
}

/** calls the next handler in the chain after the current one with
   with appropriate NULL checking, etc. */
inline int call_next_handler(mib_handler          *current,
                             handler_registration *reginfo,
                             agent_request_info   *reqinfo,
                             request_info         *requests) {

    if (current == NULL || reginfo == NULL || reqinfo == NULL ||
        requests == NULL) {
        snmp_log(LOG_ERR, "call_next_handler() called illegally");
        return  SNMP_ERR_GENERR;
    }

    return call_handler(current->next, reginfo, reqinfo, requests);
}

/** creates a mib_handler structure given a name and a access method */
mib_handler *
create_handler(const char *name, NodeHandler *handler_access_method) {
    mib_handler *ret = SNMP_MALLOC_TYPEDEF(mib_handler);
    ret->handler_name = strdup(name);
    ret->access_method = handler_access_method;
    return ret;
}

/** creates a handler registration structure given a name, a
    access_method function, a registration location oid and the modes
    the handler supports. If modes == 0, then modes will automatically
    be set to the default value of only HANDLER_CAN_DEFAULT, which is by default. */
handler_registration *
create_handler_registration(const char *name,
                            NodeHandler *handler_access_method,
                            oid *reg_oid, size_t reg_oid_len,
                            int modes) {
    handler_registration *the_reg;
    the_reg = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!the_reg)
        return NULL;

    if (modes)
        the_reg->modes = modes;
    else
        the_reg->modes = HANDLER_CAN_DEFAULT;

    the_reg->handler = create_handler(name, handler_access_method);
    memdup(&the_reg->rootoid, reg_oid, reg_oid_len * sizeof(int));
    the_reg->rootoid_len = reg_oid_len;
    return the_reg;
}

/** creates a cache of information which can be saved for future
   reference.  Use handler_check_cache() later to make sure it's still
   valid before referencing it in the future. */
inline delegated_cache *
create_delegated_cache(mib_handler               *handler,
                       handler_registration      *reginfo,
                       agent_request_info        *reqinfo,
                       request_info              *requests,
                       void                      *localinfo) {
    delegated_cache *ret;

    ret = SNMP_MALLOC_TYPEDEF(delegated_cache);
    if (ret) {
        ret->transaction_id = reqinfo->asp->pdu->transid;
        ret->handler = handler;
        ret->reginfo = reginfo;
        ret->reqinfo = reqinfo;
        ret->requests = requests;
        ret->localinfo = localinfo;
    }
    return ret;
}

/** check's a given cache and returns it if it is still valid (ie, the
   agent still considers it to be an outstanding request.  Returns
   NULL if it's no longer valid. */
inline delegated_cache *
handler_check_cache(delegated_cache *dcache)
{
    if (!dcache)
        return dcache;
    
    if (check_transaction_id(dcache->transaction_id) == SNMPERR_SUCCESS)
        return dcache;

    return NULL;
}

/** marks a list of requests as delegated (or not if isdelegaded = 0) */
void
handler_mark_requests_as_delegated(request_info *requests, int isdelegated) 
{
    while(requests) {
        requests->delegated = isdelegated;
        requests = requests->next;
    }
}

inline void
request_add_list_data(request_info *request, data_list *node) 
{
  if (request) {
    if (request->parent_data)
      add_list_data(&request->parent_data, node);
    else
      request->parent_data = node;
  }
}

inline void *
request_get_list_data(request_info *request, const char *name)
{
  if (request)
    return get_list_data(request->parent_data,name);
  return NULL;
}

inline void
free_request_data_set(request_info *request)
{
  if (request)
    free_list_data(request->parent_data);
}

inline void
free_request_data_sets(request_info *request) 
{
  if (request)
    free_all_list_data(request->parent_data);
}

/** Returns a handler from a chain based on the name */
mib_handler *
find_handler_by_name(handler_registration *reginfo, char *name) 
{
    mib_handler *it;
    for(it = reginfo->handler; it; it = it->next) {
        if (strcmp(it->handler_name, name) == 0) {
            return it;
        }
    }
    return NULL;
}

/** Returns a handler's void * pointer from a chain based on the name.
 This probably shouldn't be used by the general public as the void *
 data may change as a handler evolves.  Handlers should really
 advertise some function for you to use instead. */
void *
find_handler_data_by_name(handler_registration *reginfo,
                          char *name) 
{
    mib_handler *it = find_handler_by_name(reginfo, name);
    if (it)
        return it->myvoid;
    return NULL;
}

