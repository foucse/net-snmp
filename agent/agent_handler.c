#include <config.h>

#include <sys/types.h>

#if HAVE_STRING_H
#include <string.h>
#endif

#include <mibincl.h>
#include <snmp_agent.h>
#include <agent_registry.h>
#include <agent_handler.h>
/***********************************************************************/
/* New Handler based API */
/***********************************************************************/

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
        
    DEBUGMSGTL(("handler:calling", "calling handler %s\n",
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

inline int call_handler(mib_handler          *next_handler,
                        handler_registration *reginfo,
                        agent_request_info   *reqinfo,
                        request_info         *requests) {
    NodeHandler *nh;
    
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

    return (*nh)(next_handler, reginfo, reqinfo, requests);
}

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

mib_handler *
create_handler(const char *name, NodeHandler *handler_access_method) {
    mib_handler *ret = SNMP_MALLOC_TYPEDEF(mib_handler);
    ret->handler_name = strdup(name);
    ret->access_method = handler_access_method;
    return ret;
}

handler_registration *
create_handler_registration(const char *name,
                            NodeHandler *handler_access_method,
                            oid *reg_oid, size_t reg_oid_len) {
    handler_registration *the_reg;
    the_reg = SNMP_MALLOC_TYPEDEF(handler_registration);
    if (!the_reg)
        return NULL;

    the_reg->handler = create_handler(name, handler_access_method);
    the_reg->rootoid = reg_oid;
    the_reg->rootoid_len = reg_oid_len;
    return the_reg;
}

inline delegated_cache *
create_delegated_cache(mib_handler               *handler,
                       handler_registration      *reginfo,
                       agent_request_info        *reqinfo,
                       request_info              *requests,
                       void                      *localinfo) {
    delegated_cache *ret;

    ret = SNMP_MALLOC_TYPEDEF(delegated_cache);
    if (ret) {
        ret->handler = handler;
        ret->reginfo = reginfo;
        ret->reqinfo = reqinfo;
        ret->requests = requests;
        ret->localinfo = localinfo;
    }
    return ret;
}

inline request_parent_data *
handler_create_parent_data(const char *parent_name, void *parent_data,
    Free_Parent_Data *beer)
{
    request_parent_data *data = SNMP_MALLOC_TYPEDEF(request_parent_data);
    if (!data)
        return NULL;
    data->parent_name = strdup(parent_name);
    data->data = parent_data;
    data->free_func = beer;
    return data;
}
   
    
inline void
handler_add_parent_data(request_info *request, request_parent_data *data) 
{
    
    data->next = request->parent_data;
    request->parent_data = data;
}

inline void *
handler_get_parent_data(request_info *request, char *parent_name)
{
    request_parent_data *ptr;
    for(ptr = request->parent_data;
        ptr && strcmp(ptr->parent_name, parent_name) != 0; ptr = ptr->next);
    return ptr->data;
}

inline void
free_parent_data_set(request_info *request)
{
    Free_Parent_Data *beer;
    request_parent_data *data;

    for(data = request->parent_data; data; data = data->next) {
        beer = data->free_func;
        if (beer)
            (beer)(data->data);
        SNMP_FREE(data->parent_name);
    }
}

inline void
free_parent_data_sets(request_info *request) 
{
    for(; request; request = request->next) {
        free_parent_data_set(request);
    }
}

