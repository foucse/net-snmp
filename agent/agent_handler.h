#ifndef AGENT_HANDLER_H
#define AGENT_HANDLER_H

#ifdef __cplusplus
extern "C" {
#endif

struct handler_registration_s;

typedef struct mib_handler_s {
   char   *handler_name;
   void   *myvoid;       /* for handler's internal use */

   int (*access_method)(struct mib_handler_s *,
                        struct handler_registration_s *,
                        struct agent_request_info_s   *,
                        struct request_info_s         *);

   struct mib_handler_s *next;
   struct mib_handler_s *prev;
} mib_handler;

/* root registration info */
typedef struct handler_registration_s {

   char   *handlerName;  /* for mrTable listings, and other uses */
   char   *contextName;  /* NULL = default context */

   /* where are we registered at? */
   oid    *rootoid;
   size_t  rootoid_len;

   /* handler details */
   mib_handler *handler;
   
   /* more optional stuff */
   int     priority;
   int     range_subid;
   oid     range_ubound;
   int     timeout;

} handler_registration;

/* function handler definitions */
typedef int (NodeHandler)(
    mib_handler               *handler,
    handler_registration      *reginfo, /* pointer to registration struct */
    agent_request_info        *reqinfo, /* pointer to current transaction */
    request_info              *requests
    );

typedef struct delegated_cache_s {
   mib_handler               *handler;
   handler_registration      *reginfo;
   agent_request_info        *reqinfo;
   request_info              *requests;
   void                      *localinfo;
} delegated_cache;

/* handler API functions */
int register_handler(handler_registration *reginfo);
int inject_handler(handler_registration *reginfo, mib_handler *handler);
mib_handler *find_handler_by_name(handler_registration *reginfo, char *name);
void *find_handler_data_by_name(handler_registration *reginfo, char *name);
int call_handlers(handler_registration *reginfo,
                  agent_request_info   *reqinfo,
                  request_info         *requests);
int call_handler(mib_handler          *next_handler,
                 handler_registration *reginfo,
                 agent_request_info   *reqinfo,
                 request_info         *requests);
int call_next_handler(mib_handler          *current,
                      handler_registration *reginfo,
                      agent_request_info   *reqinfo,
                      request_info         *requests);
mib_handler *create_handler(const char *name,
                            NodeHandler *handler_access_method);
handler_registration *
create_handler_registration(const char *name,
                            NodeHandler *handler_access_method,
                            oid *reg_oid, size_t reg_oid_len);
delegated_cache *
create_delegated_cache(mib_handler               *,
                       handler_registration      *,
                       agent_request_info        *,
                       request_info              *,
                       void                      *);

inline request_parent_data *handler_create_parent_data(const char *, void *,
                                                       Free_Parent_Data *);
void handler_add_parent_data(request_info *, request_parent_data *);
void *handler_get_parent_data(request_info *, const char *);
void free_parent_data_set(request_info *);  /* single */
void free_parent_data_sets(request_info *); /* multiple */

#ifdef __cplusplus
};
#endif

#endif /* AGENT_HANDLER_H */
