#ifndef AGENT_REGISTRY_H
#define AGENT_REGISTRY_H

/***********************************************************************/
/* new version2 agent handler API structures */
/***********************************************************************/

#include "snmp_agent.h"

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
delegated_cache *
create_delegated_cache(mib_handler               *,
                       handler_registration      *,
                       agent_request_info        *,
                       request_info              *,
                       void                      *);


/***********************************************************************/
/* requests api definitions */
/***********************************************************************/

/* the structure of parameters passed to registered ACM modules */
struct view_parameters {
   struct snmp_pdu *pdu;
   oid             *name;
   size_t           namelen;
   int              errorcode; /* do not change unless you're
                                  specifying an error,
                                  as it starts in a success state. */
};

struct register_parameters {
   oid    *name;
   size_t  namelen;
   int     priority;
   int     range_subid;
   oid     range_ubound;
   int     timeout;
   u_char  flags;
};

#define MIB_REGISTERED_OK		 0
#define MIB_DUPLICATE_REGISTRATION	-1
#define MIB_REGISTRATION_FAILED		-2

#define MIB_UNREGISTERED_OK		 0
#define MIB_NO_SUCH_REGISTRATION	-1
#define MIB_UNREGISTRATION_FAILED	-2

#define DEFAULT_MIB_PRIORITY		127


void setup_tree (void);
struct subtree *find_subtree (oid *, size_t, struct subtree *);
struct subtree *find_subtree_next (oid *, size_t, struct subtree *);
struct subtree *find_subtree_previous (oid *, size_t, struct subtree *);
struct snmp_session *get_session_for_oid( oid *, size_t);

int register_mib(const char *, struct variable *, size_t, size_t, oid *, size_t);
int register_mib_priority(const char *, struct variable *, size_t, size_t, oid *, size_t, int);
int register_mib_range(const char *, struct variable *, size_t , size_t , oid *, size_t, int, int, oid, struct snmp_session *);
int register_mib_context(const char *, struct variable *, size_t , size_t , oid *, size_t, int, int, oid, struct snmp_session *, const char*, int, int);

int register_mib_table_row(const char *, struct variable *, size_t, size_t, oid *, size_t, int, int, struct snmp_session *, const char *, int, int);
int unregister_mib (oid *, size_t);
int unregister_mib_priority (oid *, size_t, int);
int unregister_mib_range (oid *, size_t, int, int, oid);
int unregister_mib_context (oid *, size_t, int, int, oid, const char*);
void unregister_mibs_by_session (struct snmp_session *);

struct subtree *free_subtree (struct subtree *);
int compare_tree (const oid *, size_t, const oid *, size_t);
int in_a_view(oid *, size_t *, struct snmp_pdu *, int);
int check_access(struct snmp_pdu *pdu);
void register_mib_reattach(void);

/* REGISTER_MIB(): This macro simply loads register_mib with less pain:

   descr:   A short description of the mib group being loaded.
   var:     The variable structure to load.
   vartype: The variable structure used to define it (variable2, variable4, ...)
   theoid:  A *initialized* *exact length* oid pointer.
            (sizeof(theoid) *must* return the number of elements!) 
*/
#define REGISTER_MIB(descr, var, vartype, theoid)                      \
  if (register_mib(descr, (struct variable *) var, sizeof(struct vartype), \
               sizeof(var)/sizeof(struct vartype),                     \
               theoid, sizeof(theoid)/sizeof(oid)) != MIB_REGISTERED_OK ) \
	DEBUGMSGTL(("register_mib", "%s registration failed\n", descr));


#define NUM_EXTERNAL_FDS 32

#define FD_REGISTERED_OK		 0
#define FD_REGISTRATION_FAILED		-2

#define FD_UNREGISTERED_OK		 0
#define FD_NO_SUCH_REGISTRATION		-1

extern int external_readfd[NUM_EXTERNAL_FDS], external_readfdlen;
extern int external_writefd[NUM_EXTERNAL_FDS], external_writefdlen;
extern int external_exceptfd[NUM_EXTERNAL_FDS], external_exceptfdlen;

extern void (* external_readfdfunc[NUM_EXTERNAL_FDS])(int, void *);
extern void (* external_writefdfunc[NUM_EXTERNAL_FDS])(int, void *);
extern void (* external_exceptfdfunc[NUM_EXTERNAL_FDS])(int, void *);

extern void *external_readfd_data[NUM_EXTERNAL_FDS];
extern void *external_writefd_data[NUM_EXTERNAL_FDS];
extern void *external_exceptfd_data[NUM_EXTERNAL_FDS];

int register_readfd(int, void (*func)(int, void *), void *);
int register_writefd(int, void (*func)(int, void *), void *);
int register_exceptfd(int, void (*func)(int, void *), void *);
int unregister_readfd(int);
int unregister_writefd(int);
int unregister_exceptfd(int);


#define SIG_REGISTERED_OK		 0
#define SIG_REGISTRATION_FAILED		-2

#define SIG_UNREGISTERED_OK		 0

#define NUM_EXTERNAL_SIGS 32

extern int external_signal_scheduled[NUM_EXTERNAL_SIGS];
extern void (* external_signal_handler[NUM_EXTERNAL_SIGS])(int);

int register_signal(int, void (*func)(int));
int unregister_signal(int);

#ifdef __cplusplus
};
#endif

#endif /* AGENT_REGISTRY_H */
