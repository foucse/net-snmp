/*
 * snmp_agent.h
 *
 * External definitions for functions and variables in snmp_agent.c.
 */

#ifndef SNMP_AGENT_H
#define SNMP_AGENT_H

#define SNMP_MAX_PDU_SIZE 64000 /* local constraint on PDU size sent by agent
                                  (see also SNMP_MAX_MSG_SIZE in snmp_api.h) */

/*  If non-zero, causes the addresses of peers to be logged when receptions
    occur.  */

extern int	log_addresses;

/*  How many ticks since we last aged the address cache entries.  */

extern int	lastAddrAge;

typedef struct request_info_s {
   struct variable_list *requestvb; /* will certainly change */
   void *parent_data;               /* can be used to pass information
                                       on a per-request basis from a
                                       helper to the final handler */
   void *state_reference;           /* if multiple calls to you are
                                       needed for a request (SETs
                                       namely), this can be used to
                                       store data between calls */
   int processed;
   int status;
   struct request_info_s         *next;
   struct request_info_s         *prev;
} request_info;

typedef struct _set_info {
   int   action;
   void *stateRef;

/* don't use yet: */
   void **oldData;
   int   setCleanupFlags;
#define AUTO_FREE_STATEREF 0x01 /* calls free(stateRef) */
#define AUTO_FREE_OLDDATA  0x02 /* calls free(*oldData) */
#define AUTO_UNDO          0x03 /* ... */
} set_info;

typedef struct tree_cache_s {
   struct subtree *subtree;
   request_info *requests_begin;
   request_info *requests_end;
} tree_cache;

/* (will likely change later) */
#define MODE_GET              SNMP_MSG_GET
#define MODE_GETNEXT          SNMP_MSG_GETNEXT
#define MODE_GETBULK          SNMP_MSG_GETBULK
#define MODE_SET_BEGIN        -1
#define MODE_SET_RESERVE1     RESERVE1
#define MODE_SET_RESERVE2     RESERVE2
#define MODE_SET_ACTION       ACTION
#define MODE_SET_COMMIT       COMMIT
#define MODE_SET_FREE         FREE
#define MODE_SET_UNDO         UNDO

typedef struct agent_request_info_s {
   int    mode;
   struct snmp_pdu *pdu;                 /* pdu contains authinfo, eg */
   struct agent_snmp_session *asp;       /* may not be needed */
   /* ... */
} agent_request_info;

struct agent_snmp_session {
    int		mode;
    struct variable_list *start, *end;
    struct snmp_session  *session;
    struct snmp_pdu      *pdu;
    struct snmp_pdu      *orig_pdu;
    int		rw;
    int		exact;
    int		status;
    int		index;
    
    struct request_list *outstanding_requests;
    struct agent_snmp_session *next;

   /* new API pointers */
   agent_request_info *reqinfo;
   tree_cache **treecache;
   int treecache_len; /* length of cache array */
   int treecache_num; /* number of current cache entries */
};

/*  Address cache handling functions.  */

void 		snmp_addrcache_initialise	(void);
void		snmp_addrcache_age		(void);


/* config file parsing routines */
int handle_snmp_packet(int, struct snmp_session *, int, struct snmp_pdu *, void *);
int handle_next_pass( struct agent_snmp_session *);
int handle_var_list( struct agent_snmp_session *);
int handle_one_var( struct agent_snmp_session *, struct variable_list *varbind_ptr);
void snmp_agent_parse_config (char *, char *);
struct agent_snmp_session  *init_agent_snmp_session( struct snmp_session *, struct snmp_pdu *);
void free_agent_snmp_session( struct agent_snmp_session * );
void remove_and_free_agent_snmp_session(struct agent_snmp_session *asp);
void free_agent_snmp_session_by_session(struct snmp_session *sess,
				  void (*free_request)(struct request_list *));
int getNextSessID(void);
void dump_sess_list(void);
int init_master_agent(void);
int agent_check_and_process(int block);
struct agent_snmp_session  *get_current_agent_session(void);
void check_outstanding_agent_requests(int status);

/*  Register and de-register agent NSAPs.  */
 
struct _snmp_transport;
 
int	register_agent_nsap	(struct _snmp_transport *t);
void	deregister_agent_nsap	(int handle);

#endif
