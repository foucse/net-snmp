/*
 * FILE: net-snmp.h
 * Definition file for the new net-snmp api and module approach.
 */

/*
 * Internal information about the state of the snmp session.
 */
struct snmp_internal_session {
    struct request_list *requests;/* Info about outstanding requests */
    struct request_list *requestsEnd; /* ptr to end of list */ 
    int (*hook_pre)  (struct snmp_session *, struct _snmp_transport *,
                      void *, int);
    int (*hook_parse)(struct snmp_session *, struct snmp_pdu *,
                      u_char *, size_t);
    int (*hook_post) (struct snmp_session *, struct snmp_pdu*, int);
    int (*hook_build)(struct snmp_session *, struct snmp_pdu *,
                      u_char *, size_t *);
    int (*check_packet) (u_char *, size_t);

    u_char *packet;
    size_t packet_len, packet_size;
};
  
/*
 * The list of active/open sessions.
 */
struct netsnmp_session {
  /* Pointers providing the list of sessions. */
  struct netsnmp_session *next, *prev;
  /* Pointer to provide information of the session.
   * This should be changed in a modular form
   * and the struct snmp_session is only for
   * backward compatibility.
   */
  struct snmp_session *session;
  /* Transport information of this session. */
  snmp_transport *transport;
  /* Internal session information containing
   * the callbacks and requests.
   * Should be a module (core module??).
   */
  struct snmp_internal_session *internal;
};

