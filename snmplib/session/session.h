
int              session_read(         netsnmp_session *sess, fd_set *fdset);
netsnmp_request* session_find_request( netsnmp_session *sess, netsnmp_pdu *pdu);
void             session_handle_report(netsnmp_session *sess, netsnmp_pdu *pdu,
                                               netsnmp_request *rp);
void             pdu_release_security( netsnmp_pdu *pdu);

int
session_send(netsnmp_session         *sess,
		     netsnmp_pdu     *pdu,
		     NetSnmpCallback  callback,
		     void            *cb_data);
int
session_save_request(netsnmp_session *sess,
		     netsnmp_pdu     *pdu,
		     NetSnmpCallback  callback,
		     void            *cb_data);
netsnmp_pdu *synch_send(    netsnmp_session *sess, netsnmp_pdu *pdu, NetSnmpCallback *callback);
netsnmp_pdu *synch_response(netsnmp_session *sess, netsnmp_pdu *pdu);

netsnmp_request* request_new(netsnmp_session *sess,
            netsnmp_pdu     *pdu,
            NetSnmpCallback  callback,
            void            *cb_data,
            int              timeout);
int  request_resend(     netsnmp_session *sess, netsnmp_request *rp, int inc_retries);
void request_add_to_list(netsnmp_session *sess,                   netsnmp_request *rp);
void request_release(    netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_request *rp);
int request_set_timeout( netsnmp_request *rp, int timeout);

netsnmp_session* session_new( int version, netsnmp_transport *transport);
netsnmp_session* session_open(int version, char *peername, int local);
void             session_free(   netsnmp_session *sess);
void             session_close(  netsnmp_session *sess);
void             session_timeout(netsnmp_session *sess);
void
session_select(netsnmp_session *sess,
                 int *numfds,
		 fd_set *fdset,
		 struct timeval *timeout,
		 int *block);
void session_link(netsnmp_session *s1, netsnmp_session *s2);

int   session_bprint(netsnmp_buf *buf,       netsnmp_session *sess);
char *session_sprint(char *str_buf, int len, netsnmp_session *sess);
void  session_fprint(FILE *fp,               netsnmp_session *sess);
void  session_print (                        netsnmp_session *sess);

void session_clear_errors(netsnmp_session *sess);
void session_set_errors(  netsnmp_session *sess, int snmp_err, int sys_err, const char* detail);

netsnmp_hooks*
hooks_new(NetSnmpPreParseHook  *hook_pre,
         NetSnmpParseHook     *hook_parse,
         NetSnmpPostParseHook *hook_post,
         NetSnmpBuildHook     *hook_build,
         NetSnmpCheckHook     *check_packet,
         NetSnmpCallback      *callback,
         void                 *callback_magic);
netsnmp_hooks *hooks_copy(netsnmp_hooks *h);
