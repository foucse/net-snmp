
#ifndef   _SEC_MODEL_SECMOD_H
#define   _SEC_MODEL_SECMOD_H


    /*
     * Assorted Security-Model-specific handling routines
     */
typedef int  (SecmodSessionCallback) (netsnmp_session *);
typedef int  (SecmodPduCallback)     (netsnmp_pdu *);
typedef int  (Secmod2PduCallback)    (netsnmp_pdu *, netsnmp_pdu *);
typedef int  (SecmodOutMsg)          (netsnmp_session *sess, netsnmp_pdu *pdu, netsnmp_buf *buf);
typedef netsnmp_pdu* (SecmodInMsg) (netsnmp_buf *buf, netsnmp_v3info *v3info, netsnmp_buf *wholeMsg);
typedef void (SecmodFreeState)       (void *);
typedef int  (SecmodPrint)           (netsnmp_buf *buf, void *info);

typedef void* (SecmodClone)          (void *);

/*
 * definition of a security module
 */

    /*
     * Security Model structure
     *
     * Encoding/Decoding routines are mandatory.
     * The rest are optional, and are only called if defined.
     */
typedef struct netsnmp_secmod_s netsnmp_secmod;
struct netsnmp_secmod_s {
    int             sec_model;
    netsnmp_secmod *prev, *next;

    SecmodOutMsg   *encode_hook;
    SecmodInMsg    *decode_hook;

    SecmodFreeState  *sm_free;
    SecmodClone      *sm_clone;
    SecmodPrint      *sm_print;

    /*
     * session manipulation (optional)
     */
    SecmodSessionCallback *session_open;      /* called in snmp_sess_open()  */
    SecmodSessionCallback *session_close;     /* called in snmp_sess_close() */

    /*
     * PDU manipulation (optional)
     */
    SecmodPduCallback     *pdu_free;           /* called in free_pdu() */
    Secmod2PduCallback    *pdu_clone;          /* called in snmp_clone_pdu() */
    SecmodPduCallback     *pdu_timeout;        /* called when request timesout */
    SecmodFreeState       *pdu_free_state_ref; /* frees pdu->securityStateRef */
};


void            secmod_init(void);
netsnmp_secmod *secmod_new(       int  /* XXX..... */ );
void            secmod_free(                         netsnmp_secmod *);
int             secmod_register(  int, const char *, netsnmp_secmod *);
int             secmod_unregister(int);
netsnmp_secmod *secmod_find(      int);

#endif /* _SEC_MODEL_SECMOD_H */

