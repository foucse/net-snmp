/*
 * scapi.h
 */

#ifndef _SCAPI_H
#define _SCAPI_H

/* 
 * Authentication transforms and bitlengths.
 */
#define	SNMP_TRANS_AUTH_HMACMD5_96	1
#define	SNMP_TRANS_AUTH_HMACSHA1_96	2

#define SNMP_TRANS_AUTHLEN_HMACMD5	128
#define SNMP_TRANS_AUTHLEN_HMACSHA1	160


/*
 * Privacy transforms and bitlengths.
 */
#define	SNMP_TRANS_PRIV_1DES		1

#define SNMP_TRANS_PRIVLEN_1DES		64



/*
 * Prototypes.
 */
int	sc_random __P((	u_char *buf, u_int *buflen));

int	sc_generate_keyed_hash __P((
		u_int authtype,	
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int *maclen));

int	sc_check_keyed_hash __P((
		u_int authtype,	
		u_char *key,		u_int keylen,
		u_char *message,	u_int msglen,
		u_char *MAC,		u_int maclen));

int	sc_encrypt __P((	u_int privtype,	 	
				u_char *key,		u_int keylen,
				u_char *plaintext,	u_int ptlen,
				u_char **ciphertext,	u_int *ctlen));

int	sc_decrypt __P((	u_int privtype,		
				u_char *key,		u_int keylen,
				u_char *ciphertext,	u_int ctlen,
				u_char **plaintext,	u_int *ptlen));

#endif	/* _SCAPI_H */

