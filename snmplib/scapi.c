/*
 * scapi.c
 */

#include "scapi.h"





/*******************************************************************-o-******
 * sc_random
 *
 * Parameters:
 *	*buf		Pre-allocated buffer.
 *	*buflen 	Size of buffer.
 *      
 * Returns:
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	Any KMT error.
 */
int
sc_random(u_char *buf, u_int *buflen)
{
	int		rval = SNMPERR_SUCCESS;

EM(1); /* */

	rval = kmt_random(KMT_RAND_DEFAULT, buf, *buflen);
	if (rval < 0) {
		rval = SNMPERR_SC_GENERAL_FAILURE;
	} else {
		*buflen = rval;
		rval = SNMPERR_SUCCESS;
	}


	return rval;

}  /* end sc_random() */



/*******************************************************************-o-******
 * sc_generate_keyed_hash
 *
 * Parameters:
 *	  authtype	Type of authentication transform.
 *	 *key		Pointer to key (Kul) to use in keyed hash.
 *	  keylen	Length of key in bytes.
 *	 *message	Pointer to the message to hash.
 *	  msglen	Length of the message.
 *	**MAC		Will be returned with allocated bytes containg hash.
 *	 *maclen	Length of the hash buffer in bytes.
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 * A hash of the first msglen bytes of message using a keyed hash defined
 * by authtype is created and stored in MAC.  Allocated bytes for its
 * storage and its length, maclen, are returned.
 *
 * ASSUMED that the number of hash bits is a multiple of 8.
 *
 * FIX	Change authtype to be an OID.
 */
int
sc_generate_keyed_hash(	u_int authtype,         
			u_char *key,		u_int keylen,
			u_char *message,        u_int msglen,
			u_char *MAC,           u_int *maclen)
{
	int		rval = SNMPERR_SUCCESS;

EM(1); /* */
	
	/* FIX DO
		. sanity checking.
		. check for the key
		. add it if necessary
		. do a full authenticatoin, return all bits.
	 */

sc_generate_keyed_hash_quit:
	return rval;

}  /* end sc_generate_keyed_hash() */




/*******************************************************************-o-******
 * sc_check_keyed_hash
 *
 * Parameters:
 *	 authtype
 *	*key
 *	*message
 *	 msglen
 *	*MAC
 *	 maclen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_check_keyed_hash(	u_int authtype,		
			u_char *key,		u_int keylen,
			u_char *message,	u_int msglen,
			u_char *MAC,		u_int maclen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_check_keyed_hash_quit:
	return rval;

}  /* end sc_check_keyed_hash() */




/*******************************************************************-o-******
 * sc_encrypt
 *
 * Parameters:
 *	  privtype
 *	 *key
 *	  keylen
 *	 *plaintext
 *	  ptlen
 *	**ciphertext
 *	 *ctlen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_encrypt(	u_int privtype,	 	
		u_char *key,		u_int keylen,
		u_char *plaintext,	u_int ptlen,
		u_char **ciphertext,	u_int *ctlen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_encrypt_quit:
	return rval;

}  /* end sc_encrypt() */




/*******************************************************************-o-******
 * sc_decrypt
 *
 * Parameters:
 *	  privtype
 *	 *key
 *	  keylen
 *	 *ciphertext
 *	  ctlen
 *	**plaintext
 *	 *ptlen
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
int
sc_decrypt(	u_int privtype,	 	
		u_char *key,		u_int keylen,
		u_char *ciphertext,	u_int ctlen,
		u_char **plaintext,	u_int *ptlen)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

sc_decrypt_quit:
	return rval;

}  /* end sc_decrypt() */

