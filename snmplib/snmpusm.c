/*
 * snmpusm.c
 *
 * Routines to manipulate a information about a "user" as
 * defined by the SNMP-USER-BASED-SM-MIB MIB.
 */

#include <config.h>

#include <stdio.h>
#include <sys/types.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif

#include "asn1.h"
#include "snmp_api.h"
#include "snmp.h"
#include "snmpv3.h"
#include "snmp-tc.h"
#include "system.h"
#include "read_config.h"
#include "snmpusm.h"
#include "snmp_api.h"
#include "scapi.h"
#include "lcd_time.h"
#include "keytools.h"
#include "tools.h"

/*
	This is the seed for the salt (an arbitrary number - RFC2274,
	Sect 8.1.1.1.)
*/

static u_int salt_integer = 4985517;

int
asn_predict_int_length (int type, long number, int len)
{
	/* Do this the same way as asn_built_int... */
	register u_long mask;

	if (len != sizeof (long)) return -1;

	mask = ((u_long) 0x1FF) << ((8 * (sizeof(long) - 1)) - 1);
	/* mask is 0xFF800000 on a big-endian machine */

	while((((number & mask) == 0) || ((number & mask) == mask)) && len > 1)
	{
		len--;
		number <<= 8;
	}

	return 1+1+len;
}


int
asn_predict_length (int type, u_char *ptr, int u_char_len)
{
	if (type & ASN_SEQUENCE) return 1+3+u_char_len;

	if (type &  ASN_INTEGER)
		return asn_predict_int_length (type, (long) *ptr, u_char_len);

	if (u_char_len < 0x80)
		return 1+1+u_char_len;
	else if (u_char_len < 0xFF)
		return 1+2+u_char_len;
	else
		return 1+3+u_char_len;
}

int
usm_calc_offsets (
	int globalDataLen,
	int secLevel,
	int secEngineIDLen,
	int secNameLen,
	int scopedPduLen,
	long engineboots,
	long enginetime,
	int *theTotalLength,
	int *authParamsOffset,
	int *privParamsOffset,
	int *dataOffset,
	int *datalen,
	int *msgAuthParmLen,
	int *msgPrivParmLen,
	int *otstlen,
	int *seq_len,
	int *msgSecParmLen)
{
	int engIDlen, engBtlen, engTmlen, namelen, authlen, privlen;

	/* If doing authentication, msgAuthParmLen = 12 else msgAuthParmLen = 0 */
	*msgAuthParmLen = (secLevel == SNMP_SEC_LEVEL_AUTHNOPRIV
						|| secLevel == SNMP_SEC_LEVEL_AUTHPRIV)?12:0;

	/* If doing encryption, msgPrivParmLen = 8 else msgPrivParmLen = 0 */
	*msgPrivParmLen = (secLevel == SNMP_SEC_LEVEL_AUTHPRIV)?8:0;

	/* Calculate lengths */
	if ((engIDlen = asn_predict_length (ASN_OCTET_STR,0,secEngineIDLen))==-1)
	{
		return -1;
	}
	if ((engBtlen = asn_predict_length (ASN_INTEGER,
					(u_char*)&engineboots,sizeof(long)))==-1)
	{
		return -1;
	}
	if ((engTmlen = asn_predict_length (ASN_INTEGER,
					(u_char*)&enginetime,sizeof(long)))==-1)
	{
		return -1;
	}
	if ((namelen = asn_predict_length (ASN_OCTET_STR,0,secNameLen))==-1)
	{
		return -1;
	}
	if ((authlen = asn_predict_length (ASN_OCTET_STR,0,*msgAuthParmLen))==-1)
	{
		return -1;
	}
	if ((privlen = asn_predict_length (ASN_OCTET_STR,0,*msgPrivParmLen))==-1)
	{
		return -1;
	}

	*seq_len = engIDlen+engBtlen+engTmlen+namelen+authlen+privlen;
	if ((*otstlen = asn_predict_length (ASN_SEQUENCE,0, *seq_len))==-1)
	{
		return -1;
	}

	if ((*msgSecParmLen = asn_predict_length (ASN_OCTET_STR,0,*otstlen))==-1)
	{
		return -1;
	}

	*authParamsOffset =	globalDataLen +
		+ (*msgSecParmLen/*-otstlen)+(otstlen*/-*seq_len)
		+ engIDlen + engBtlen + engTmlen + namelen
		+ (authlen - *msgAuthParmLen);

	*privParamsOffset =	*authParamsOffset + *msgAuthParmLen
		+ (privlen - *msgPrivParmLen);

	if (secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		/* Assumes that the encrypted(sPDU) length is the same as plaintext */
		if ((*datalen = asn_predict_length (ASN_OCTET_STR,0,scopedPduLen))==-1)
		{
			return -1;
		}
	}
	else
	{
		*datalen = scopedPduLen;
	}

	*dataOffset = globalDataLen + *msgSecParmLen + (*datalen - scopedPduLen);

	*theTotalLength = globalDataLen + *msgSecParmLen + *datalen;

	return 0;
}

int
usm_generate_out_msg_NULL (msgProcModel, globalData, globalDataLen, maxMsgSize, 
		    secModel, secEngineID, secEngineIDLen, secName, secNameLen,
		    secLevel, scopedPdu, scopedPduLen, secStateRef,
		    secParams, secParamsLen, wholeMsg, wholeMsgLen)
     int msgProcModel;          /* not used */
     u_char *globalData;        /* IN - pointer to msg header data */
                                /* will point to the beginning of the entire */
                                /* packet buffer to be transmitted on wire, */
                                /* memory will be contiguous with secParams, */
                                /* typically this pointer will be passed */
                                /* back as beginning of wholeMsg below. */
                                /* asn seq. length is updated w/ new length */
     int globalDataLen;         /* length of msg header data */
     int maxMsgSize;            /* not used */
     int secModel;              /* not used */
     u_char *secEngineID;       /* IN - pointer snmpEngineID */
     int secEngineIDLen;        /* IN - snmpEngineID length */
     u_char *secName;           /* IN - pointer to securityName */
     int secNameLen;            /* IN - securityName length */
     int secLevel;              /* IN - authNoPriv, authPriv etc. */
     u_char *scopedPdu;         /* IN - pointer to scopedPdu */
                                /* will be encrypted by USM if needed and */
                                /* written to packet buffer immediately */
                                /* following securityParameters, entire msg */
                                /* will be authenticated by USM if needed */
     int scopedPduLen;          /* IN - scopedPdu length */
     void *secStateRef;         /* IN - secStateRef, pointer to cached info */
                                /* provided only for Response, otherwise NULL */
     u_char *secParams;         /* OUT - BER encoded securityParameters */
                                /* pointer to offset within packet buffer */
                                /* where secParams should be written, the */
                                /* entire BER encoded OCTET STRING (including */
                                /* header) is written here by USM */
                                /* secParams = globalData + globalDataLen */
     int *secParamsLen;         /* IN/OUT - len available, len returned */
     u_char **wholeMsg;         /* OUT - complete authenticated/encrypted */
                                /* message - typically the pointer to start */
                                /* of packet buffer provided in globalData */
                                /* is returned here, could also be a separate */
                                /* buffer */
     int *wholeMsgLen;          /* IN/OUT - len available, len returned */
{
/* This is the function used when no security is possible.  Only around
for reference now. */
  u_char *cp, *msg_hdr_e, *oct_hdr_e, *seq_hdr_e;
  int asn_len = *secParamsLen;
  long boots = 0;
  long time = 0;
  int tmp_len;
  u_char type;

  /* build header for secParams OCTET STRING, zero length at the moment */
  oct_hdr_e = asn_build_string(secParams, &asn_len, 
                            (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			       NULL, 0);
  /* build header for secParams SEQUENCE, zero length at the moment */
  seq_hdr_e = asn_build_sequence(oct_hdr_e, &asn_len, 
			(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), 0);
  /* build msgAuthoritativeEngineID */
  cp = asn_build_string(seq_hdr_e, &asn_len,
			(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			secEngineID, secEngineIDLen);
  /* build msgAuthoritativeEngineBoots */
  cp = asn_build_int(cp, &asn_len,
		     (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		     &boots, sizeof(boots));
  /* build msgAuthoritativeEngineTime */
  cp = asn_build_int(cp, &asn_len,
		     (u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
		     &time, sizeof(time));
  /* build msgUserName */
  cp = asn_build_string(cp, &asn_len,
			(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			secName, secNameLen);
  /* build msgAuthenticationParameters */
  cp = asn_build_string(cp, &asn_len, 
			(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			NULL, 0);
  /* build msgPrivacyParameters */
  cp = asn_build_string(cp, &asn_len, 
			(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
			NULL, 0);
  /* update OCTET STRING header with real length */
  tmp_len = asn_len;
  asn_build_header(secParams, &tmp_len, 
		   (u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
		   cp - oct_hdr_e);
  /* update SEQUENCE header with real length */
  tmp_len = asn_len;
  asn_build_sequence(oct_hdr_e, &tmp_len, 
		   (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), cp - seq_hdr_e);

  *secParamsLen = cp - secParams; /* entire len of secParams OCTET STRING */

  /* for noAuthNoPriv unencrypted scopedPdu is written to mem after secParams */
  memcpy(cp, scopedPdu, scopedPduLen);
  cp += scopedPduLen;

  /* update sequence header for wholeMsg */
  tmp_len = globalDataLen;
  msg_hdr_e = asn_parse_header(globalData, &tmp_len, &type);
  asn_build_sequence(globalData, &tmp_len,
		     (u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), cp - msg_hdr_e);

  *wholeMsgLen = globalDataLen + *secParamsLen + scopedPduLen;
  *wholeMsg = globalData;
  return 0;
}

int
usm_set_salt (u_char *iv, int *iv_length, u_char *priv_key, int prev_key_length)
{
	/*
		The salt is defined to be the concatenation of the boots and the
		salt integer.  The result of the concatenation is then XORed with
		the last 8 bytes of the key.
		The salt integer is then incremented.
	*/
	int index;
	int boots = snmpv3_get_engine_boots();

	if (iv_length == NULL || *iv_length != 8 || iv == NULL
		|| prev_key_length != 16 || priv_key == NULL) return -1;

	memcpy (iv, &boots, sizeof(int));
	memcpy (&iv[sizeof(int)], &salt_integer, sizeof(int));
	salt_integer++;

	/* Now, must XOR the iv with the last 8 bytes of the priv_key */

	for (index = 0; index < 8; index++)
		iv[index] ^= priv_key[8+index];

	return 0;
}

int
usm_generate_out_msg (msgProcModel, globalData, globalDataLen, maxMsgSize, 
		    secModel, secEngineID, secEngineIDLen, secName, secNameLen,
		    secLevel, scopedPdu, scopedPduLen, secStateRef,
		    secParams, secParamsLen, wholeMsg, wholeMsgLen)
     int msgProcModel;          /* not used */
     u_char *globalData;        /* IN - pointer to msg header data */
                                /* will point to the beginning of the entire */
                                /* packet buffer to be transmitted on wire, */
                                /* memory will be contiguous with secParams, */
                                /* typically this pointer will be passed */
                                /* back as beginning of wholeMsg below. */
                                /* asn seq. length is updated w/ new length */
     int globalDataLen;         /* length of msg header data */
     int maxMsgSize;            /* not used */
     int secModel;              /* not used */
     u_char *secEngineID;       /* IN - pointer snmpEngineID */
     int secEngineIDLen;        /* IN - snmpEngineID length */
     u_char *secName;           /* IN - pointer to securityName */
     int secNameLen;            /* IN - securityName length */
     int secLevel;              /* IN - authNoPriv, authPriv etc. */
     u_char *scopedPdu;         /* IN - pointer to scopedPdu */
                                /* will be encrypted by USM if needed and */
                                /* written to packet buffer immediately */
                                /* following securityParameters, entire msg */
                                /* will be authenticated by USM if needed */
     int scopedPduLen;          /* IN - scopedPdu length */
     void *secStateRef;         /* IN - secStateRef, pointer to cached info */
                                /* provided only for Response, otherwise NULL */
     u_char *secParams;         /* OUT - BER encoded securityParameters */
                                /* pointer to offset within packet buffer */
                                /* where secParams should be written, the */
                                /* entire BER encoded OCTET STRING (including */
                                /* header) is written here by USM */
                                /* secParams = globalData + globalDataLen */
     int *secParamsLen;         /* IN/OUT - len available, len returned */
     u_char **wholeMsg;         /* OUT - complete authenticated/encrypted */
                                /* message - typically the pointer to start */
                                /* of packet buffer provided in globalData */
                                /* is returned here, could also be a separate */
                                /* buffer */
     int *wholeMsgLen;          /* IN/OUT - len available, len returned */
{
	int otstlen;
	int seq_len;
	int msgAuthParmLen;
	int msgPrivParmLen;
	int msgSecParmLen;
	int authParamsOffset;
	int privParamsOffset;
	int datalen;
	int dataOffset;
	int theTotalLength;

	u_char         *ptr;
	int            ptr_len;
	int            remaining;
	int            offSet;
	struct usmUser *user;
	u_int          boots_uint;
	u_int          time_uint;
	long           boots_long;
	long           time_long;

	DEBUGP ("usm_generate_out_msg():%s,%d: USM processing begun\n",
		__FILE__,__LINE__);

	if (secStateRef != NULL) free (secStateRef);

	/* Identify the user record */

	if ((user = usm_get_user(secEngineID, secEngineIDLen, secName)) == NULL)
	{
		/* RETURN: unknownSecurityName */
		DEBUGP ("usm_generate_out_msg():%s,%d: Unknown User\n",
			__FILE__,__LINE__);
		return USM_ERR_UNKNOWN_SECURITY_NAME;
	}

	/* Check to see if the user can use the requested sec services */

	if (usm_check_secLevel(secLevel, user) == 1)
	{
		/* RETURN: unsupportedSecurityLevel */
		DEBUGP ("usm_generate_out_msg():%s,%d: Unsupported Security Level\n",
			__FILE__,__LINE__);
		return USM_ERR_UNSUPPORTED_SECURITY_LEVEL;
	}

	/* Retrieve the engine information */

	if (get_enginetime(secEngineID,secEngineIDLen,&boots_uint,&time_uint)==-1)
	{
		DEBUGP ("usm_generate_out_msg():%s,%d: Failed to find engine data\n",
			__FILE__,__LINE__);
		return USM_ERR_GENERIC_ERROR;
	}

	boots_long = boots_uint;
	time_long = time_uint;
	
	/* Set up the Offsets */

	if (usm_calc_offsets (globalDataLen, secLevel, secEngineIDLen,
							secNameLen, scopedPduLen, boots_long, time_long,
							&theTotalLength, &authParamsOffset,
							&privParamsOffset, &dataOffset, &datalen,
							&msgAuthParmLen, &msgPrivParmLen,
							&otstlen, &seq_len, &msgSecParmLen) == -1)
	{
		DEBUGP ("usm_generate_out_msg():%s,%d: Failed calculating offsets\n",
			__FILE__,__LINE__);
		return USM_ERR_GENERIC_ERROR;
	}

	/*
		So, we have the offsets for the three parts that need to be determined,
		and an overall length.  Now we need to make sure all of this would
		fit in the outgoing buffer, and whether or not we need to make a
		new buffer, etc.
	*/

	/* For now, the hell with it, *wholeMsg is globalData, regardless */
	ptr = *wholeMsg = globalData;
	if (theTotalLength > *wholeMsgLen)
	{
		DEBUGP ("usm_generate_out_msg():%s,%d: Message won't fit in buffer\n",
			__FILE__,__LINE__);
		return USM_ERR_GENERIC_ERROR;
	}

	ptr_len = *wholeMsgLen = theTotalLength;

	/* Do the encryption */

	if (secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		/* We have to do encryption */

		int encrypted_length = datalen;
		int iv_length = msgPrivParmLen;

		if (usm_set_salt (&ptr[privParamsOffset], &iv_length,
						user->privKey, user->privKeyLen) == -1)
		{
			DEBUGP ("usm_generate_out_msg():%s,%d: Can't set CBC-DES salt\n",
				__FILE__,__LINE__);
			return USM_ERR_GENERIC_ERROR;
		}

		if (sc_encrypt (user->privProtocol, user->privProtocolLen,
						user->privKey, user->privKeyLen,
						&ptr[privParamsOffset], iv_length,
						scopedPdu, scopedPduLen,
						&ptr[dataOffset], &encrypted_length)
											!= SNMP_ERR_NOERROR)
		{
			/* RETURN: encryptionError */
			DEBUGP ("usm_generate_out_msg():%s,%d: CBC-DES error\n",
				__FILE__,__LINE__);
			return USM_ERR_ENCRYPTION_ERROR;
		}

		if (encrypted_length != datalen || iv_length != msgPrivParmLen)
		{
			/* RETURN: encryptionError */
			DEBUGP ("usm_generate_out_msg():%s,%d: CBC-DES length error\n",
				__FILE__,__LINE__);
			return USM_ERR_ENCRYPTION_ERROR;
		}

		DEBUGP ("usm_generate_out_msg():%s,%d: encryption successful\n",
				__FILE__,__LINE__);
	}
	else
	{
		/* No encryption for you! */
		memcpy (&ptr[dataOffset],scopedPdu,scopedPduLen);
		/* I don't think I need to do this:
				 memset (&ptr[privParamsOffset],0,1);*/
	}

	/* Start filling in the other fields (in prep for authentication) */

	remaining = ptr_len - globalDataLen;

	offSet =  ptr_len - remaining;
	asn_build_header (&ptr[offSet], &remaining, 
					(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
					msgSecParmLen);

	offSet = ptr_len - remaining;
	asn_build_header (&ptr[offSet], &remaining, 
					(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), otstlen);
	
	offSet = ptr_len - remaining;
	asn_build_string (&ptr[offSet], &remaining,
					(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
					secEngineID, secEngineIDLen);
	
	offSet = ptr_len - remaining;
	asn_build_int (&ptr[offSet], &remaining,
					(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
					&boots_long, sizeof(long));
	
	offSet = ptr_len - remaining;
	asn_build_int (&ptr[offSet], &remaining,
					(u_char)(ASN_UNIVERSAL | ASN_PRIMITIVE | ASN_INTEGER),
					&time_long, sizeof(long));
	
	offSet = ptr_len - remaining;
	asn_build_string (&ptr[offSet], &remaining,
					(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
					secName, secNameLen);

	/* Time for the authentication area - for now, blank sig if signing */

	offSet = ptr_len - remaining;
	if (secLevel == SNMP_SEC_LEVEL_AUTHNOPRIV
						|| secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		asn_build_header(&ptr[offSet], &remaining,
						(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
						msgAuthParmLen);
		offSet = ptr_len - remaining;
		memset (&ptr[offSet],0,msgAuthParmLen);
	}
	else
	{
		asn_build_string(&ptr[offSet], &remaining,
							(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
							NULL, msgAuthParmLen);
	}

	/* Time for the encryption parameters - if privacy is applied, the
		parameters are already in there, just the header is needed. */

	offSet = ptr_len - remaining;
	if (secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		asn_build_header(&ptr[offSet], &remaining,
							(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
							msgPrivParmLen);
		/* Privacy parameters are already in there */
	}
	else
	{
		asn_build_string(&ptr[offSet], &remaining,
							(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
							NULL, msgPrivParmLen);
	}

	offSet = ptr_len - remaining;
	asn_build_header(&ptr[offSet], &remaining,
						(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
						msgPrivParmLen);

	/* In doing encyption, need to add the octet string header for it */

	if (secLevel==SNMP_SEC_LEVEL_AUTHPRIV)
	{
		offSet = ptr_len - remaining;
		asn_build_header(&ptr[offSet], &remaining,
						(u_char)(ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR),
						scopedPduLen);
	}

	/* Need to adjust overall length */

	remaining = theTotalLength;
	asn_build_sequence (ptr, &remaining, 
				(u_char)(ASN_SEQUENCE | ASN_CONSTRUCTOR), theTotalLength-4);

	/* Now, time to consider / do authentication */

	if (secLevel == SNMP_SEC_LEVEL_AUTHNOPRIV
						|| secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		int temp_sig_len = msgAuthParmLen;
		u_char *temp_sig = (u_char *) malloc (temp_sig_len);

		if (temp_sig == NULL)
		{
			DEBUGP ("usm_generate_out_msg():%s,%d: out of memory\n",
				__FILE__,__LINE__);
			return USM_ERR_GENERIC_ERROR;
		}

		if (sc_generate_keyed_hash (user->authProtocol, user->authProtocolLen,
									user->authKey, user->authKeyLen,
									ptr, ptr_len,
									temp_sig, &temp_sig_len)
											!= SNMP_ERR_NOERROR)
		{
			free (temp_sig);
			/* RETURN: authenticationFailure */
			DEBUGP ("usm_generate_out_msg():%s,%d: signing failed\n",
				__FILE__,__LINE__);
			return USM_ERR_AUTHENTICATION_FAILURE;
		}

		if (temp_sig_len != msgAuthParmLen)
		{
			free (temp_sig);
			/* RETURN: authenticationFailure */
			DEBUGP ("usm_generate_out_msg():%s,%d: signing lengths failed\n",
				__FILE__,__LINE__);
			return USM_ERR_AUTHENTICATION_FAILURE;
		}

		memcpy (&ptr[authParamsOffset], temp_sig, msgAuthParmLen);

		free (temp_sig);
	}

	DEBUGP ("usm_generate_out_msg():%s,%d: USM processing completed\n",
		__FILE__,__LINE__);
	
	return USM_ERR_NO_ERROR;
}

int
usm_process_in_msg_NULL (msgProcModel, maxMsgSize, secParams, secModel, secLevel, 
		    wholeMsg, wholeMsgLen, secEngineID, secEngineIDLen, 
		    secName, secNameLen, scopedPdu, scopedPduLen, 
		    maxSizeResponse, secStateRef)
     int msgProcModel;          /* not used */
     int maxMsgSize;            /* IN - used to calc maxSizeResponse */
     u_char *secParams;         /* IN - BER encoded securityParameters */
     int secModel;              /* not used */
     int secLevel;              /* IN - authNoPriv, authPriv etc. */
     u_char *wholeMsg;          /* IN - auth/encrypted data */
     int wholeMsgLen;           /* IN - msg length */
     u_char *secEngineID;       /* OUT - pointer snmpEngineID */
     int *secEngineIDLen;       /* IN/OUT - len available, len returned */
                                /* NOTE: memory provided by caller */
     u_char *secName;           /* OUT - pointer to securityName */
     int *secNameLen;           /* IN/OUT - len available, len returned */
     u_char **scopedPdu;        /* OUT - pointer to plaintext scopedPdu */
     int *scopedPduLen;         /* IN/OUT - len available, len returned */
     int *maxSizeResponse;      /* OUT - max size of Response PDU */
     void **secStateRef;        /* OUT - ref to security state */
{
  u_char *cp;
  u_char type;
  int asn_len;
  long engineBoots;
  long engineTime;
#define USM_AUTH_PARAMS_SIZE 64
#define USM_PRIV_PARAMS_SIZE 64
  u_char authParams[USM_AUTH_PARAMS_SIZE];
  int authParamsLen = USM_AUTH_PARAMS_SIZE;
  u_char privParams[USM_PRIV_PARAMS_SIZE];
  int privParamsLen = USM_PRIV_PARAMS_SIZE;

  asn_len = wholeMsgLen - (secParams - wholeMsg);
  /* parse past header of secParams OCTET STRING */
  cp = asn_parse_header(secParams, &asn_len, &type);
  if (asn_len) {
    /* parse past secParams sequence embedded in OCTET STRING */
    cp = asn_parse_header(cp, &asn_len, &type);
    /* parse msgAuthoritativeEngineID */
    cp = asn_parse_string(cp, &asn_len, &type, secEngineID, secEngineIDLen);
    /* parse msgAuthoritativeEngineBoots */
    cp = asn_parse_int(cp, &asn_len, &type, &engineBoots, sizeof(engineBoots));
    /* parse msgAuthoritativeEngineTime */
    cp = asn_parse_int(cp, &asn_len, &type, &engineTime, sizeof(engineTime));
    /* parse msgUserName */
    cp = asn_parse_string(cp, &asn_len, &type, secName, secNameLen);
    /* parse msgAuthenticationParameters */
    cp = asn_parse_string(cp, &asn_len, &type, authParams, &authParamsLen);
    /* parse msgPrivacyParameters */
    cp = asn_parse_string(cp, &asn_len, &type, privParams, &privParamsLen);
  }
  *scopedPdu = cp; /* for noAuthNoPriv just point at scopedPdu in packet */
  *scopedPduLen = wholeMsgLen - (cp - wholeMsg);

  return 0;
}

int
usm_parse_security_parameters (secParams, remaining, secEngineID,
			secEngineIDLen, boots_uint, time_uint, secName, secNameLen,
			signature, signature_length, salt, salt_length, data_ptr)
	u_char *secParams;
	u_int  remaining;
	u_char *secEngineID;
	int    *secEngineIDLen;
	u_int  *boots_uint;
	u_int  *time_uint;
	u_char *secName;
	int    *secNameLen;
	u_char *signature;
	u_int  *signature_length;
	u_char *salt;
	u_int  *salt_length;
	u_char *data_ptr;
{
	u_char *parse_ptr = secParams;
	u_char *value_ptr;
	u_char *next_ptr;
	u_char type_value;

	u_int octet_string_length = remaining;
	u_int sequence_length;
	u_int remaining_bytes;

	long boots_long;
	long time_long;

	/* Eat the first octet header */

	if ((value_ptr = asn_parse_header (parse_ptr, &octet_string_length,
			&type_value)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
	{
		/* RETURN parse error */ return -1;
	}

	/* Eat the sequence header */

	parse_ptr = value_ptr;
	sequence_length = octet_string_length;

	if ((value_ptr = asn_parse_header (parse_ptr, &sequence_length,
			&type_value)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_SEQUENCE | ASN_CONSTRUCTOR))
	{
		/* RETURN parse error */ return -1;
	}

	/* Retrieve the engineID */

	parse_ptr = value_ptr;
	remaining_bytes = sequence_length;

	if ((next_ptr = asn_parse_string (parse_ptr, &remaining_bytes, &type_value,
						secEngineID, secEngineIDLen)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
	{
		/* RETURN parse error */ return -1;
	}

	/* Retrieve the engine boots, notice switch in the way next_ptr and
		remaining_bytes are used (to accomodate the asn code) */

	if ((next_ptr = asn_parse_int (next_ptr, &remaining_bytes, &type_value,
						&boots_long, sizeof(long))) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_INTEGER))
	{
		/* RETURN parse error */ return -1;
	}

	*boots_uint = (u_int) boots_long;

	/* Retrieve the time value */

	if ((next_ptr = asn_parse_int (next_ptr, &remaining_bytes, &type_value,
						&time_long, sizeof(long))) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_INTEGER))
	{
		/* RETURN parse error */ return -1;
	}

	*time_uint = (u_int) time_long;

	/* Retrieve the secName */

	if ((next_ptr = asn_parse_string (next_ptr, &remaining_bytes, &type_value,
						secName, secNameLen)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
	{
		/* RETURN parse error */ return -1;
	}

	/* Retrieve the signature and blank it if there */

	if ((next_ptr = asn_parse_string (next_ptr, &remaining_bytes, &type_value,
						signature, signature_length)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
	{
		/* RETURN parse error */ return -1;
	}

	if (*signature_length != 0) /* Blanking for authentication step later */
	{
		memset (next_ptr-(u_long)*signature_length, 0, *signature_length);
	}

	/* Retrieve the salt */
	/* Note that the next ptr is where the data section starts. */

	if ((data_ptr = asn_parse_string (next_ptr, &remaining_bytes, &type_value,
						salt, salt_length)) == NULL)
	{
		/* RETURN parse error */ return -1;
	}

	if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
	{
		/* RETURN parse error */ return -1;
	}

	return 0;
}

int
usm_check_and_update_timeliness (secEngineID, secEngineIDLen, boots_uint,
		time_uint, error)
	u_char *secEngineID;
	int    secEngineIDLen;
	u_int  boots_uint;
	u_int  time_uint;
	int    *error;
{
#define USM_MAX_ID_LENGTH 1024
	u_char myID[USM_MAX_ID_LENGTH];

	int myIDLength = snmpv3_get_engineID (myID);
	u_int myBoots;
	u_int myTime;

	if (myIDLength > USM_MAX_ID_LENGTH)
	{
		DEBUGP ("usm_check_and_update_timeliness():%s,%d: Buffer overflow\n",
			__FILE__,__LINE__);

		/* We're probably already screwed...buffer overwrite */
		*error = USM_ERR_GENERIC_ERROR;
		return -1;
	}

	myBoots = snmpv3_get_engine_boots();
	myTime = snmpv3_get_engineTime();

	/* If the time involved is local */
		/* Make sure  message is inside the time window */
	/* else */
		/* if the boots is higher or boots is the same and time is higher */
			/* remember this new data */
		/* else */
			/* if !(boots is the same and the time is within 150 secs) */
				/* Message is too old */
			/* else */
				/* Message is ok, but don't take time */

	if (secEngineIDLen == myIDLength && memcmp (secEngineID, myID, myIDLength))
	{
		/* This is a local reference */

		u_int time_difference = myTime > time_uint ?
				myTime - time_uint : time_uint - myTime;

		if (boots_uint == 2147483647 /* Is there a defined const.? */
			|| boots_uint != myBoots
			|| time_difference > 150) /* Ditto */
		{
			/* INCREMENT usmStatsNotInTimeWindows */
			if (snmp_increment_statistic (STAT_USMSTATSNOTINTIMEWINDOWS)==0)
			{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Failed to increment statistic");
				*error = USM_ERR_GENERIC_ERROR;
			}
			else
			{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
				__FILE__,__LINE__, "Not in local time window");
				*error = USM_ERR_NOT_IN_TIME_WINDOW;
			}
			return -1;
		}
	}
	else
	{
		/* This is a remote reference */

		u_int theirBoots, theirTime;
		u_int time_difference;

		if (get_enginetime(secEngineID,secEngineIDLen,&theirBoots,&theirTime)
			!= SNMPERR_SUCCESS)
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Failed to get remote engine's times");

			*error = USM_ERR_GENERIC_ERROR;
			return -1;
		}

		time_difference = theirTime > time_uint ?
				theirTime - time_uint : time_uint - theirTime;

		/* Contrary to the pseudocode: */
		/* See if boots is invalid first */

		if (theirBoots == 2147483647 /* See comment above */
			|| theirBoots > boots_uint)
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Remote boot count invalid");

			*error = USM_ERR_NOT_IN_TIME_WINDOW;
			return -1;
		}

		/* Boots is ok, see if the boots is the same but the time is old */

		if (theirBoots == boots_uint && theirTime > time_uint)
		{
			if(time_difference > 150)
			{
				DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Message too old");

				*error = USM_ERR_NOT_IN_TIME_WINDOW;
				return -1;
			}
			else
			{
				*error = USM_ERR_NO_ERROR;
				return 0; /* Old, but acceptable */
			}
		}

		/*
			Message is ok, either boots has been advanced, or time is
			greater than before with the same boots.
		*/

		if (set_enginetime (secEngineID,secEngineIDLen,boots_uint,time_uint)
			!= SNMPERR_SUCCESS)
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
				__FILE__,__LINE__,
				"Failed updating remote boot/time");

			*error = USM_ERR_GENERIC_ERROR;
			return -1;
		}

		*error = USM_ERR_NO_ERROR;
		return 0; /* Fresh message and time updated */
	}
}

int
usm_process_in_msg (msgProcModel, maxMsgSize, secParams, secModel, secLevel, 
		    wholeMsg, wholeMsgLen, secEngineID, secEngineIDLen, 
		    secName, secNameLen, scopedPdu, scopedPduLen, 
		    maxSizeResponse, secStateRef)
     int msgProcModel;          /* not used */
     int maxMsgSize;            /* IN - used to calc maxSizeResponse */
     u_char *secParams;         /* IN - BER encoded securityParameters */
     int secModel;              /* not used */
     int secLevel;              /* IN - authNoPriv, authPriv etc. */
     u_char *wholeMsg;          /* IN - auth/encrypted data */
     int wholeMsgLen;           /* IN - msg length */
     u_char *secEngineID;       /* OUT - pointer snmpEngineID */
     int *secEngineIDLen;       /* IN/OUT - len available, len returned */
                                /* NOTE: memory provided by caller */
     u_char *secName;           /* OUT - pointer to securityName */
     int *secNameLen;           /* IN/OUT - len available, len returned */
     u_char **scopedPdu;        /* OUT - pointer to plaintext scopedPdu */
     int *scopedPduLen;         /* IN/OUT - len available, len returned */
     int *maxSizeResponse;      /* OUT - max size of Response PDU */
     void **secStateRef;        /* OUT - ref to security state */
{
#define USM_MAX_SALT_LENGTH			64
#define USM_MAX_KEYEDHASH_LENGTH	64

	u_int  remaining =
		wholeMsgLen - (u_int)((u_long)*secParams-(u_long)*wholeMsg);

	u_int  boots_uint;
	u_int  time_uint;
	u_char signature[USM_MAX_KEYEDHASH_LENGTH];
	u_int  signature_length = USM_MAX_KEYEDHASH_LENGTH;
	u_char salt[USM_MAX_KEYEDHASH_LENGTH];
	u_int  salt_length = USM_MAX_KEYEDHASH_LENGTH;
	u_char *data_ptr;
	u_char *value_ptr;
	u_char type_value;
	u_char *end_of_overhead;
	int    reportErrorOnUnknownID = 0; /* Should be configurable item */
	int    error;

	struct usmUser *user;

	/* Make sure the *secParms is an OCTET STRING */
	/* Extract the user name, engine ID, and security level */

	DEBUGP ("usm_process_in_msg():%s,%d: USM processing begun\n",
		__FILE__,__LINE__);

	if (usm_parse_security_parameters (secParams, remaining,
		secEngineID, secEngineIDLen, &boots_uint, &time_uint, secName,
		secNameLen, signature, &signature_length, salt, &salt_length,
		data_ptr) == -1)
	{
		DEBUGP ("usm_process_in_msg():%s,%d: Parsing failed\n",
			__FILE__,__LINE__);

		/* INCREMENT snmpInASNParseErrs */
		if (snmp_increment_statistic (STAT_SNMPINASNPARSEERRS)==0)
			return USM_ERR_GENERIC_ERROR;

		return USM_ERR_PARSE_ERROR;
	}
	
	/* Locate the engine ID record */
	/* If it is unknown, then either create one or note this as an error */

	if (reportErrorOnUnknownID)
	{
		if (ISENGINEKNOWN(secEngineID, *secEngineIDLen)==FALSE)
		{
			/* Report error */
			/* INCREMENT usmStatsUnknownEngineIDs */
			DEBUGP ("usm_process_in_msg():%s,%d: Unknown Engine ID\n",
				__FILE__,__LINE__);

			if (snmp_increment_statistic (STAT_USMSTATSUNKNOWNENGINEIDS)==0)
				return USM_ERR_GENERIC_ERROR;
	
			return USM_ERR_UNKNOWN_ENGINE_ID;
		}
	}
	else
	{
		if (ENSURE_ENGINE_RECORD(secEngineID,*secEngineIDLen)!=SNMPERR_SUCCESS)
		{
			DEBUGP ("usm_process_in_msg():%s,%d: %s\n",
				__FILE__,__LINE__, "Couldn't ensure engine record");

			return USM_ERR_GENERIC_ERROR;
		}
		
	}

	/* Locate the User record */
	/* If the user/engine ID is unknown, report this as an error */

	if ((user = usm_get_user(secEngineID, *secEngineIDLen, secName)) == NULL)
	{
		DEBUGP ("usm_process_in_msg():%s,%d: Unknown User\n",
			__FILE__,__LINE__);

		/* INCREMENT usmStatsUnknownUserNames */
		if (snmp_increment_statistic (STAT_USMSTATSUNKNOWNUSERNAMES)==0)
			return USM_ERR_GENERIC_ERROR;

		return USM_ERR_UNKNOWN_SECURITY_NAME;
	}

	/* Make sure the security level is appropriate */

	if (usm_check_secLevel(secLevel, user) == 1)
	{
		DEBUGP ("usm_process_in_msg():%s,%d: Unsupported Security Level\n",
			__FILE__,__LINE__);

		/* INCREMENT usmStatsUnsupportedSecLevels */
		if (snmp_increment_statistic (STAT_USMSTATSUNSUPPORTEDSECLEVELS)==0)
			return USM_ERR_GENERIC_ERROR;

		return USM_ERR_UNSUPPORTED_SECURITY_LEVEL;
	}

	/* Check the authentication credentials of the message */

	if (sc_check_keyed_hash (user->authProtocol, user->authProtocolLen,
									user->authKey, user->authKeyLen,
									wholeMsg, wholeMsgLen,
									signature, signature_length)
											!= SNMP_ERR_NOERROR)
	{
			DEBUGP ("usm_process_in_msg():%s,%d: Verification failed\n",
				__FILE__,__LINE__);

			/* INCREMENT usmStatsWrongDigests */
			if (snmp_increment_statistic (STAT_USMSTATSWRONGDIGESTS)==0)
				return USM_ERR_GENERIC_ERROR;

			return USM_ERR_AUTHENTICATION_FAILURE;
	}

	DEBUGP ("usm_process_in_msg():%s,%d: Verification succeeded\n",
		__FILE__,__LINE__);


	/* Perform the timeliness/time manager functions */

	if (usm_check_and_update_timeliness (secEngineID, *secEngineIDLen,
		boots_uint, time_uint, &error)==-1)
	{
		return error;
	}

	/* If needed, decrypt the scoped PDU */

	if (secLevel == SNMP_SEC_LEVEL_AUTHPRIV)
	{
		/* We have an encrypted message */
		remaining = wholeMsgLen - (data_ptr - wholeMsg);

		if ((value_ptr = asn_parse_header (data_ptr, &remaining,
				&type_value)) == NULL)
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
				__FILE__,__LINE__,
				"Failed parseing encrypted sPDU");

			/* INCREMENT snmpInASNParseErrs */

			if (snmp_increment_statistic (STAT_SNMPINASNPARSEERRS)==0)
			{
				DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Failed increment statistic");
				return USM_ERR_GENERIC_ERROR;
			}

			return USM_ERR_PARSE_ERROR;
		}
	
		if (type_value != (u_char) (ASN_UNIVERSAL|ASN_PRIMITIVE|ASN_OCTET_STR))
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
				__FILE__,__LINE__,
				"Failed parseing encrypted sPDU, wrong type");

			/* INCREMENT snmpInASNParseErrs */
			if (snmp_increment_statistic (STAT_SNMPINASNPARSEERRS)==0)
			{
				DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__,
					"Failed increment statistic");

				return USM_ERR_GENERIC_ERROR;
			}

			return USM_ERR_PARSE_ERROR;
		}

		end_of_overhead = value_ptr;

		if (sc_decrypt (user->privProtocol, user->privProtocolLen,
						user->privKey, user->privKeyLen,
						salt, salt_length,
						value_ptr, remaining,
						*scopedPdu, scopedPduLen)
											!= SNMP_ERR_NOERROR)
		{
			DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
				__FILE__,__LINE__, "Failed decryption");

			/* INCREMENT usmStatsDecryptionErrors */
			if (snmp_increment_statistic (STAT_USMSTATSDECRYPTIONERRORS)==0)
			{
				DEBUGP ("usm_check_and_update_timeliness():%s,%d: %s\n",
					__FILE__,__LINE__, "Failed increment statistic");

				return USM_ERR_GENERIC_ERROR;
			}

			return USM_ERR_DECRYPTION_ERROR;
		}
	}
	else
	{
		/* sPDU is in plaintext */

		*scopedPdu = data_ptr;
		*scopedPduLen = wholeMsgLen - (data_ptr - wholeMsg);
		end_of_overhead = data_ptr;
	}

	/* Calculate the biggest sPDU for the response (i.e., whole - ovrhd) */

	*maxSizeResponse = maxMsgSize - (int)
				((u_long)end_of_overhead - (u_long)wholeMsg);

	/* Steps 10-11, don't know why */

	*secStateRef = NULL;

	DEBUGP ("usm_process_in_msg():%s,%d: USM processing completed\n",
		__FILE__,__LINE__);

	return USM_ERR_NO_ERROR;
}

/* 
 * Local storage (LCD) of the default user list.
 */
static struct usmUser *userList=NULL;

struct usmUser *
usm_get_userList()
{
  return userList;
}

/* checks that a given security level is valid for a given user */
int
usm_check_secLevel(int level, struct usmUser *user)
{
  if (level == SNMP_SEC_LEVEL_AUTHPRIV &&
      compare(user->privProtocol, user->privProtocolLen, usmNoPrivProtocol,
              sizeof(usmNoPrivProtocol)/sizeof(oid)))
    return 1;
  if ((level == SNMP_SEC_LEVEL_AUTHPRIV ||
       level == SNMP_SEC_LEVEL_AUTHNOPRIV) &&
      compare(user->authProtocol, user->authProtocolLen, usmNoAuthProtocol,
              sizeof(usmNoAuthProtocol)/sizeof(oid)))
    return 1;
  return 0; /* success */
}

/* usm_get_user(): Returns a user from userList based on the engineID,
   engineIDLen and name of the requested user. */

struct usmUser *
usm_get_user(char *engineID, int engineIDLen, char *name)
{
  return usm_get_user_from_list(engineID, engineIDLen, name, userList);
}

struct usmUser *
usm_get_user_from_list(char *engineID, int engineIDLen,
                                       char *name, struct usmUser *userList)
{
  struct usmUser *ptr;
  for (ptr = userList; ptr != NULL; ptr = ptr->next) {
    if (ptr->engineIDLen == engineIDLen &&
        memcmp(ptr->engineID, engineID, engineIDLen) == 0 &&
        !strcmp(ptr->name, name))
      return ptr;
  }
  return NULL;
}

/* usm_add_user(): Add's a user to the userList, sorted by the
   engineIDLength then the engineID then the name length then the name
   to facilitate getNext calls on a usmUser table which is indexed by
   these values.

   Note: userList must not be NULL (obviously), as thats a rather trivial
   addition and is left to the API user.

   returns the head of the list (which could change due to this add).
*/

struct usmUser *
usm_add_user(struct usmUser *user)
{
  userList = usm_add_user_to_list(user, userList);
  return userList;
}

struct usmUser *
usm_add_user_to_list(struct usmUser *user,
                                     struct usmUser *userList)
{
  struct usmUser *nptr, *pptr;

  /* loop through userList till we find the proper, sorted place to
     insert the new user */
  for (nptr = userList, pptr = NULL; nptr != NULL;
       pptr = nptr, nptr = nptr->next) {
    if (nptr->engineIDLen > user->engineIDLen)
      break;

    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) > 0)
      break;

    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) == 0 &&
        strlen(nptr->name) > strlen(user->name))
      break;

    if (nptr->engineIDLen == user->engineIDLen &&
        memcmp(nptr->engineID, user->engineID, user->engineIDLen) == 0 &&
        strlen(nptr->name) == strlen(user->name) &&
        strcmp(nptr->name, user->name) > 0)
      break;
  }

  /* nptr should now point to the user that we need to add ourselves
     in front of, and pptr should be our new 'prev'. */

  /* change our pointers */
  user->prev = pptr;
  user->next = nptr;

  /* change the next's prev pointer */
  if (user->next)
    user->next->prev = user;

  /* change the prev's next pointer */
  if (user->prev)
    user->prev->next = user;

  /* rewind to the head of the list and return it (since the new head
     could be us, we need to notify the above routine who the head now is. */
  for(pptr = user; pptr->prev != NULL; pptr = pptr->prev);
  return pptr;
}

/* usm_remove_user(): finds and removes a user from a list */
struct usmUser *
usm_remove_user(struct usmUser *user)
{
  return usm_remove_user_from_list(user, userList);
}

struct usmUser *
usm_remove_user_from_list(struct usmUser *user,
                                          struct usmUser *userList)
{
  struct usmUser *nptr, *pptr;
  for (nptr = userList, pptr = NULL; nptr != NULL;
       pptr = nptr, nptr = nptr->next) {
    if (nptr == user)
      break;
  }

  if (nptr) {
    /* remove the user from the linked list */
    if (pptr) {
      pptr->next = nptr->next;
    }
    if (nptr->next) {
      nptr->next->prev = pptr;
    }
  } else {
    return userList;
  }
  if (nptr == userList) /* we're the head of the list, return the next */
    return nptr->next;
  return userList;
}

/* usm_free_user():  calls free() on all needed parts of struct usmUser and
   the user himself.

   Note: This should *not* be called on an object in a list (IE,
   remove it from the list first, and set next and prev to NULL), but
   will try to reconnect the list pieces again if it is called this
   way.  If called on the head of the list, the entire list will be
   lost. */
struct usmUser *
usm_free_user(struct usmUser *user)
{
  if (user->engineID != NULL)
    free(user->engineID);
  if (user->name != NULL)
    free(user->name);
  if (user->secName != NULL)
    free(user->secName);
  if (user->cloneFrom != NULL)
    free(user->cloneFrom);
  if (user->authProtocol != NULL)
    free(user->authProtocol);
  if (user->authKey != NULL)
    free(user->authKey);
  if (user->privProtocol != NULL)
    free(user->privProtocol);
  if (user->privKey != NULL)
    free(user->privKey);
  if (user->userPublicString != NULL)
    free(user->userPublicString);
  if (user->prev != NULL) { /* ack, this shouldn't happen */
    user->prev->next = user->next;
  }
  if (user->next != NULL) {
    user->next->prev = user->prev;
    if (user->prev != NULL) /* ack this is really bad, because it means
                              we'll loose the head of some structure tree */
      DEBUGP("Severe: Asked to free the head of a usmUser tree somewhere.");
  }
  return NULL;  /* for convenience to returns from calling functions */
}

/* take a given user and clone the security info into another */
struct usmUser *
usm_cloneFrom_user(struct usmUser *from, struct usmUser *to)
{
  /* copy the authProtocol oid row pointer */
  if (to->authProtocol != NULL)
    free(to->authProtocol);

  if ((to->authProtocol =
       snmp_duplicate_objid(from->authProtocol,from->authProtocolLen)) != NULL)
    to->authProtocolLen = from->authProtocolLen;
  else
    to->authProtocolLen = 0;


  /* copy the authKey */
  if (to->authKey)
    free(to->authKey);

  if (from->authKeyLen > 0 &&
      (to->authKey = (char *) malloc(sizeof(char) * from->authKeyLen))
      != NULL) {
    memcpy(to->authKey, to->authKey, to->authKeyLen);
    to->authKeyLen = from->authKeyLen;
  } else {
    to->authKey = NULL;
    to->authKeyLen = 0;
  }


  /* copy the privProtocol oid row pointer */
  if (to->privProtocol != NULL)
    free(to->privProtocol);

  if ((to->privProtocol =
       snmp_duplicate_objid(from->privProtocol,from->privProtocolLen)) != NULL)
    to->privProtocolLen = from->privProtocolLen;
  else
    to->privProtocolLen = 0;

  /* copy the privKey */
  if (to->privKey)
    free(to->privKey);

  if (from->privKeyLen > 0 &&
      (to->privKey = (char *) malloc(sizeof(char) * from->privKeyLen))
      != NULL) {
    memcpy(to->privKey, to->privKey, to->privKeyLen);
    to->privKeyLen = from->privKeyLen;
  } else {
    to->privKey = NULL;
    to->privKeyLen = 0;
  }
}

/* take a given user and duplicate him */
struct usmUser *
usm_clone_user(struct usmUser *from)
{
  struct usmUser *ptr;
  struct usmUser *newUser;

  /* create the new user */
  newUser = (struct usmUser *) malloc(sizeof(struct usmUser));
  if (newUser == NULL)
    return NULL;
  memset(newUser, 0, sizeof(struct usmUser));  /* initialize everything to 0 */

/* leave everything initialized to devault values if they didn't give
   us a user to clone from */
  if (from == NULL) {
    if ((newUser->authProtocol =
         snmp_duplicate_objid(usmNoAuthProtocol,
                              sizeof(usmNoAuthProtocol)/sizeof(oid))) == NULL)
      return usm_free_user(newUser);
    newUser->authProtocolLen = sizeof(usmNoAuthProtocol)/sizeof(oid);

    if ((newUser->privProtocol =
         snmp_duplicate_objid(usmNoPrivProtocol,
                              sizeof(usmNoPrivProtocol)/sizeof(oid))) == NULL)
      return usm_free_user(newUser);
    newUser->privProtocolLen = sizeof(usmNoPrivProtocol)/sizeof(oid);

    newUser->userStorageType = ST_NONVOLATILE;
    return newUser;
  }

  /* copy the engineID & it's length */
  if (from->engineIDLen > 0) {
    if ((newUser->engineID = (char *) malloc(from->engineIDLen*sizeof(char)))
        == NULL);
      return usm_free_user(newUser);
    newUser->engineIDLen = from->engineIDLen;
    memcpy(newUser->engineID, from->engineID, from->engineIDLen*sizeof(char));
  }

  /* copy the name of the user */
  if (from->name != NULL)
    if ((newUser->name = strdup(from->name)) == NULL)
      return usm_free_user(newUser);

  /* copy the security Name for the user */
  if (from->secName != NULL)
    if ((newUser->secName = strdup(from->secName)) == NULL)
      return usm_free_user(newUser);

  /* copy the cloneFrom oid row pointer */
  if (from->cloneFromLen > 0) {
    if ((newUser->cloneFrom = (oid *) malloc(sizeof(oid)*from->cloneFromLen))
        == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->cloneFrom, from->cloneFrom,
           sizeof(oid)*from->cloneFromLen);
  }

  /* copy the authProtocol oid row pointer */
  if (from->authProtocolLen > 0) {
    if ((newUser->authProtocol =
         (oid *) malloc(sizeof(oid) * from->authProtocolLen)) == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->authProtocol, from->authProtocol,
           sizeof(oid)*from->authProtocolLen);
  }

  /* copy the authKey */
  if (from->authKeyLen > 0) {
    if ((newUser->authKey = (char *) malloc(sizeof(char) * from->authKeyLen))
        == NULL)
      return usm_free_user(newUser);
  }

  /* copy the privProtocol oid row pointer */
  if (from->privProtocolLen > 0) {
    if ((newUser->privProtocol =
         (oid *) malloc(sizeof(oid)*from->privProtocolLen)) == NULL)
      return usm_free_user(newUser);
    memcpy(newUser->privProtocol, from->privProtocol,
           sizeof(oid)*from->privProtocolLen);
  }

  /* copy the privKey */
  if (from->privKeyLen > 0) {
    if ((newUser->privKey = (char *) malloc(sizeof(char) * from->privKeyLen))
        == NULL)
      return usm_free_user(newUser);
  }

  /* copy the userPublicString convenience string */
  if (from->userPublicString != NULL)
    if ((newUser->userPublicString = strdup(from->userPublicString)) == NULL)
      return usm_free_user(newUser);

  newUser->userStatus = from->userStatus;
  newUser->userStorageType = from->userStorageType;

  return newUser;
}

/* create_initial_user: creates an initial user, filled with the
   defaults defined in the USM document. */

struct usmUser *
usm_create_initial_user(void)
{
  struct usmUser *newUser  = usm_clone_user(NULL);

  if ((newUser->name = strdup("initial")) == NULL)
    return usm_free_user(newUser);

  if ((newUser->secName = strdup("initial")) == NULL)
    return usm_free_user(newUser);

  if ((newUser->engineID = snmpv3_generate_engineID(&newUser->engineIDLen))
      == NULL)
    return usm_free_user(newUser);

  if ((newUser->cloneFrom = (oid *) malloc(sizeof(oid)*2)) == NULL)
    return usm_free_user(newUser);
  newUser->cloneFrom[0] = 0;
  newUser->cloneFrom[1] = 0;
  newUser->cloneFromLen = 2;

  if (newUser->privProtocol)
    free(newUser->privProtocol);
  if ((newUser->privProtocol = (oid *) malloc(sizeof(usmDESPrivProtocol)))
      == NULL)
    return usm_free_user(newUser);
  newUser->privProtocolLen = sizeof(usmDESPrivProtocol)/sizeof(oid);
  memcpy(newUser->privProtocol, usmDESPrivProtocol, sizeof(usmDESPrivProtocol));

  if (newUser->authProtocol)
    free(newUser->authProtocol);
  if ((newUser->authProtocol = (oid *) malloc(sizeof(usmHMACMD5AuthProtocol)))
      == NULL)
    return usm_free_user(newUser);
  newUser->authProtocolLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
  memcpy(newUser->authProtocol, usmHMACMD5AuthProtocol,
         sizeof(usmHMACMD5AuthProtocol));

  newUser->userStatus = RS_ACTIVE;
  newUser->userStorageType = ST_READONLY;

  return newUser;
}

/* usm_save_users(): saves a list of users to the persistent cache */
void usm_save_users(char *token, char *type) {
  usm_save_users_from_list(userList, token, type);
}

void usm_save_users_from_list(struct usmUser *userList, char *token,
                              char *type) {
  struct usmUser *uptr;
  for (uptr = userList; uptr != NULL; uptr = uptr->next) {
    if (uptr->userStorageType == ST_NONVOLATILE)
      usm_save_user(uptr, token, type);
  }
}

/* usm_save_user(): saves a user to the persistent cache */
void usm_save_user(struct usmUser *user, char *token, char *type) {
  char line[4096];
  char *cptr;
  int i, tmp;

  memset(line, 0, sizeof(line));

  sprintf(line, "%s %d %d ", token, user->userStatus, user->userStorageType);
  cptr = &line[strlen(line)]; /* the NULL */
  cptr = read_config_save_octet_string(cptr, user->engineID, user->engineIDLen);
  *cptr++ = ' ';
  /* XXX: makes the mistake of assuming the name doesn't contain a NULL */
  cptr = read_config_save_octet_string(cptr, user->name,
                                       (user->name == NULL) ? 0 :
                                       strlen(user->name)+1);
  *cptr++ = ' ';
  cptr = read_config_save_octet_string(cptr, user->secName,
                                       (user->secName == NULL) ? 0 :
                                       strlen(user->secName)+1);
  *cptr++ = ' ';
  cptr = read_config_save_objid(cptr, user->cloneFrom, user->cloneFromLen);
  *cptr++ = ' ';
  cptr = read_config_save_objid(cptr, user->authProtocol,
                                user->authProtocolLen);
  *cptr++ = ' ';
  cptr = read_config_save_octet_string(cptr, user->authKey, user->authKeyLen);
  *cptr++ = ' ';
  cptr = read_config_save_objid(cptr, user->privProtocol,
                                user->privProtocolLen);
  *cptr++ = ' ';
  cptr = read_config_save_octet_string(cptr, user->privKey, user->privKeyLen);
  *cptr++ = ' ';
  cptr = read_config_save_octet_string(cptr, user->userPublicString,
                                       (user->userPublicString == NULL) ? 0 :
                                       strlen(user->userPublicString)+1);
  read_config_store(type, line);
}

/* usm_parse_user(): reads in a line containing a saved user profile
   and returns a pointer to a newly created struct usmUser. */
struct usmUser *
usm_read_user(char *line) {
  struct usmUser *user;
  int len;

  user = usm_clone_user(NULL);
  user->userStatus = atoi(line);
  line = skip_token(line);
  user->userStorageType = atoi(line);
  line = skip_token(line);
  line = read_config_read_octet_string(line, &user->engineID,
                                       &user->engineIDLen);
  line = read_config_read_octet_string(line, &user->name,
                                       &len);
  line = read_config_read_octet_string(line, &user->secName,
                                       &len);
  if (user->cloneFrom) {
    free(user->cloneFrom);
    user->cloneFromLen = 0;
  }
  line = read_config_read_objid(line, &user->cloneFrom, &user->cloneFromLen);
  if (user->authProtocol) {
    free(user->authProtocol);
    user->authProtocolLen = 0;
  }
  line = read_config_read_objid(line, &user->authProtocol,
                                &user->authProtocolLen);
  line = read_config_read_octet_string(line, &user->authKey,
                                       &user->authKeyLen);
  if (user->privProtocol) {
    free(user->privProtocol);
    user->privProtocolLen = 0;
  }
  line = read_config_read_objid(line, &user->privProtocol,
                                &user->privProtocolLen);
  line = read_config_read_octet_string(line, &user->privKey,
                                       &user->privKeyLen);
  line = read_config_read_octet_string(line, &user->userPublicString,
                                       &len);
  return user;
}

/* snmpd.conf parsing routines */
void
usm_parse_config_usmUser(char *token, char *line)
{
  struct usmUser *uptr;

  uptr = usm_read_user(line);
  usm_add_user(uptr);
}

void usm_set_password(char *token, char *line) {
  /* format: userSetAuthPass     secname engineIDLen engineID pass */
  /*     or: userSetPrivPass     secname engineIDLen engineID pass */
  /*     or: userSetAuthKey      secname engineIDLen engineID KuLen Ku */
  /*     or: userSetPrivKey      secname engineIDLen engineID KuLen Ku */
  /*     or: userSetAuthLocalKey secname engineIDLen engineID KulLen Kul */
  /*     or: userSetPrivLocalKey secname engineIDLen engineID KulLen Kul */

  char *cp;
  char nameBuf[SNMP_MAXBUF];
  u_char *engineID;
  int nameLen, engineIDLen;
  struct usmUser *user;

  u_char **key;
  int *keyLen;

  u_char *userKey;
  int userKeyLen;
  int type, ret;
  
  cp = copy_word(line, nameBuf);
  if (cp == NULL) {
    config_perror("invalid name specifier");
    return;
  }
    
  cp = read_config_read_octet_string(cp, &engineID, &engineIDLen);
  if (cp == NULL) {
    config_perror("invalid engineID specifier");
    return;
  }

  user = usm_get_user(engineID, engineIDLen, nameBuf);
  if (user == NULL) {
    config_perror("not a valid user/engineID pair");
    return;
  }

  if (strcmp(token, "userSetAuthPass") == 0) {
    key = &user->authKey;
    keyLen = &user->authKeyLen;
    type = 0;
  } else if (strcmp(token, "userSetPrivPass") == 0) {
    key = &user->privKey;
    keyLen = &user->privKeyLen;
    type = 0;
  } else if (strcmp(token, "userSetAuthKey") == 0) {
    key = &user->authKey;
    keyLen = &user->authKeyLen;
    type = 1;
  } else if (strcmp(token, "userSetPrivKey") == 0) {
    key = &user->privKey;
    keyLen = &user->privKeyLen;
    type = 1;
  } else if (strcmp(token, "userSetAuthLocalKey") == 0) {
    key = &user->authKey;
    keyLen = &user->authKeyLen;
    type = 2;
  } else if (strcmp(token, "userSetPrivLocalKey") == 0) {
    key = &user->privKey;
    keyLen = &user->privKeyLen;
    type = 2;
  }
  
  if (*key) {
    /* (destroy and) free the old key */
    memset(*key, 0, *keyLen);
    free(*key);
  }

  if (type == 0) {
    /* convert the password into a key 
    ret = generate_Ku(cp, strlen(cp), &userKey, &userKeyLen);
	FIXupdate */
  
    if (ret == 1) {
      config_perror("setting key failed (in sc_genKu())");
      return;
    }
  }
   
  if (type == 1) {
    cp = read_config_read_octet_string(cp, &userKey, &userKeyLen);
    
    if (cp == NULL) {
      config_perror("invalid user key");
      return;
    }
  }
  
  if (type < 2) {
    /* generate the kul
    generate_kul(engineID, engineIDLen, userKey, userKeyLen, key, keyLen);
	FIXupdate */
    /* (destroy and) free the old key */
    memset(userKey, 0, userKeyLen);
    free(userKey);
  } else {
    /* the key is given, copy it in */
    cp = read_config_read_octet_string(cp, key, keyLen);
    
    if (cp == NULL) {
      config_perror("invalid localized user key");
      return;
    }
  }
}
