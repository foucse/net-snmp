/*
 * snmpv3.c
 */

#include <config.h>

#include <stdio.h>
#if TIME_WITH_SYS_TIME
# include <sys/time.h>
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h>
# else
#  include <time.h>
# endif
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#if HAVE_UNISTD_H
#include <unistd.h>
#endif
#if HAVE_WINSOCK_H
#include <winsock.h>
#else
#include <sys/socket.h>
#include <netdb.h>
#endif
#if HAVE_STDLIB_H
#       include <stdlib.h>
#endif


#include "system.h"
#include "asn1.h"
#include "snmpv3.h"
#include "snmpusm.h"
#include "snmp.h"
#include "snmp_api.h"
#include "read_config.h"
#include "scapi.h"
#include "tools.h"




static int		 engineBoots	 = 0;
static char		*engineID	 = NULL;
static int		 engineIDLength	 = 0;
static struct timeval	 snmpv3starttime;


/* 
 * Set up default snmpv3 parameter value storage.
 */
static char	*defaultSecName		= NULL;
static char	*defaultContext		= NULL;
int		defaultSecurityLevel	= 0;




void
snmpv3_secName_conf(char *word, char *cptr)
{
  if (defaultSecName)
    free(defaultSecName);
  defaultSecName = strdup(cptr);
  DEBUGP("default security name set to: %s\n",defaultSecName);
}

char *
get_default_secName(void)
{
  return defaultSecName;
}

void
snmpv3_context_conf(char *word, char *cptr)
{
  if (defaultContext)
    free(defaultContext);
  defaultContext = strdup(cptr);
  DEBUGP("default context set to: %s\n",defaultContext);
}

char *
get_default_context(void)
{
  return defaultContext;
}

void
snmpv3_secLevel_conf(char *word, char *cptr)
{
  char buf[1024];
  
  if (strcmp(cptr,"noAuthNoPriv") == 0 || strcmp(cptr, "1") == 0)
    defaultSecurityLevel = SNMP_SEC_LEVEL_NOAUTH;
  else if (strcmp(cptr,"authNoPriv") == 0 || strcmp(cptr, "2") == 0)
    defaultSecurityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;
  else if (strcmp(cptr,"authPriv") == 0 || strcmp(cptr, "3") == 0)
    defaultSecurityLevel = SNMP_SEC_LEVEL_AUTHPRIV;
  else {
    sprintf(buf,"unknown security level: cptr");
    config_perror(buf);
  }
  DEBUGP("default secLevel set to: %s = %d\n", cptr, defaultSecurityLevel);
}

int
get_default_secLevel(void)
{
  return defaultSecurityLevel;
}




/*******************************************************************-o-******
 * setup_engineID
 *
 * Parameters:
 *	*text	Printable (?) text to be plugged into the snmpEngineID.
 *
 * XXX	Does the TC require a minimum length of 12?
 * XXX	Is text a NULL-terminated printable string?
 * XXX	What if a node has multiple interfaces?
 * XXX	What if multiple engines all choose the same address?  There must
 *	  be some additional enumeration.  (Static counter?)
 */
void
setup_engineID(char *text)
{
  int netid = htonl(ENTERPRISE_NUMBER);
  char buf[SNMP_MAXBUF_SMALL];
  struct hostent *hent;
  
  if (engineID)
    free(engineID);

  
  if (text) {
    engineIDLength = 5+strlen(text)+1; /* 5 leading bytes + text + null char. */
  } else {
    engineIDLength = 5 + 4;  /* 5 leading bytes + four byte IPv4 address */
    gethostname(buf, SNMP_MAXBUF_SMALL);
    hent = gethostbyname(buf);
#ifdef AF_INET6
    if (hent && hent->h_addrtype == AF_INET6)
      engineIDLength += 12;	/* 16 bytes total for IPv6 address. */
#endif
  }  /* endif -- text (1) */


  if ((engineID = (char *) malloc(engineIDLength)) == NULL) {
    /* malloc failed */
    perror("malloc");
    return;
  }


  memcpy(engineID, &netid, sizeof(netid)); /* XXX this had better be 4 bytes */
  engineID[0] |= 0x80;
  
  if (text) {
    engineID[4] = 4;
    sprintf(engineID+5,text);

  } else {
    engineID[4] = 1;
    gethostname(buf, SNMP_MAXBUF_SMALL);
    hent = gethostbyname(buf);
#ifdef AF_INET6
    if (hent && hent->h_addrtype == AF_INET6) {
      engineID[4] = 2;
      memcpy(engineID+5, hent->h_addr_list[0], hent->h_length);
    } else
#endif

    if (hent && hent->h_addrtype == AF_INET) {
      memcpy(engineID+5, hent->h_addr_list[0], hent->h_length);

    } else {
      /* sigh...  unknown address type.  Default to 127.0.0.1 */
      engineID[5] = 127;
      engineID[6] = 0;
      engineID[7] = 0;
      engineID[8] = 1;
    }
  }  /* endif -- text (2) */

}  /* end setup_engineID() */



void
engineBoots_conf(char *word, char *cptr)
{
  engineBoots = atoi(cptr)+1;
  DEBUGP("engineBoots: %d\n",engineBoots);
}



/*******************************************************************-o-******
 * engineID_conf
 *
 * Parameters:
 *	*word
 *	*cptr
 *
 * FIX	cptr should be treated as a non-printable octet string, or perhaps
 *	converted from a printable hex string...  (?)
 */
void
engineID_conf(char *word, char *cptr)
{
  setup_engineID(cptr);
  DEBUGP("initialized engineID with: %s\n",cptr);
}




/*******************************************************************-o-******
 * init_snmpv3
 *
 * Parameters:
 *	*type	Label for the config file "type" used by calling entity.
 *      
 * Set time and engineID.
 * Set parsing functions for config file tokens.
 * Initialize SNMP Crypto API (SCAPI).
 */
void
init_snmpv3(char *type) {
  gettimeofday(&snmpv3starttime, NULL);
  setup_engineID(NULL);
  register_config_handler(type,"engineBoots", engineBoots_conf, NULL);
  register_config_handler(type,"engineID", engineID_conf, NULL);
  register_config_handler("snmp","defSecurityName", snmpv3_secName_conf, NULL);
  register_config_handler("snmp","defContext", snmpv3_context_conf, NULL);
  register_config_handler("snmp","defSecurityLevel", snmpv3_secLevel_conf,
                          NULL);
  register_config_handler(type,"userSetAuthPass", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivPass", usm_set_password, NULL);
  register_config_handler(type,"userSetAuthKey", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivKey", usm_set_password, NULL);
  register_config_handler(type,"userSetAuthLocalKey", usm_set_password, NULL);
  register_config_handler(type,"userSetPrivLocalKey", usm_set_password, NULL);
#if		!defined(USE_INTERNAL_MD5)
	sc_init();
#endif		/* !USE_INTERNAL_MD5 */
}

/*******************************************************************-o-******
 * shutdown_snmpv3
 *
 * Parameters:
 *	*type
 */
void
shutdown_snmpv3(char *type)
{
	char            line[SNMP_MAXBUF_SMALL];

	sprintf(line, "engineBoots %d", engineBoots);
	read_config_store(type, line);

#if		!defined(USE_INTERNAL_MD5) 
	sc_shutdown();
#endif		/* !USE_INTERNAL_MD5 */

}  /* shutdown_snmpv3() */




int
snmpv3_local_snmpEngineBoots(void)
{
  return engineBoots;
}


/*******************************************************************-o-******
 * snmpv3_get_engineID
 *
 * Parameters:
 *	*buf
 *	 buflen
 *      
 * Returns:
 *	Length of engineID	On Success
 *	SNMPERR_GENERR		Otherwise.
 *
 *
 * Store engineID in buf; return the length.
 */
int
snmpv3_get_engineID(char *buf, int buflen)
{
  /*
   * Sanity check.
   */
  if ( !buf || (buflen < engineIDLength) ) {
    return SNMPERR_GENERR;
  }

  memcpy(buf,engineID,engineIDLength);
  return engineIDLength;

}  /* end snmpv3_get_engineID() */





/*******************************************************************-o-******
 * snmpv3_generate_engineID
 *
 * Parameters:
 *	*length
 *      
 * Returns:
 *	Pointer to copy of engineID	On Success.
 *	NULL				If malloc() or snmpv3_get_engineID()
 *						fail.
 *
 * Generates a malloced copy of our engineID.
 *
 * 'length' is set to the length of engineID  -OR-  < 0 on failure.
 */
u_char *
snmpv3_generate_engineID(int *length)
{
  char *newID;
  newID = (char *) malloc(engineIDLength);

  if (newID) {
    *length = snmpv3_get_engineID(newID, engineIDLength);
  }

  if (*length < 0) {
    SNMP_FREE(newID);
    newID = NULL;
  }

  return newID;

}  /* end snmpv3_generate_engineID() */



/* snmpv3_local_snmpEngineTime(): return the number of seconds since the
   snmpv3 engine last incremented engine_boots */
int
snmpv3_local_snmpEngineTime(void)
{
  struct timeval now;

  gettimeofday(&now, NULL);
  return calculate_time_diff(&now, &snmpv3starttime)/100;
}
