#include <config.h>

#include <stdio.h>
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

static int engineBoots=0;
static char *engineID=NULL;
static int engineIDLength=0;

/* places a malloced copy of the engineID into engineID */
void
setup_engineID(char *text) {

#define MAX_HOSTNAME_LEN 512
  int netid = htonl(ENTERPRISE_NUMBER);
  char buf[MAX_HOSTNAME_LEN];
  struct hostent *hent;
  
  if (engineID)
    free(engineID);
  
  if (text) {
    engineIDLength = 5 + strlen(text);  /* 5 leading bytes + text */
  } else {
    engineIDLength = 5 + 4;  /* 5 leading bytes + four byte IPv4 address */
    gethostname(buf, MAX_HOSTNAME_LEN);
    hent = gethostbyname(buf);
#ifdef AF_INET6
    if (hent->h_addrtype == AF_INET6)
      engineIDLength += 2;
#endif
  }
  if ((engineID = (char *) malloc(engineIDLength)) == NULL) {
    /* malloc failed */
    snmp_perror("malloc");
    return;
  }

  memcpy(engineID, &netid, sizeof(netid)); /* this had better be 4 bytes */
  engineID[0] |= 0x80;
  
  if (text) {
    engineID[4] = 4;
    sprintf(engineID+5,text);
  } else {
    engineID[4] = 1;
    gethostname(buf, MAX_HOSTNAME_LEN);
    hent = gethostbyname(buf);
#ifdef AF_INET6
    if (hent->h_addrtype == AF_INET6) {
      engineID[4] = 2;
      memcpy(engineID+5, hent->h_addr_list[0], hent->h_length);
    } else
#endif
    if (hent->h_addrtype == AF_INET) {
      memcpy(engineID+5, hent->h_addr_list[0], hent->h_length);
    } else {
      /* sigh...  unknown address type.  Default to 127.0.0.1 */
      engineID[5] = 127;
      engineID[6] = 0;
      engineID[7] = 0;
      engineID[8] = 1;
    }
  }
}

void
engineBoots_conf(char *word, char *cptr)
{
  engineBoots = atoi(cptr)+1;
  DEBUGP("engineBoots: %d\n",engineBoots);
}

void
engineID_conf(char *word, char *cptr)
{
  setup_engineID(cptr);
  DEBUGP("initialized engineID with: %s\n",cptr);
}

void
init_snmpv3(char *type) {
  setup_engineID(NULL);
  register_config_handler(type,"engineBoots", engineBoots_conf, NULL);
  register_config_handler(type,"engineID", engineID_conf, NULL);
}

void
shutdown_snmpv3(char *type) {
  char line[512];
  sprintf(line, "engineBoots %d", engineBoots);
  read_config_store(type, line);
}

int
snmpv3_get_engine_boots(void) {
  return engineBoots;
}

int
snmpv3_get_engineID(char *buf) {
  memcpy(buf,engineID,engineIDLength);
  return engineIDLength;
}
