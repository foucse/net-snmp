
/* snmpMPDStats.c: tallies errors for SNMPv3 message processing. */

#include <config.h>

#include "mibincl.h"
#include "snmpMPDStats.h"

static int MPDErrors[3];

void init_snmpMPDStats(void) {
  int i;
  
  for(i=0; i < 3; i++)
    MPDErrors[i] = 0;
}

void incr_snmpMPDStat(int which) {
  if (which >= 0 && which < 3)
    MPDErrors[which]++;
}


unsigned char *
var_snmpMPDStats(vp, name, length, exact, var_len, write_method)
    struct variable *vp;
    oid     *name;
    int     *length;
    int     exact;
    int     *var_len;
    int     (**write_method) __P((int, unsigned char *,unsigned char, int, unsigned char *,oid*, int));
{

  /* variables we may use later */
  static long long_ret;
  static unsigned char string[1500];
  static oid objid[30];
  static struct counter64 c64;

  *write_method = 0;           /* assume it isnt writable for the time being */
  *var_len = sizeof(long_ret); /* assume an integer and change later if not */

  if (header_generic(vp,name,length,exact,var_len,write_method))
      return 0;

  /* this is where we do the value assignments for the mib results. */

  if (vp->magic >= 0 && vp->magic <= 2) {
    long_ret = MPDErrors[vp->magic];
    return (unsigned char *) &long_ret;
  }
  return 0;
}

