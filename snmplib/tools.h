/*
 * tools.h
 */

#ifndef _TOOLS_H
#define _TOOLS_H

#include "all_system.h"
#include "all_general_local.h"




/* 
 * Macros and constants.
 */
#define SNMP_MAXBUF		4096
#define SNMP_FILEMODE		0600

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)

#define SNMP_FREE(s)		if (s) free_zero((void *)s);
#define SNMP_MALLOC(s)		malloc_zero(s)



/* 
 * Prototypes.
 */
void	free_zero __P((void *buf, u_long size));

char   *malloc_random __P((u_long size));
char   *malloc_zero __P((u_long size));



#endif /* _TOOLS_H */

