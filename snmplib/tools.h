/*
 * tools.h
 */

#ifndef _TOOLS_H
#define _TOOLS_H



/* 
 * Macros and constants.
 */
#define SNMP_MAXBUF		4096
#define SNMP_MAXBUF_SMALL	512

#define SNMP_FILEMODE		0600

#define BYTESIZE(bitsize)       ((bitsize + 7) >> 3)


#define SNMP_FREE(s)		if (s) free((void *)s);
#define SNMP_MALLOC(s)		malloc_zero(s)


#define TOUPPER(c)	(c >= 'a' && c <= 'z' ? c - ('a' - 'A') : c)
#define TOLOWER(c)	(c >= 'A' && c <= 'Z' ? c + ('a' - 'A') : c)

#define HEX2VAL(s) \
	((isalpha(s) ? (TOLOWER(s)-'a'+10) : (TOLOWER(s)-'0')) & 0xf)
#define VAL2HEX(s)	( (s) + (((s) >= 10) ? ('a'-10) : '0') )



/* XXX	Got these two somewhere already?
 */
#define SNMP_MAX(a,b) ((a) > (b) ? (a) : (b))
#define SNMP_MIN(a,b) ((a) > (b) ? (b) : (a))

/*
 * QUIT the FUNction:
 *	e	Error code variable
 *	l	Label to goto to cleanup and get out of the function.
 *
 * XXX	It would be nice if the label could be constructed by the
 *	preprocessor in context.  Limited to a single error return value.
 *	Temporary hack at best.
 */
#define QUITFUN(e, l)			\
	if (e != SNMPERR_SUCCESS) {	\
		rval = SNMPERR_GENERR;	\
		goto l ;		\
	}



/* 
 * Prototypes.
 */
void	free_zero __P((void *buf, u_long size));

char   *malloc_random __P((int *size));
char   *malloc_zero __P((u_long size));
int     memdup __P((u_char **to, u_char *from, u_int size));

u_int	binary_to_hex __P((char *input, u_long len, char **output));
int	hex_to_binary2 __P((char *input, u_long len, char **output));

void	dump_chunk __P((char *buf, int size));
char   *dump_snmpEngineID __P((u_char *buf, u_int *buflen));



#endif /* _TOOLS_H */

