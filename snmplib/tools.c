/*
 * tools.c
 */

#include "tools.h"




/*******************************************************************-o-******
 * free_zero
 *
 * Parameters:
 *	*buf	Pointer at bytes to free.
 *	size	Number of bytes in buf.
 */
void
free_zero(void *buf, u_long size)
{
	if (buf) {
		memset(buf, 0, size);
		free(buf);
	}

}  /* end free_zero() */




/*******************************************************************-o-******
 * malloc_random
 *
 * Parameters:
 *	size	Number of bytes to malloc() and fill with random bytes.
 *      
 * Returns:
 *	<char *>	Pointer to allocaed & set buffer on success.
 *
 * XXX	Degenerates to malloc_zero if HAVE_LIBKMT is not defined.
 */
char *
malloc_random(u_long size)
{
	int	rval = SNMPERR_SUCCESS;
	u_long	actualsize = size;
	char	*buf = (char *) malloc_zero(size);

#ifdef							HAVE_LIBKMT
	if (buf) {
		rval = kmt_random(KMT_RAND_DEFAULT, buf, actualsize);

		if (rval < 0) {
			/* FIX -- Log an error? */
		}
		if (actualsize != rval) {
			/* FIX -- Log an error? */
		}

	} else {
		; /* FIX -- Log a fatal error? */
	}
#endif							/* HAVE_LIBKMT */


	return buf;

}  /* end malloc_random() */




/*******************************************************************-o-******
 * malloc_zero
 *
 * Parameters:
 *	size	Number of bytes to malloc().
 *      
 * Returns:
 *	<char *>	Pointer to allocaed & zeroed buffer on success.
 */
char *
malloc_zero(u_long size)
{
	return (char *) malloc_set(size, 0);

}  /* end malloc_zero() */

