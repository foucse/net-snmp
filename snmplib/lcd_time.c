/*
 * lcd_time.c
 */

#include "all_system.h"
#include "all_general_local.h"


/*
 * Global static hashlist to contain Enginetime entries.
 */
static Enginetime eidlist[HASHLIST_SIZE];




/*******************************************************************-o-******
 * get_enginetime
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *	*enginetime
 *	*engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 *
 * Lookup engineID and return the recorded values for the
 * <enginetime, engineboot> tuple adjusted to reflect the estimated time
 * at the engine in question.
 *
 *
 * FIX	Check case of NULL or "" engineID (sez Ed).
 * FIX	Need to initialize eidlist?
 */
int
get_enginetime(	u_char	*engineID,	
		u_int	 engineID_len,
		u_int	*enginetime,	
		u_int	*engineboot)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

get_enginetime_quit:
	return 0;

}  /* end get_enginetime() */



/*******************************************************************-o-******
 * set_enginetime
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *	 enginetime
 *	 engineboot
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 *
 * Lookup engineID and record the given <enginetime, engineboot> tuple
 * and timestamp the change with the current time within the local engine.
 * If the engineID record does not exist, create one.
 *
 * XXX	"Current time within the local engine" == time(NULL)...
 */
int
set_enginetime(	u_char	*engineID,
		u_int	 engineID_len,
		u_int  	 enginetime,
		u_int	 engineboot)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

write_enginetime_quit:
	return rval;

}  /* end write_enginetime() */




/*******************************************************************-o-******
 * traverse_enginetime_list
 *
 * Parameters:
 *      
 * Returns:
 *	SNMPERR_SUCCESS		Success.
 */
Enginetime *
traverse_enginetime_list(Enginetime *e, u_char *engineID, u_int engineID_len)
{
	int		rval = SNMPERR_SUCCESS;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */


traverse_enginetime_list_quit:
	return NULL;

}  /* end traverse_enginetime_list() */





/*******************************************************************-o-******
 * hash_engineID
 *
 * Parameters:
 *	*engineID
 *	 engineID_len
 *      
 * Returns:
 *	>1				eidlist index for this engineID.
 *	SNMPERR_SUCCESS			Success.
 *	SNMPERR_SC_GENERAL_FAILURE	Error.
 *	
 * 
 * Use a traditional hash to build an index into the eidlist.  Method is 
 * to hash the engineID, then split the hash into longs and add them up.
 * Modulo the sum and add 1 to give the hash.  Calling environment will 
 * need to subtract one.  This last addition is only to avoid collusion with
 * the error code for success.
 *
 */
int
hash_engineID(u_char *engineID, u_int engineID_len)
{
	int		  rval		= SNMPERR_SUCCESS, 
			  buf_len	= SNMP_MAXBUF;

	u_int		  additive	= 0;

	char		 *bufp,
			  buf[SNMP_MAXBUF];

	void		**context;

EM(1); /* */


	SET_HASH_TRANSFORM(kmt_s_md5);

	rval = kmt_hash(KMT_CRYPT_MODE_ALL, context,
			engineID, engineID_len,
			&buf, &buf_len);
	QUITFUN(rval, hash_engineID_quit);

	for ( bufp = buf; (bufp-buf) < buf_len; bufp += 4 ) {
		additive += (u_int) bufp;
	}
	rval = (additive % HASHLIST_SIZE) + 1;


hash_engineID_quit:
	SNMP_FREE(context);
	memset(buf, 0, SNMP_MAXBUF);

	return rval;

}  /* end hash_engineID() */


