/*
 * scapitest.c
 *
 * Expected SUCCESSes:	2 + 2 + XXX for all tests.
 *
 * Returns:
 *	Number of FAILUREs.
 *
 *
 * XXX	Split into individual modules?
 * XXX	Error/fringe conditions should be tested.
 *
 * Test of sc_random.			SUCCESSes == 2.
 * Test of sc_generate_keyed_hash and sc_check_keyed_hash.
 *					SUCCESSes == 2.
 */

static char *rcsid = "$Id";	/* */


#include "all_system.h"
#include "all_general_local.h"

#include <stdlib.h>

extern char     *optarg;
extern int      optind, optopt, opterr;

#if !defined(__linux__)
extern int	optreset;
#endif



/*
 * Globals, &c...
 */
char *local_progname;

#define USAGE	"Usage: %s [-h][-aHr]"
#define OPTIONLIST	"ahHr"

int	doalltests	= 0,
	dokeyedhash	= 0,
	dorandom	= 0;

#define	ALLOPTIONS	(doalltests + dokeyedhash + dorandom)



#define LOCAL_MAXBUF	(1024 * 8)

#define OUTPUT(o)	fprintf(stdout, "\n\n%s\n\n", o);

#define SUCCESS(s)					\
{							\
	if (!failcount)					\
		fprintf(stdout, "\nSUCCESS: %s\n", s);	\
}

#define FAILED(e, f)					\
{							\
	if (e != SNMPERR_SUCCESS) {			\
		fprintf(stdout, "\nFAILED: %s\n", f);	\
		failcount += 1;				\
	}						\
}


#define BIGSTRING							\
    "   A port may be a pleasant retreat for any mind grown weary of"	\
    "the struggle for existence.  The vast expanse of sky, the"		\
    "mobile architecture of the clouds, the chameleon coloration"	\
    "of the sea, the beacons flashing on the shore, together make"	\
    "a prism which is marvellously calculated to entertain but not"	\
    "fatigue the eye.  The lofty ships with their complex webs of"	\
    "rigging, swayed to and fro by the swell in harmonious dance,"	\
    "all help to maintain a taste for rhythm and beauty in the"		\
    "mind.  And above all there is a mysterious, aristrocratic kind"	\
    "of pleasure to be had, for those who have lost all curiosity"	\
    "or ambition, as they strech on the belvedere or lean over the"	\
    "mole to watch the arrivals and departures of other men, those"	\
    "who still have sufficient strength of purpose in them, the"	\
    "urge to travel or enrich themselves."				\
    "	-- Baudelaire"							\
    "	   From _The_Poems_in_Prose_, \"The Port\" (XLI)."

#define BIGSECRET	"Shhhh... Don't tell *anyone* about this.  Not a soul."
#define BKWDSECRET	".luos a toN  .siht tuoba *enoyna* llet t'noD ...hhhhS"




/*
 * Prototypes.
 */
void	usage(FILE *ofp);
int	test_dorandom(void);
int	test_dokeyedhash(void);




int
main(int argc, char **argv)
{
	int		 rval		= SNMPERR_SUCCESS,
			 failcount	= 0;
	char		 ch;

	local_progname = argv[0];

/* EM(1);	/* */

	/*
	 * Parse.
	 */
	while ( (ch = getopt(argc, argv, OPTIONLIST)) != EOF )
	{
		switch(ch) {
		case 'a':	doalltests = 1;		break;
		case 'H':	dokeyedhash = 1;	break;
		case 'r':	dorandom = 1;		break;
		case 'h':
			rval = 0;
		default:
			usage(stdout);
			exit(rval);
		}

		argc -= 1; argv += 1;
		optind = 1;
#if !defined(__linux__)
		optreset = 1;
#endif

	}  /* endwhile getopt */

	if ((argc > 1)) {
		usage(stdout);
		exit(1000);

	} else if ( ALLOPTIONS != 1 ) {
		usage(stdout);
		exit(1000);
	}


	/*
	 * Test stuff.
	 */
	rval = sc_init();
	FAILED(rval, "sc_init().");

	if (dorandom || doalltests) {
		failcount += test_dorandom();
	}
	if (dokeyedhash || doalltests) {
		failcount += test_dokeyedhash();
	}


	/*
	 * Cleanup.
	 */
	rval = sc_shutdown();
	FAILED(rval, "sc_shutdown().");

	return failcount;

} /* end main() */





void
usage(FILE *ofp)
{
	fprintf(ofp,

	USAGE								"\n"
	""								"\n"
	"	-a		All tests."				"\n"
	"	-h		Help."					"\n"
	"	-H              Test sc_{generate,check}_keyed_hash()." "\n"
	"	-r              Test sc_random()." 			"\n"
	""								"\n"
		, local_progname);

}  /* end usage() */




#ifdef EXAMPLE
/*******************************************************************-o-******
 * test_dosomething
 *
 * Test template.
 *
 * Returns:
 *	Number of failures.
 */
int
test_dosomething(void)
{
	int		rval = SNMPERR_SUCCESS,
			failcount = 0;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

test_dosomething_quit:
	return failcount;

}  /* end test_dosomething() */
#endif /* EXAMPLE */





/*******************************************************************-o-******
 * test_dorandom
 *
 * One large request, one set of short requests.
 *
 * Returns:
 *	Number of failures.
 *
 * XXX	probably should split up into individual options.
 */
int
test_dorandom(void)
{
	int	rval		= SNMPERR_SUCCESS,
		failcount	= 0,
		origrequest	= (1024 * 2),
		origrequest_short = 16,
		nbytes		= origrequest,
		shortcount	= 8,
		printunit	= 64,
		i;
	char	*s, *sp,
		buf[LOCAL_MAXBUF],
		chunk[LOCAL_MAXBUF];

EM(1); /* */


	OUTPUT("Random test -- large request:");

	rval = sc_random(buf, &nbytes);
	FAILED(rval, "sc_random().");

	if (nbytes != origrequest) {
		FAILED(SNMPERR_GENERR,
		    "sc_random() returned different than requested.");
	}

	binary_to_hex(buf, nbytes, &s);
	sp = s;
	nbytes *= 2;

	while (nbytes > 0)
	{
		if (nbytes > printunit) {
			strncpy(chunk, sp, printunit);	
			chunk[printunit] = '\0';
			fprintf(stdout, "\t%s\n", chunk);
		} else {
			fprintf(stdout, "\t%s\n", sp);
		}

		sp	+= printunit;
		nbytes	-= printunit;
	}
	SNMP_FREE(s);

	SUCCESS("Random test -- large request.");


	OUTPUT("Random test -- short requests:");
	origrequest_short = 16;

	for (i = 0; i < shortcount; i++ )
	{
		nbytes = origrequest_short;
		rval = sc_random(buf, &nbytes);
		FAILED(rval, "sc_random().");

		if (nbytes != origrequest_short) {
			FAILED(	SNMPERR_GENERR,
				"sc_random() returned different "
				"than requested.");
		}

		binary_to_hex(buf, nbytes, &s);
		fprintf(stdout, "    %s\n", s);
		SNMP_FREE(s);
	}  /* endfor */

	SUCCESS("Random test -- short requests.");


	return failcount;

}  /* end test_dorandom() */



/*******************************************************************-o-******
 * test_dokeyedhash
 *
 * FIX	Get input or output from some other package which hashes...
 *
 * XXX	Could cut this in half with a little indirection...
 *
 * Returns:
 *	Number of failures.
 */
int
test_dokeyedhash(void)
{
	int		 rval		 = SNMPERR_SUCCESS,
			 failcount	 = 0,
			 bigstring_len	 = strlen(BIGSTRING),
			 secret_len	 = strlen(BIGSECRET),
			 properlength;

	u_int		 hashbuf_len     = LOCAL_MAXBUF;

	u_char		 hashbuf[LOCAL_MAXBUF];

/* EM(1); /* */


	OUTPUT("Keyed hash test using MD5 --");

	memset(hashbuf, 0, LOCAL_MAXBUF);

	rval = sc_generate_keyed_hash(
		usmHMACMD5AuthProtocol, USM_LENGTH_OID_TRANSFORM,
		BIGSECRET, secret_len,
		BIGSTRING, bigstring_len,
		hashbuf, &hashbuf_len);
	FAILED(rval, "sc_generate_keyed_hash().");

	properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);
	if (hashbuf_len != properlength) {
		FAILED(SNMPERR_GENERR, "Wrong MD5 hash length returned.");
	}

	rval = sc_check_keyed_hash(
		usmHMACMD5AuthProtocol, USM_LENGTH_OID_TRANSFORM,
		BIGSECRET, secret_len,
		BIGSTRING, bigstring_len,
		hashbuf, hashbuf_len);
	FAILED(rval, "sc_check_keyed_hash().");

	SUCCESS("Keyed hash test using MD5.");



	OUTPUT("Keyed hash test using SHA1 --");

	memset(hashbuf, 0, LOCAL_MAXBUF);
	hashbuf_len = LOCAL_MAXBUF;
	secret_len  = strlen(BKWDSECRET);


	rval = sc_generate_keyed_hash(
		usmHMACSHA1AuthProtocol, USM_LENGTH_OID_TRANSFORM,
		BKWDSECRET, secret_len,
		BIGSTRING, bigstring_len,
		hashbuf, &hashbuf_len);
	FAILED(rval, "sc_generate_keyed_hash().");

	properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
	if (hashbuf_len != properlength) {
		FAILED(SNMPERR_GENERR, "Wrong SHA1 hash length returned.");
	}

	rval = sc_check_keyed_hash(
		usmHMACSHA1AuthProtocol, USM_LENGTH_OID_TRANSFORM,
		BKWDSECRET, secret_len,
		BIGSTRING, bigstring_len,
		hashbuf, hashbuf_len);
	FAILED(rval, "sc_check_keyed_hash().");

	SUCCESS("Keyed hash test using SHA1.");



	return failcount;

}  /* end test_dokeyedhash() */

