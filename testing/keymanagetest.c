/*
 * keymanagetest.c
 *
 * Expected SUCCESSes:	2 + 2 + XXX for all tests.
 *
 * Returns:
 *	Number of FAILUREs.
 * 
 *
 * FIX	Useful to allow usmUser key (U) and/or localized key (L) to be
 *	entered with commandline option?
 * FIX	Or how about passing a usmUser name and looking up the entry as
 *	a means of getting key material?  This means the userList is
 *	available from an application...
 *
 * ASSUMES  No key management functions return non-zero success codes.
 *
 * Test of generate_Ku().			SUCCESSes: 2
 * Test of generate_kul().			SUCCESSes: 2
 */

static char *rcsid = "$Id$";	/* */

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

#define USAGE	"Usage: %s [-h][-alu][-E <engineID>][-P <passphrase>]"
#define OPTIONLIST	"aE:hlP:u"

int	doalltests	= 0,
	dogenKu		= 0,
	dogenkul	= 0;

#define	ALLOPTIONS	(doalltests + dogenKu + dogenkul)


#define LOCAL_MAXBUF	(1024 * 8)
#define NL		"\n"

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



/*
 * Test specific globals.
 */
#define	ENGINEID_DEFAULT	"1.2.3.4wild"
#define PASSPHRASE_DEFAULT	"Clay's Conclusion: Creativity is great, " \
					"but plagiarism is faster."

char	*engineID	= NULL;
char	*passphrase	= NULL;




/*
 * Prototypes.
 */
void	usage(FILE *ofp);
int	test_genkul(void);
int	test_genKu(void);




int
main(int argc, char **argv)
{
	int		 rval		= SNMPERR_SUCCESS,
			 failcount	= 0;
	char		 ch;

	local_progname = argv[0];
	optarg = NULL;

/* EM(1);	/* */

	/*
	 * Parse.
	 */
	while ( (ch = getopt(argc, argv, OPTIONLIST)) != EOF )
	{
		switch(ch) {
		case 'a':	doalltests = 1;		break;
		case 'E':	engineID = optarg;	break;
		case 'l':	dogenkul = 1;		break;
		case 'P':	passphrase = optarg;	break;
		case 'u':	dogenKu = 1;		break;
		case 'h':
			rval = 0;
		default:
			usage(stdout);
			exit(rval);
		}

		argc -= 1; argv += 1;
		if (optarg) {
			argc -= 1; argv += 1;
		}
			
		optind = 1;
		optarg = NULL;
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

	if (dogenKu || doalltests) {
		failcount += test_genKu();
	}
	if (dogenkul || doalltests) {
		failcount += test_genkul();
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

	USAGE								
	""								NL
	"	-a		All tests."				NL
	"	-E <engineId>	snmpEngineID string."			NL
	"	-l		generate_kul()."			NL
	"	-h		Help."					NL
	"	-P <passphrase>	Source string for usmUser master key."	NL
	"	-u		generate_Ku()."				NL
	""								NL
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
 * test_genKu
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test generation of usmUser master key from a passphrase.
 *
 * ASSUMES  Passphrase is made of printable characters!
 */
int
test_genKu(void)
{
	int		 rval		= SNMPERR_SUCCESS,
			 failcount	= 0,
			 properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5),
			 kulen;
	char		*hashname = "usmHMACMD5AuthProtocol.",
			*s;
	u_char		 Ku[LOCAL_MAXBUF];
	oid		*hashtype =  usmHMACMD5AuthProtocol;

/* EM(1); /* */


	OUTPUT("Test of generate_Ku --");
	
	/*
	 * Set passphrase.
	 */
	if (!passphrase) {
		passphrase = PASSPHRASE_DEFAULT;
	}
	fprintf(stdout, "Passphrase%s:\n\t%s\n\n",
		(passphrase == PASSPHRASE_DEFAULT) ? " (default)" : "",
		passphrase);

		
test_genKu_again:
	memset(Ku, 0, LOCAL_MAXBUF);
	kulen = LOCAL_MAXBUF;

	rval = generate_Ku(	hashtype, USM_LENGTH_OID_TRANSFORM,
				passphrase, strlen(passphrase),
				Ku, &kulen);
	FAILED(rval, "generate_Ku().");

	if (kulen != properlength) {
		FAILED(SNMPERR_GENERR, "Ku length is wrong for this hashtype.");
	}

	binary_to_hex(Ku, kulen, &s);
	fprintf(stdout, "Ku (len=%d):  %s\n", kulen, s);
	free_zero(s, kulen);

	SUCCESS(hashname);
	fprintf(stdout, "\n");

	if (hashtype == usmHMACMD5AuthProtocol) {
		hashtype	=  usmHMACSHA1AuthProtocol;
		hashname	= "usmHMACSHA1AuthProtocol.";
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
		goto test_genKu_again;
	}


	return failcount;

}  /* end test_genKu() */




/*******************************************************************-o-******
 * test_genkul
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test of generate_kul().
 *
 * A passphrase and engineID are hashed into a master key Ku using
 * both known hash transforms.  Localized keys, also using both hash
 * transforms, are generated from each of these master keys.
 *
 * ASSUME  generate_Ku is already tested.
 */
int
test_genkul(void)
{
	int		 rval		= SNMPERR_SUCCESS,
			 failcount	= 0,
			 properlength,
			 kulen,
			 kul_len;
	char		*testname    = "Using HMACMD5 to create master key.",
			*hashname_Ku = "usmHMACMD5AuthProtocol",
			*hashname_kul,
			*s;
	u_char		 Ku[LOCAL_MAXBUF],
			 kul[LOCAL_MAXBUF];
	oid		*hashtype_Ku =  usmHMACMD5AuthProtocol,
			*hashtype_kul;

EM(1); /* */


	OUTPUT("Test of generate_kul --");
	

	/*
	 * Set passphrase and engineID.
	 */
	if (!passphrase) {
		passphrase = PASSPHRASE_DEFAULT;
	}
	fprintf(stdout, "Passphrase%s:\n\t%s\n\n",
		(passphrase == PASSPHRASE_DEFAULT) ? " (default)" : "",
		passphrase);
	if (!engineID) {
		engineID = ENGINEID_DEFAULT;
	}
	fprintf(stdout, "engineID%s:  %s\n\n",
		(engineID == ENGINEID_DEFAULT) ? " (default)" : "",
		engineID);


	/*
	 * Create a master key using both hash transforms; create localized
	 * keys using both hash transforms from each master key.
	 */
test_genkul_again_master:
	memset(Ku, 0, LOCAL_MAXBUF);
	kulen = LOCAL_MAXBUF;
	hashname_kul = "usmHMACMD5AuthProtocol";
	hashtype_kul =  usmHMACMD5AuthProtocol;
	properlength = BYTESIZE(SNMP_TRANS_AUTHLEN_HMACMD5);


	rval = generate_Ku(	hashtype_Ku, USM_LENGTH_OID_TRANSFORM,
				passphrase, strlen(passphrase),
				Ku, &kulen);
	FAILED(rval, "generate_Ku().");

	binary_to_hex(Ku, kulen, &s);
	fprintf(stdout, "\nMaster Ku using \"%s\":\n\t%s\n\n", hashname_Ku, s);
	free_zero(s, kulen);


test_genkul_again_local:
	memset(kul, 0, LOCAL_MAXBUF);
	kul_len = LOCAL_MAXBUF;

	rval = generate_kul(	hashtype_kul, USM_LENGTH_OID_TRANSFORM,
				engineID, strlen(engineID),
				Ku, kulen,
				kul, &kul_len);
	FAILED(rval, "generate_kul().");

	if (kul_len != properlength) {
		FAILED(	SNMPERR_GENERR,
			"kul length is wrong for the given hashtype.");
	}

	binary_to_hex(kul, kul_len, &s);
	fprintf(stdout, "kul (len=%d):  %s\n", kul_len, s);
	free_zero(s, kul_len);


	/* Create localized key using the other hash transform, but from
	 * the same master key.
	 */
	if (hashtype_kul == usmHMACMD5AuthProtocol) {
		hashtype_kul	=  usmHMACSHA1AuthProtocol;
		hashname_kul	= "usmHMACSHA1AuthProtocol";
		properlength	= BYTESIZE(SNMP_TRANS_AUTHLEN_HMACSHA1);
		goto test_genkul_again_local;
	}

	SUCCESS(testname);


	/* Re-create the master key using the other hash transform.
	 */
	if (hashtype_Ku == usmHMACMD5AuthProtocol) {
		hashtype_Ku	=  usmHMACSHA1AuthProtocol;
		hashname_Ku	= "usmHMACSHA1AuthProtocol";
		testname	= "Using HMACSHA1 to create master key.";
		goto test_genkul_again_master;
	}


test_genkul_quit:
	return failcount;

}  /* end test_genkul() */

