/*
 * etimetest.c
 *
 * Expected SUCCESSes:	FIX -- list number of lines containing the string
 *			"SUCCESS" that are expected to be printed to stdout.
 *
 * Returns:
 *	Number of FAILUREs.
 *
 * FIX	Short test description/table of contents.
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

#define USAGE	"Usage: %s [-h][-ae]"
#define OPTIONLIST	"aeh"

int	doalltests	= 0,
	doetimetest	= 0;

#define	ALLOPTIONS	(doalltests + doetimetest)



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
 * Prototypes.
 */
void	usage(FILE *ofp);
int	test_dosomething(void);




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
		case 'e':	doetimetest = 1;	break;
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
	if (doetimetest || doalltests) {
		failcount += test_etime();
	}


	/*
	 * Cleanup.
	 */
	return failcount;

} /* end main() */





void
usage(FILE *ofp)
{
	fprintf(ofp,

	USAGE								
	""								NL
	"	-a	All tests."					NL
	"	-e	Test engine time maintenance somehow.  FIX"	NL
	"	-h	Help."						NL
	""								NL
		, local_progname);

}  /* end usage() */




#ifdef EXAMPLE
/*******************************************************************-o-******
 * test_dosomething
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test template.
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
 * test_etime
 *
 * Returns:
 *	Number of failures.
 *
 *
 * Test template.  FIX
 */
int
test_etime(void)
{
	int		rval = SNMPERR_SUCCESS,
			failcount = 0;

EM0(1, "UNIMPLEMENTED");	/* EM(1); /* */

test_etime_quit:
	return failcount;

}  /* end test_etime() */

