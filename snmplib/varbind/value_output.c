/*******************************
 *
 *	varbind/value_output.c
 *
 *	Net-SNMP library - Variable-handling interface
 *
 *	Value output routines
 *
 *******************************/

#include <config.h>

#include <ctype.h>
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif


#include <net-snmp/var_api.h>
#include <net-snmp/mib_api.h>
#include <net-snmp/utils.h>

#include "default_store.h"

#define _R( x )	if ( x < 0 ) { return -1; }

	/*
	 *  Let's try and hide the 'opaque wrapping' of these
	 *    types within the PDU building/parsing routines.
	 */
#define _OPAQUE(x)	(0x30 + (x))
#define	ASN_OPAQUE_COUNTER64	_OPAQUE(ASN_COUNTER64)
#define	ASN_OPAQUE_DOUBLE	_OPAQUE(ASN_DOUBLE)
#define	ASN_OPAQUE_FLOAT	_OPAQUE(ASN_FLOAT)
#define	ASN_OPAQUE_I64		_OPAQUE(ASN_INTEGER64)
#define	ASN_OPAQUE_U64		_OPAQUE(ASN_UNSIGNED64)

int val_print_int(    netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_uint(   netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_tticks( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_count64(netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );

int val_print_netaddr(netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_ipaddr( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_nsapaddr(netsnmp_buf buf, netsnmp_value value, netsnmp_mib mib );

int val_print_oid(    netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_null(   netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );

int val_print_octetstr(netsnmp_buf buf, netsnmp_value value, netsnmp_mib mib );
int val_print_bitstr( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );

int val_print_opaque( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_float(  netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );
int val_print_double( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib );


int val_print_string( netsnmp_buf buf,  char* string, int strlen, netsnmp_mib mib );
int val_print_hexstr( netsnmp_buf buf,  char* string, int strlen, netsnmp_mib mib );

		/**************************************
		 *
		 *	Public API
		 *	   (see <net-snmp/varbind_api.h>)
		 *
		 **************************************/
		/** @package varbind_api */


   /**
    *
    *  Prints the specified value in the expandable buffer provided.
    *
    *  Returns 0 if successful, -ve otherwise.
    *
    */
int var_bprint_value(  netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    if (( buf   == NULL ) ||
        ( value == NULL )) {
		/*
		 * mib == NULL is quite OK.
		 * This simply means that we can't apply any
		 *   OID-specific semantics to how we display this value
		 */
	return -1;
    }

    switch( value->type ) {
	case ASN_INTEGER:
	    return val_print_int(     buf, value, mib );
	case ASN_OCTET_STR:
	    return val_print_octetstr(buf, value, mib );
	case ASN_BIT_STR:
	    return val_print_bitstr(  buf, value, mib );
	case ASN_OPAQUE:
	    return val_print_opaque(  buf, value, mib );
	case ASN_OBJECT_ID:
	    return val_print_oid(     buf, value, mib );
	case ASN_TIMETICKS:
	    return val_print_tticks(  buf, value, mib );
	case ASN_IPADDRESS:
	    return val_print_ipaddr(  buf, value, mib );
	case ASN_NULL:
	    return val_print_null(    buf, value, mib );
	case ASN_GAUGE:
	case ASN_COUNTER:
	case ASN_UINTEGER:
	    return val_print_uint(    buf, value, mib );
	case ASN_COUNTER64:
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_COUNTER64:
	    return val_print_count64( buf, value, mib );
	case ASN_OPAQUE_FLOAT:
	    return val_print_float(   buf, value, mib );
	case ASN_OPAQUE_DOUBLE:
	    return val_print_double(  buf, value, mib );
	default:
	    (void)buffer_append_string( buf, "Variable has bad type" );
	    return -1;
    }
    return -1;
}


   /**
    *
    *  Prints the specified value in the string buffer provided.
    *  Returns a pointer to this if successful, NULL otherwise.
    *
    */
char *var_sprint_value( char *str_buf, int len, netsnmp_value value, netsnmp_mib mib )
{
    netsnmp_buf buf;
    char *cp = NULL;

    if ( value == NULL ) {
	return NULL;
    }
    buf = buffer_new( str_buf, len, NETSNMP_BUFFER_NOFREE );
    if ( buf == NULL ) {
	return NULL;
    }
    if ( var_bprint_value( buf, value, mib ) == 0 ) {
	cp = buffer_string( buf );
    }
    buffer_free( buf );
    return cp;
}


   /**
    *
    *  Prints a value to the specified file.
    *
    */
void  var_fprint_value( FILE *fp, netsnmp_value value, netsnmp_mib mib )
{
    netsnmp_buf buf;

    if ( value == NULL ) {
	return;
    }
    buf = buffer_new( NULL, 0, 0 );
    if ( buf == NULL ) {
	return;
    }
    if ( var_bprint_value( buf, value, mib ) == 0 ) {
	fprintf( fp, "%s", buf->string );
    }
}


   /**
    *
    *  Print a value to standard output.
    *
    */
void  var_print_value( netsnmp_value value, netsnmp_mib mib )
{
    var_fprint_value( stdout, value, mib );
}



		/**************************************
		 *
		 *	internal utility routines
		 *
		 **************************************/
		/** @package varbind_internals */


char *_named_number( int value, netsnmp_mib mib )
{
    SmiNode        *node;
    SmiType        *type;
    SmiNamedNumber *enumeration;

    if ( mib == NULL ) {
	return NULL;
    }

    node  = (SmiNode *)mib;
    type  = smiGetNodeType( node );
    if ( type == NULL ) {
	return NULL;
    }    

    for  ( enumeration = smiGetFirstNamedNumber( type );
	   enumeration != NULL ;
	   enumeration = smiGetNextNamedNumber( enumeration )) {

	if ( enumeration->value.value.integer64 == value ) {
	    return enumeration->name;
	}
    }
    return NULL;
}


		/**************************************
		 *
		 *	internal 'convenience' types
		 *
		 **************************************/


int val_print_hintstr( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char *hint, ch;
    char *cp, *end_cp;
    int   len, i;
    long  v;
    char intbuf[ BUFSIZ];

    int  repeat = -1;
    int  width  = -1;
    char code   =  0;
    char separator  = 0;
    char terminator = 0;

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    if ((  value->val.string == NULL ) ||
        (*(value->val.string) == '\0' )) {
	return 0;
    }
    if (( mib         == NULL ) ||
        ( mib->format == NULL ) ||
        (*mib->format == '\0' )) {
	return -1;
    }

    len = value->len;
    cp  = value->val.string;
    end_cp = cp+len;
    hint   = mib->format;


    while ( cp<end_cp ) {
	/*
	 *  Parse the format hint
	 *  This consists of a number of specifications of the form '*Ndst'
	 *  where:
	 *	'*' (a literal '*' character)
	 *	    indicates that this format hint should be 
	 *	    repeated a number of times - the repetition
	 *	    count being taken from the string being displayed.
	 *	N   (a decimal number)
	 *	    indicates how many octets of the string should be
	 *	    processed using this format specifier.
	 *	d   (a single character - one of "xdoat" )
	 *	    indicates how this section of the string should be
	 *	    displayed - "xdo" denote integer representations,
	 *	    "at" denote ASCII or UTF-8 characters
	 *	s   (a single character - other than '*' or '0'-'9')
	 *	    indicates a 'separator' character, to be displayed
	 *	    after each application of this specification
	 *	    (other than the last).
	 *	t   (a single character - other than '*' or '0'-'9')
	 *	    indicates a 'terminator' character, to be displayed
	 *	    after the final application of this specification.
	 *	
	 *  Note that '*', 's' and 't' are optional.
	 *
	 *  See RFC 2579 "Textual Conventions for SMIv2" - section 3.1
	 *	for the full description of this.
	 */

	repeat = 1;
	if ( *hint ) {		/* If we've run out of hint specification,
				   use the last settings we read.   */
	    if ( *hint == '*' ) {
		repeat = *cp++;
		hint++;
	    }

	    width = 0;
	    while ( isdigit( *hint )) {
		width = width*10 + (*hint++ - '0' );
	    }
	    if ( width == 0 ) {
		width = 1;	/* XXX - why ?  A width of 0 is legal */
	    }

	    code = *hint++;	/* Will be validated later */

		/*
		 * XXX - the earlier implementation rejected the integer
		 *       display format code as valid separator or terminator
		 *       characters.
		 * I don't see how this follows from RFC 2579 Section 3.1, 
		 *	so am omitting this restriction for now.
		 *	Once the error of my ways has been pointed out to me,
		 *	I'll gladly reinstate this!
		 */
	    separator = 0;
	    ch        = *hint;
	    if ( ch && ch != '*' && !isdigit( ch )) {
		separator = ch;
	    }
	    
	    terminator = 0;
	    ch         = *hint;
	    if ( ch && ch != '*' && !isdigit( ch )) {
		terminator = ch;
	    }
	}

	/*
	 *  Now we know how to display the next N octets,
	 *  let's do so!
	 */
	while ( repeat ) {
	    if ( end_cp-cp < width ) {	/* Nearly finished.... */
		width  = end_cp-cp;
		repeat = 1;
	    }

			/* If this is an integer display code,
			   calculate the appropriate value */
	    v = -1;
	    if ( code == 'x' || code == 'd' || code == 'o' ) {
		v = 0;
		for ( i=0; i<width; i++ ) {
		    v = v*256 + *cp++;
		}
	    }
	    switch ( code ) {

		case 'x':
			sprintf( intbuf, "%lx", v );
			_R( buffer_append_string( buf, intbuf ))
			break;

		case 'd':
			sprintf( intbuf, "%ld", v );
			_R( buffer_append_string( buf, intbuf ))
			break;

		case 'o':
			sprintf( intbuf, "%lo", v );
			_R( buffer_append_string( buf, intbuf ))
			break;

		case 't':
			_R( buffer_append_string( buf,
				"(UTF-8 output not implemented) " ))
			/* Fall-through */

		case 'a':
			_R( buffer_append( buf, cp, width ))
			cp += width;
			break;

		default:
			_R( buffer_append_string( buf,
				"(Bad hint display character ignored " ))
			_R( buffer_append_char(   buf, code   ))
			_R( buffer_append_string( buf, ") "   ))

				/* Or construct a new 'value' to print */
			cp += width;
			break;
	    }
	    repeat--;
	    if ( separator && repeat ) {
		_R( buffer_append_char( buf, separator ))
	    }
	}
	if ( terminator ) {
	    _R( buffer_append_char( buf, terminator ))
	}
    }
    return 0;
}


int val_print_string( netsnmp_buf buf,  char *string, int strlen, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];
    char *cp, *tp;
    int i, len;

    if ( buf    == NULL ) {
	return -1;
    }
    if ( string == NULL ) {
	return 0;
    }
    if ( strlen == 0 ) {
	return 0;	/* or -1 to indicate an error ? */
    }

    len = strlen;
    cp  = string;
    memset( tmpbuf, 0, BUFSIZ );	/* Clear the working buffer */

    while ( len > 0 ) {
		/*
		 * Build up the printable string 'BUFSIZ' characters
		 *   at a time, until we've processed the whole thing.
		 */
	tp = tmpbuf;
	for ( i=0;  i<BUFSIZ-1;  i++ ) {
	    if (isprint(*cp)) {
	        if ( *cp == '\\' || *cp == '"' ) {
		    *tp++ = '\\';
		    i++;
	        }
	        *tp++ = *cp++;
	    }
	    else {
	        *tp++ = '.';
	         cp++;
	    }
	    if ( --len == 0 ) {
		break;
	    }
	}
	*tp = '\0';
	_R( buffer_append_string( buf, tmpbuf ))
    }
    return 0;
}


int val_print_hexstr( netsnmp_buf buf,  char *string, int strlen, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];
    u_char *cp, *tp;
    int len, len2, i;

    if ( buf    == NULL ) {
	return -1;
    }
    if ( string == NULL ) {
	return 0;
    }
    if ( strlen == 0 ) {
	return 0;	/* or -1 to indicate an error ? */
    }

    len = strlen;
    cp  = string;
    memset( tmpbuf, 0, BUFSIZ );	/* Clear the working buffer */

		/*
		 * Print the "full" lines of output....
		 */
    for ( ; len >= 16; len -= 16) {
	sprintf( tmpbuf, "%02X %02X %02X %02X %02X %02X %02X %02X ",
				cp[0], cp[1], cp[2], cp[3],
				cp[4], cp[5], cp[6], cp[7]);
	_R( buffer_append_string( buf, tmpbuf ))
	cp += 8;

	sprintf( tmpbuf, "%02X %02X %02X %02X %02X %02X %02X %02X",
				cp[0], cp[1], cp[2], cp[3],
				cp[4], cp[5], cp[6], cp[7]);
	_R( buffer_append_string( buf, tmpbuf ))
	cp += 8;

	if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT)) {
	    sprintf(tmpbuf, "  [................]");
	    cp -= 16;
	    tp  = tmpbuf + 3;	/* just after the '[' */

	    for ( i=16; i>0 ; i-- ) {
		if ( isprint( *cp )) {
		    *tp = *cp;
		}
		cp++;
		tp++;
	    }
	    _R( buffer_append_string( buf, tmpbuf ))
	}
    }

		/*
		 * ... and anything left over
		 */
    if ( len > 0 ) {
	len2 = len;
	for ( ; len > 0 ; len-- ) {
	    sprintf( tmpbuf, "%02X ", *cp++);
	    _R( buffer_append_string( buf, tmpbuf ))
	}
	
	if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT)) {
	    sprintf(tmpbuf, "  [                ]");
	    cp -= len2;
	    tp  = tmpbuf + 3;	/* just after the '[' */
	    for ( ;  len2>0;  len2-- ) {
		if ( isprint( *cp )) {
		    *tp = *cp;
		}
		else {
		    *tp = '.';
		}
		cp++;
		tp++;
	    }
	    _R( buffer_append_string( buf, tmpbuf ))
	}
    }
    return 0;
}

		/**************************************
		 *
		 *	standard ASN.1 types
		 *
		 **************************************/


int val_print_int(    netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];
    long val;
    char *name = NULL;

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    if ( value->type != ASN_INTEGER) {
	_R(buffer_append_string( buf, "Wrong Type (should be Integer): "))
	return var_bprint_value( buf, value, mib );
    }
    val = *(long*)value->val.integer;

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "Integer32: "))
    }

		/* XXX - hints  XXX */
    if ( !ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
	name = _named_number( val, mib );
    }
    if ( name ) {
	if ( ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	    strncpy( tmpbuf, name, BUFSIZ );
	}
	else {
	    snprintf( tmpbuf, BUFSIZ, "%s(%ld)", name, val );
	}
    }
    else {
	snprintf( tmpbuf, BUFSIZ, "%ld", val );
    }

    _R( buffer_append_string( buf, tmpbuf ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }
    return 0;
}


int val_print_uint(   netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];
    u_long val;
    char *name = NULL;

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    switch ( value->type ) {

	case ASN_UINTEGER:
	case ASN_COUNTER:
	case ASN_GAUGE:
	    break;
	default:
	    _R(buffer_append_string( buf, "Wrong Type (should be UInteger-based): "))
	    return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	switch ( value->type ) {
	    case ASN_COUNTER:
		_R(buffer_append_string( buf, "Counter: "))
		break;
	    case ASN_GAUGE:
		_R(buffer_append_string( buf, "Gauge: "))
		break;
	    case ASN_UINTEGER:
		_R(buffer_append_string( buf, "UInteger32: "))
		break;
	    default:
	}
    }

    val = *(u_long*)value->val.integer;

	/*
	 * Handle enumerations (if appropriate)
	 */
    if (( value->type == ASN_UINTEGER ) &&
	!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
	name = _named_number( val, mib );
    }
    if ( name ) {
	if ( ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	    strncpy( tmpbuf, name, BUFSIZ );
	}
	else {
	    snprintf( tmpbuf, BUFSIZ, "%s(%lu)", name, val );
	}
    }
    else {
	snprintf( tmpbuf, BUFSIZ, "%lu", val );
    }
    _R(buffer_append_string( buf, tmpbuf ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }

    return 0;
}


int val_print_tticks( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    u_long timeticks;
    int centisecs, seconds, minutes, hours, days;
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    if ( value->type != ASN_TIMETICKS) {
	_R(buffer_append_string( buf, "Wrong Type (should be TimeTicks): "))
	return var_bprint_value( buf, value, mib );
    }

    timeticks = *(value->val.integer);

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "TimeTicks: "))
    }
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS)) {
	sprintf(tmpbuf,"%lu",timeticks);
	return( buffer_append_string( buf, tmpbuf ));
    }

    centisecs  = timeticks % 100;
    timeticks /= 100;
    days       = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);
    hours      = timeticks / (60 * 60);
    timeticks %= (60 * 60);
    minutes    = timeticks / 60; 
    seconds    = timeticks % 60;

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	sprintf(tmpbuf, "%d:%d:%02d:%02d.%02d",
			days, hours, minutes, seconds, centisecs);
    }
    else {
	if (days == 0){
	    sprintf(tmpbuf, "%d:%02d:%02d.%02d",
			      hours, minutes, seconds, centisecs);
	}
	else if (days == 1) {
	    sprintf(tmpbuf, "%d day, %d:%02d:%02d.%02d",
			days, hours, minutes, seconds, centisecs);
	}
	else {
	    sprintf(tmpbuf, "%d days, %d:%02d:%02d.%02d",
			days, hours, minutes, seconds, centisecs);
	}
    }
    return( buffer_append_string( buf, tmpbuf ));
}


int val_print_count64(netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    switch ( value->type ) {

	case ASN_COUNTER64:
	case ASN_OPAQUE_COUNTER64:
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_I64:
	    break;
	default:
	    _R(buffer_append_string( buf, "Wrong Type (should be Counter64): "))
	    return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	switch ( value->type ) {
	    case ASN_COUNTER64:
		_R(buffer_append_string( buf, "Counter64: "))
		break;
	    case ASN_OPAQUE_COUNTER64:
		_R(buffer_append_string( buf, "Opaque: Counter64: "))
		break;
	    case ASN_OPAQUE_U64:
		_R(buffer_append_string( buf, "Opaque: UInt64: "))
		break;
	    case ASN_OPAQUE_I64:
		_R(buffer_append_string( buf, "Opaque: Int64: "))
		break;
	    default:
	}
    }

    if ( value->type == ASN_OPAQUE_I64 ) {
	printI64( tmpbuf, value->val.integer64);
    }
    else {
	printU64( tmpbuf, value->val.integer64);
    }
    _R(buffer_append_string( buf, tmpbuf ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }

    return 0;
}


int val_print_ipaddr( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    u_char *ip;
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_IPADDRESS) {
	_R(buffer_append_string( buf, "Wrong Type (should be IpAddress): "))
	return var_bprint_value( buf, value, mib );
    }

    ip = value->val.string;
    if ( !ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "IpAddress: "))
    }
    snprintf( tmpbuf, BUFSIZ, "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
    _R( buffer_append_string(  buf, tmpbuf ))

    return 0;
}


int val_print_nsapaddr(netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }
    if ( value->type != ASN_NSAP) {
	_R(buffer_append_string( buf, "Wrong Type (should be NsapAddress): "))
	return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	_R(buffer_append_string( buf, "NsapAdress: " ))
    }
    return val_print_hexstr( buf, value->val.string, value->len, mib );
}


int val_print_oid(    netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    netsnmp_oid oid;

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_OBJECT_ID) {
	_R(buffer_append_string( buf, "Wrong Type (should be OBJECT IDENTIFIER): "))
	return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "OBJECT IDENTIFIER: "))
    }
    return var_bprint_oid( buf, value->val.oid );
}


int val_print_null(   netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_NULL) {
	_R(buffer_append_string( buf, "Wrong Type (should be NULL): "))
	return var_bprint_value( buf, value, mib );
    }

    _R(buffer_append_string( buf, "NULL"))
    return 0;
}


int val_print_octetstr(netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    int hex, x;
    char *cp;

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_OCTET_STR) {
	_R(buffer_append_string( buf, "Wrong Type (should be OCTET STRING): "))
	return var_bprint_value( buf, value, mib );
    }


		/*
		 * If we've got some display hints, then use them
		 */
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "OCTET STRING: "))
    }
    if ( mib && mib->format && *(mib->format) ) {
	_R( val_print_hintstr( buf, value, mib ))
    }
    else {
		/*
		 * Otherwise, is this a printable string or not?
		 */
	hex = 0;
	for ( cp = value->val.string, x = 0;
	      x < value->len;
	      x++, cp++ ) {

	     if (!(isprint(*cp) || isspace(*cp))) {
		hex++;
	     }
	}

		/*
		 *   ... and display accordingly.
		 */
	if ( hex == 0 ) {
	    _R( buffer_append_char(buf, '"'        ))
	    _R( val_print_string(  buf, value->val.string, value->len, mib ))
	    _R( buffer_append_char(buf, '"'        ))
	}
	else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	    _R( buffer_append_char(buf, '"'        ))
	    _R( val_print_hexstr(  buf, value->val.string, value->len, mib ))
	    _R( buffer_append_char(buf, '"'        ))
	}
	else {
	    _R( buffer_append_string(buf, "Hex: "  ))
	    _R( val_print_hexstr(  buf, value->val.string, value->len, mib ))
	}
    }

		/*
		 * Regardless of how we've printed the string,
		 *   if there are units defined for this object,
		 *   then add this information.
		 */
    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }
    return 0;
}


int val_print_bitstr( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char *cp, *name;
    int len, bit, v;
    netsnmp_mib enum_mib = mib;
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if (( value->type != ASN_OCTET_STR) &&
        ( value->type != ASN_BIT_STR  )) {
	_R(buffer_append_string( buf, "Wrong Type (should be BITS): "))
	return var_bprint_value( buf, value, mib );
    }

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R( buffer_append_char(buf, '"'        ))
	_R( val_print_hexstr(  buf, value->val.string, value->len, mib ))
	_R( buffer_append_char(buf, '"'        ))
    }
    else {
	_R(buffer_append_string( buf, "BITS: "))
	_R( val_print_hexstr(  buf, value->val.string, value->len, mib ))

		/*
		 * Indicate which bits were set
		 *  (preferably with 'meaningful' enumeration tags)
		 */
	if ( ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
	    enum_mib=NULL;
	}
	cp = value->val.string;
	for ( len=0; len < (int)value->len; len++, cp++ ) {
	    for ( bit=0 ; bit<8; bit++ ) {
		if ( *cp && (0x80>>bit)) {
		    v     = len*8+bit;
		    name  = _named_number( v, enum_mib );
		    if ( name ) {
			snprintf( tmpbuf, BUFSIZ, "(%d) %s", v, name );
		    }
		    else {
			snprintf( tmpbuf, BUFSIZ, "%d", v );
		    }
		    _R( buffer_append_string( buf, tmpbuf  ))
		}
	    }
	}
    }
    return 0;
}


int val_print_opaque( netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    switch ( value->type ) {

	case ASN_OPAQUE:
	    break;
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_COUNTER64:
	    return val_print_count64( buf, value, mib );
	case ASN_OPAQUE_FLOAT:
	    return val_print_float(   buf, value, mib );
	case ASN_OPAQUE_DOUBLE:
	    return val_print_double(  buf, value, mib );
	default:
	    _R(buffer_append_string( buf, "Wrong Type (should be Opaque): "))
	    return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "Opaque: "))
    }
    _R( val_print_hexstr(  buf, value->val.string, value->len, mib ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }

    return 0;
}


	/*
	 * This isn't strictly a 'standard' ASN.1 type,
	 *   but it's treated as such by the library.
	 */
int val_print_float(  netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_OPAQUE_FLOAT) {
	_R(buffer_append_string( buf, "Wrong Type (should be Float): "))
	return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "Opaque: Float: "))
    }
    snprintf( tmpbuf, BUFSIZ, "%f", value->val.floatVal );
    _R( buffer_append_string( buf, tmpbuf ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }
    return 0;
}


	/*
	 * This isn't strictly a 'standard' ASN.1 type,
	 *   but it's treated as such by the library.
	 */
int val_print_double(  netsnmp_buf buf,  netsnmp_value value, netsnmp_mib mib )
{
    char tmpbuf[ BUFSIZ ];

    if (( buf   == NULL ) ||
        ( value == NULL )) {
	return -1;
    }

    if ( value->type != ASN_OPAQUE_DOUBLE) {
	_R(buffer_append_string( buf, "Wrong Type (should be Double): "))
	return var_bprint_value( buf, value, mib );
    }

    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
	_R(buffer_append_string( buf, "Opaque: Double: "))
    }
    snprintf( tmpbuf, BUFSIZ, "%f", value->val.doubleVal );
    _R( buffer_append_string( buf, tmpbuf ))

    if (mib && mib->units) {
	_R( buffer_append_char(   buf, ' '        ))
	_R( buffer_append_string( buf, mib->units ))
    }
    return 0;
}
