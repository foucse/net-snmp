/*******************************
 *
 *	ucd_print_value.c
 *
 *	Temporary inclusion of old UCD-SNMP routines
 *	(until we can develop the Net-SNMP replacements)
 *
 *******************************/

#include <config.h>

#include <stdio.h>
#include <ctype.h>
#if TIME_WITH_SYS_TIME
# ifdef WIN32
#  include <sys/timeb.h>
# else
#  include <sys/time.h>
# endif
# include <time.h>
#else
# if HAVE_SYS_TIME_H
#  include <sys/time.h># else
#  include <time.h>
# endif
#endif
#if HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#if HAVE_STDLIB_H
#include <stdlib.h>
#endif


#include "asn1.h"
#include "snmp.h"
#include "snmp_api.h"
#include "snmp_impl.h"
#include "read_config.h"
#include "snmp_debug.h"
#include "default_store.h"
#include "snmp_logging.h"
#include "int64.h"
#include "tools.h"

struct enum_list;
int
sprint_realloc_by_type(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units);
void
sprint_by_type(char *buf,
	       struct variable_list *var,
	       struct enum_list *enums,
	       const char *hint,
	       const char *units);

void
sprint_counter64(char *buf,
		 struct variable_list *var,
		 struct enum_list *enums,
		 const char *hint,
		 const char *units);

extern char *sprint_objid (char *buf, oid *objid, int objidlen);



static char *
uptimeString(u_long timeticks,
	     char *buf)
{
    int	centisecs, seconds, minutes, hours, days;

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS)) {
	sprintf(buf,"%ld",timeticks);
	return buf;
    }


    centisecs = timeticks % 100;
    timeticks /= 100;
    days = timeticks / (60 * 60 * 24);
    timeticks %= (60 * 60 * 24);

    hours = timeticks / (60 * 60);
    timeticks %= (60 * 60);

    minutes = timeticks / 60;
    seconds = timeticks % 60;

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%d:%d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
    else {
	if (days == 0){
	    sprintf(buf, "%d:%02d:%02d.%02d",
		hours, minutes, seconds, centisecs);
	} else if (days == 1) {
	    sprintf(buf, "%d day, %d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
	} else {
	    sprintf(buf, "%d days, %d:%02d:%02d.%02d",
		days, hours, minutes, seconds, centisecs);
	}
    }
    return buf;
}

/*
 * Convert timeticks to hours, minutes, seconds string.
 * CMU compatible does not show centiseconds.
 */
char *uptime_string(u_long timeticks, char *buf)
{
    char tbuf[64];
    char * cp;
    uptimeString(timeticks, tbuf);
    cp = strrchr(tbuf, '.');
#ifdef CMU_COMPATIBLE
        if (cp) *cp = '\0';
#endif
    strcpy(buf, tbuf);    return buf;
}




/* prints character pointed to if in human-readable ASCII range,
	otherwise prints a blank space */
static void sprint_char(char *buf, const u_char ch)
{
    if (isprint(ch)) {
	sprintf(buf, "%c", (int)ch);
    } else {
	sprintf(buf, ".");
    }
}


void sprint_hexstring(char *buf,
                      const u_char *cp,
                      size_t len)
{
	const u_char *tp;
	size_t lenleft;
	
    for(; len >= 16; len -= 16){
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X ", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
	sprintf(buf, "%02X %02X %02X %02X %02X %02X %02X %02X", cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
	buf += strlen(buf);
	cp += 8;
	if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT))
	{
		sprintf(buf, "  [");
		buf += strlen(buf);
		for (tp = cp - 16; tp < cp; tp ++)
		{
			sprint_char(buf++, *tp);
		}
		sprintf(buf, "]");
		buf += strlen(buf);
	}
	if (len > 16) { *buf++ = '\n'; *buf = 0; }
    }
    lenleft = len;
    for(; len > 0; len--){
	sprintf(buf, "%02X ", *cp++);
	buf += strlen(buf);
    }
	if ((lenleft > 0) && ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT))
	{
		sprintf(buf, " [");
		buf += strlen(buf);
		for (tp = cp - lenleft; tp < cp; tp ++)
		{
			sprint_char(buf++, *tp);
		}
		sprintf(buf, "]");
		buf += strlen(buf);
    }
    *buf = '\0';
}

int
sprint_realloc_hexstring(u_char **buf, size_t *buf_len, size_t *out_len,
			 int allow_realloc,
			 const u_char *cp, size_t len)
{
  const u_char *tp;
  size_t lenleft;
	
  for(; len >= 16; len -= 16){
    while ((*out_len + 50) >= *buf_len) {
      if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	return 0;
      }
    }

    sprintf((*buf + *out_len), "%02X %02X %02X %02X %02X %02X %02X %02X ",
	    cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
    *out_len += strlen((*buf + *out_len));
    cp += 8;
    sprintf((*buf + *out_len), "%02X %02X %02X %02X %02X %02X %02X %02X",
	    cp[0], cp[1], cp[2], cp[3], cp[4], cp[5], cp[6], cp[7]);
    *out_len += strlen((*buf + *out_len));
    cp += 8;

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT)) {
      while ((*out_len + 21) >= *buf_len) {
	if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	  return 0;
	}
      }
      sprintf((*buf + *out_len), "  [");
      *out_len += strlen((*buf + *out_len));
      for (tp = cp - 16; tp < cp; tp ++) {
	sprint_char((*buf + *out_len), *tp);
	(*out_len)++;
      }
      sprintf((*buf + *out_len), "]");
      *out_len += strlen((*buf + *out_len));
    }
    if (len > 16) {
      while ((*out_len + 2) >= *buf_len) {
	if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	  return 0;
	}
      }
      *(*buf + (*out_len)++) = '\n';
      *(*buf + *out_len)   = 0;
    }
  }

  lenleft = len;
  for(; len > 0; len--) {
    while ((*out_len + 4) >= *buf_len) {
      if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	return 0;
      }
    }
    sprintf((*buf + *out_len), "%02X ", *cp++);
    *out_len += strlen((*buf + *out_len));
  }

  if ((lenleft > 0) && ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_HEX_TEXT)) {
    while ((*out_len + 5 + lenleft) >= *buf_len) {
      if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	return 0;
      }
    }
    sprintf((*buf + *out_len), "  [");
    *out_len += strlen((*buf + *out_len));
    for (tp = cp - lenleft; tp < cp; tp ++) {
      sprint_char((*buf + *out_len), *tp);
      (*out_len)++;
    }
    sprintf((*buf + *out_len), "]");
    *out_len += strlen((*buf + *out_len));
  }
  return 1;
}

void sprint_asciistring(char *buf,
		        const u_char  *cp,
		        size_t	    len)
{
    int	x;

    for(x = 0; x < (int)len; x++){
	if (isprint(*cp)){
	    if (*cp == '\\' || *cp == '"')
		*buf++ = '\\';
	    *buf++ = *cp++;
	} else {
	    *buf++ = '.';
	    cp++;
	}
    }
    *buf = '\0';
}

int
sprint_realloc_asciistring(u_char **buf, size_t *buf_len, size_t *out_len,
			   int allow_realloc,
			   const u_char *cp, size_t len)
{
  int i;

  for(i = 0; i < (int)len; i++) {
    if (isprint(*cp)) {
      if (*cp == '\\' || *cp == '"') {
	if ((*out_len >= *buf_len) &&
	    !(allow_realloc && snmp_realloc(buf, buf_len))) {
	  return 0;
	}
	*(*buf + (*out_len)++) = '\\';
      }
      if ((*out_len >= *buf_len) &&
	  !(allow_realloc && snmp_realloc(buf, buf_len))) {
	return 0;
      }
      *(*buf + (*out_len)++) = *cp++;
    } else {
      if ((*out_len >= *buf_len) &&
	  !(allow_realloc && snmp_realloc(buf, buf_len))) {
	return 0;
      }
      *(*buf + (*out_len)++) = '.';
      cp++;
    }
  }
  if ((*out_len >= *buf_len) &&
      !(allow_realloc && snmp_realloc(buf, buf_len))) {
    return 0;
  }
  *(*buf + *out_len) = '\0';
  return 1;
}


/*
  0
  < 4
  hex

  0 ""
  < 4 hex Hex: oo oo oo
  < 4     "fgh" Hex: oo oo oo
  > 4 hex Hex: oo oo oo oo oo oo oo oo
  > 4     "this is a test"

  */

void
sprint_octet_string(char *buf,
		    struct variable_list *var,
		    struct enum_list *enums,
		    const char *hint,
		    const char *units)
{
    int hex, x;
    u_char *cp;
    const char *saved_hint = hint;
    char *saved_buf = buf;

    if (var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be OCTET STRING): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }

    if (hint) {
	int repeat, width = 1;
	long value;
	char code = 'd', separ = 0, term = 0, ch;
	u_char *ecp;

	*buf = 0;
	cp = var->val.string;
	ecp = cp + var->val_len;
	while (cp < ecp) {
	    repeat = 1;
	    if (*hint) {
		if (*hint == '*') {
		    repeat = *cp++;
		    hint++;
		}
		width = 0;
		while ('0' <= *hint && *hint <= '9')
		    width = width * 10 + *hint++ - '0';
		code = *hint++;
		if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
		    separ = *hint++;
		else separ = 0;
		if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
                    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
		    term = *hint++;
		else term = 0;
		if (width == 0) width = 1;
	    }
	    while (repeat && cp < ecp) {
                value = 0;
		if (code != 'a')
		    for (x = 0; x < width; x++) value = value * 256 + *cp++;
		switch (code) {
		case 'x':
                    sprintf (buf, "%lx", value); break;
		case 'd':
                    sprintf (buf, "%ld", value); break;
		case 'o':
                    sprintf (buf, "%lo", value); break;
		case 'a':
                    for (x = 0; x < width && cp < ecp; x++)
			*buf++ = *cp++;
		    *buf = 0;
		    break;
		default:
		    sprintf(saved_buf, "(Bad hint ignored: %s) ", saved_hint);
		    sprint_octet_string(saved_buf+strlen(saved_buf),
					var, enums, NULL, NULL);
		    return;
		}
		buf += strlen (buf);
		if (cp < ecp && separ) *buf++ = separ;
		repeat--;
	    }
	    if (term && cp < ecp) *buf++ = term;
	}
	if (units) sprintf (buf, " %s", units);
        return;
    }

    hex = 0;
    for(cp = var->val.string, x = 0; x < (int)var->val_len; x++, cp++){
	if (!(isprint(*cp) || isspace(*cp)))
	    hex = 1;
    }
    if (var->val_len == 0){
	strcpy(buf, "\"\"");
	return;
    }
    if (!hex){
	*buf++ = '"';
	sprint_asciistring(buf, var->val.string, var->val_len);
	buf += strlen(buf);
	*buf++ = '"';
	*buf = '\0';
    }
    if (hex){
	if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	    *buf++ = '"';
	    *buf = '\0';
	} else {
	    sprintf(buf, " Hex: ");
	    buf += strlen(buf);
	}
	sprint_hexstring(buf, var->val.string, var->val_len);
	if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	    buf += strlen(buf);
	    *buf++ = '"';
	    *buf = '\0';
	}
    }
    if (units) sprintf (buf, " %s", units);
}


int
sprint_realloc_octet_string(u_char **buf, size_t *buf_len, size_t *out_len,
			    int allow_realloc,
			    struct variable_list *var,
			    struct enum_list *enums,
			    const char *hint,
			    const char *units)
{
  size_t saved_out_len = *out_len;
  const char *saved_hint = hint;
  int hex = 0, x = 0;
  u_char *cp;

  if (var->type != ASN_OCTET_STR) {
    const char str[] = "Wrong Type (should be OCTET STRING): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (hint) {
    int repeat, width = 1;
    long value;
    char code = 'd', separ = 0, term = 0, ch, intbuf[16];
    u_char *ecp;

    cp = var->val.string;
    ecp = cp + var->val_len;

    while (cp < ecp) {
      repeat = 1;
      if (*hint) {
	if (*hint == '*') {
	  repeat = *cp++;
	  hint++;
	}
	width = 0;
	while ('0' <= *hint && *hint <= '9')
	  width = (width * 10) + (*hint++ - '0');
	code = *hint++;
	if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
	    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
	  separ = *hint++;
	else separ = 0;
	if ((ch = *hint) && ch != '*' && (ch < '0' || ch > '9')
	    && (width != 0 || (ch != 'x' && ch != 'd' && ch != 'o')))
	  term = *hint++;
	else term = 0;
	if (width == 0) width = 1;
      }

      while (repeat && cp < ecp) {
	value = 0;
	if (code != 'a') {
	  for (x = 0; x < width; x++) {
	    value = value * 256 + *cp++;
	  }
	}
	switch (code) {
	case 'x':
	  sprintf(intbuf, "%lx", value);
	  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, intbuf)) {
	    return 0;
	  }
	  break;
	case 'd':
	  sprintf (intbuf, "%ld", value);
	  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, intbuf)) {
	    return 0;
	  }
	  break;
	case 'o':
	  sprintf (intbuf, "%lo", value);
	  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, intbuf)) {
	    return 0;
	  }
	  break;
	case 'a':
	  while ((*out_len + width + 1) >= *buf_len) {
	    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	      return 0;
	    }
	  }
	  for (x = 0; x < width && cp < ecp; x++) {
	    *(*buf + *out_len) = *cp++;
	    (*out_len)++;
	  }
	  *(*buf + *out_len) = '\0';
	  break;
	default:
	  *out_len = saved_out_len;
	  if (snmp_strcat(buf, buf_len, out_len, allow_realloc, 
			  "(Bad hint ignored: ") &&
	      snmp_strcat(buf, buf_len, out_len, allow_realloc, 
			  saved_hint) &&
	      snmp_strcat(buf, buf_len, out_len, allow_realloc, 
			  ") ")) {
	    return sprint_realloc_octet_string(buf, buf_len, out_len,
					       allow_realloc, var,
					       enums, NULL, NULL);
	  } else {
	    return 0;
	  }
	}

	if (cp < ecp && separ) {
	  while ((*out_len + 1) >= *buf_len) {
	    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	      return 0;
	    }
	  }
	  *(*buf + *out_len) = separ;
	  (*out_len)++;
	  *(*buf + *out_len) = '\0';
	}
	repeat--;
      }

      if (term && cp < ecp) {
	while ((*out_len + 1) >= *buf_len) {
	  if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
	    return 0;
	  }
	}
	*(*buf + *out_len) = term;
	(*out_len)++;
	*(*buf + *out_len) = '\0';
      }
    }

    if (units) {
      return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
    }
    return 1;
  }

  hex = 0;
  for(cp = var->val.string, x = 0; x < (int)var->val_len; x++, cp++) {
    if (!(isprint(*cp) || isspace(*cp))) {
      hex = 1;
    }
  }

  if (var->val_len == 0) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, "\"\"");
  }

  if (hex) {
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "\"")) {
	return 0;
      }
    } else {
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, " Hex: ")) {
	return 0;
      }
    }

    if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
				  var->val.string, var->val_len)) {
      return 0;
    }

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "\"")) {
	return 0;
      }
    }
  } else {
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "\"")) {
      return 0;
    }
    if (!sprint_realloc_asciistring(buf, buf_len, out_len, allow_realloc,
				     var->val.string, var->val_len)) {
      return 0;
    }
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "\"")) {
      return 0;
    }
  } 

  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

#ifdef OPAQUE_SPECIAL_TYPES

void
sprint_float(char *buf,
	     struct variable_list *var,
	     struct enum_list *enums,
	     const char *hint,
	     const char *units)
{
  if (var->type != ASN_OPAQUE_FLOAT) {
	sprintf(buf, "Wrong Type (should be Float): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "Opaque: Float:");
	buf += strlen(buf);
    }
    sprintf(buf, " %f", *var->val.floatVal);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_float(u_char **buf, size_t *buf_len,
		      size_t *out_len, int allow_realloc,
		     struct variable_list *var,
		     struct enum_list *enums,
		     const char *hint,
		     const char *units)
{
  if (var->type != ASN_OPAQUE_FLOAT) {
    const char str[] = "Wrong Type (should be Float): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc,"Opaque: Float: ")) {
      return 0;
    }
  }


  /*  How much space needed for max. length float?  128 is overkill.  */

  while ((*out_len + 128 + 1) >= *buf_len) {
    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
      return 0;
    }
  }

  sprintf((*buf + *out_len), "%f", *var->val.floatVal);
  *out_len += strlen((*buf + *out_len));

  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_double(char *buf,
	      struct variable_list *var,
	      struct enum_list *enums,
	      const char *hint,
	      const char *units)
{
  if (var->type != ASN_OPAQUE_DOUBLE) {
	sprintf(buf, "Wrong Type (should be Double): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "Opaque: Double:");
	buf += strlen(buf);
    }
    sprintf(buf, " %f", *var->val.doubleVal);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_double(u_char **buf, size_t *buf_len,
		      size_t *out_len, int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units)
{
  if (var->type != ASN_OPAQUE_DOUBLE) {
    const char str[] = "Wrong Type (should be Double): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc,"Opaque: Float: ")) {
      return 0;
    }
  }

  /*  How much space needed for max. length double?  128 is overkill.  */

  while ((*out_len + 128 + 1) >= *buf_len) {
    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
      return 0;
    }
  }

  sprintf((*buf + *out_len), "%f", *var->val.doubleVal);
  *out_len += strlen((*buf + *out_len));

  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

#endif /* OPAQUE_SPECIAL_TYPES */

void
sprint_opaque(char *buf,
	      struct variable_list *var,
	      struct enum_list *enums,
	      const char *hint,
	      const char *units)
{

    if (var->type != ASN_OPAQUE
#ifdef OPAQUE_SPECIAL_TYPES
        && var->type != ASN_OPAQUE_COUNTER64
        && var->type != ASN_OPAQUE_U64
        && var->type != ASN_OPAQUE_I64
        && var->type != ASN_OPAQUE_FLOAT
        && var->type != ASN_OPAQUE_DOUBLE
#endif /* OPAQUE_SPECIAL_TYPES */
      ){
	sprintf(buf, "Wrong Type (should be Opaque): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
#ifdef OPAQUE_SPECIAL_TYPES
    switch(var->type) {
      case ASN_OPAQUE_COUNTER64:
      case ASN_OPAQUE_U64:
      case ASN_OPAQUE_I64:
        sprint_counter64(buf, var, enums, hint, units);
        break;

      case ASN_OPAQUE_FLOAT:
        sprint_float(buf, var, enums, hint, units);
        break;

      case ASN_OPAQUE_DOUBLE:
        sprint_double(buf, var, enums, hint, units);
        break;

      case ASN_OPAQUE:
#endif
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "OPAQUE: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
    buf += strlen (buf);
#ifdef OPAQUE_SPECIAL_TYPES
    }
#endif
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_counter64(u_char **buf, size_t *buf_len, size_t *out_len,
			 int allow_realloc,
			 struct variable_list *var,
			 struct enum_list *enums,
			 const char *hint,
			 const char *units)
{
  char a64buf[I64CHARSZ+1];

  if (var->type != ASN_COUNTER64
#ifdef OPAQUE_SPECIAL_TYPES
      && var->type != ASN_OPAQUE_COUNTER64
      && var->type != ASN_OPAQUE_I64
      && var->type != ASN_OPAQUE_U64
#endif
      ) {
    const char str[] = "Wrong Type (should be Counter64): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }
  
  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
#ifdef OPAQUE_SPECIAL_TYPES
    if (var->type != ASN_COUNTER64) {
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "Opaque: ")) {
	return 0;
      }
    }
#endif
#ifdef OPAQUE_SPECIAL_TYPES
    switch(var->type) {
    case ASN_OPAQUE_U64:
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "UInt64: ")) {
	return 0;
      }
      break;
    case ASN_OPAQUE_I64:
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "Int64: ")) {
	return 0;
      }
      break;
    case ASN_COUNTER64:
    case ASN_OPAQUE_COUNTER64:
#endif
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, "Counter64: ")) {
	return 0;
      }
#ifdef OPAQUE_SPECIAL_TYPES
    }
#endif
  }

#ifdef OPAQUE_SPECIAL_TYPES
  if (var->type == ASN_OPAQUE_I64) {
    printI64(a64buf, var->val.counter64);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, a64buf)) {
      return 0;
    }
  } else {
#endif
    printU64(a64buf, var->val.counter64);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, a64buf)) {
      return 0;
    }
#ifdef OPAQUE_SPECIAL_TYPES
  }
#endif

  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

int
sprint_realloc_opaque(u_char **buf, size_t *buf_len,
		      size_t *out_len, int allow_realloc,
		      struct variable_list *var,
		      struct enum_list *enums,
		      const char *hint,
		      const char *units)
{
  if (var->type != ASN_OPAQUE
#ifdef OPAQUE_SPECIAL_TYPES
      && var->type != ASN_OPAQUE_COUNTER64
      && var->type != ASN_OPAQUE_U64
      && var->type != ASN_OPAQUE_I64
      && var->type != ASN_OPAQUE_FLOAT
      && var->type != ASN_OPAQUE_DOUBLE
#endif /* OPAQUE_SPECIAL_TYPES */
      ) {
    const char str[] = "Wrong Type (should be Opaque): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

#ifdef OPAQUE_SPECIAL_TYPES
  switch(var->type) {
  case ASN_OPAQUE_COUNTER64:
  case ASN_OPAQUE_U64:
  case ASN_OPAQUE_I64:
    return sprint_realloc_counter64(buf, buf_len, out_len, allow_realloc,
				    var, enums, hint, units);
    break;

  case ASN_OPAQUE_FLOAT:
    return sprint_realloc_float(buf, buf_len, out_len, allow_realloc,
				var, enums, hint, units);
    break;

  case ASN_OPAQUE_DOUBLE:
    return sprint_realloc_double(buf, buf_len, out_len, allow_realloc,
				 var, enums, hint, units);
    break;

  case ASN_OPAQUE:
#endif
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
      const char str[] = "OPAQUE: ";
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
	return 0;
      }
    }
    if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
				  var->val.string, var->val_len)) {
      return 0;
    }
#ifdef OPAQUE_SPECIAL_TYPES
  }
#endif
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_object_identifier(char *buf,
			 struct variable_list *var,
			 struct enum_list *enums,
			 const char *hint,
			 const char *units)
{
    if (var->type != ASN_OBJECT_ID){
	sprintf(buf, "Wrong Type (should be OBJECT IDENTIFIER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "OID: ");
	buf += strlen(buf);
    }
    sprint_objid(buf, (oid *)(var->val.objid), var->val_len / sizeof(oid));
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_object_identifier(u_char **buf, size_t *buf_len,
				 size_t *out_len, int allow_realloc,
				 struct variable_list *var,
				 struct enum_list *enums,
				 const char *hint,
				 const char *units)
{
  int buf_overflow = 0;

  if (var->type != ASN_OBJECT_ID) {
    const char str[] = "Wrong Type (should be OBJECT IDENTIFIER): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "OID: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }

  sprint_objid(*buf, (oid *)(var->val.objid), var->val_len/sizeof(oid));

  if (buf_overflow) {
    return 0;
  }

  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_timeticks(char *buf,
		 struct variable_list *var,
		 struct enum_list *enums,
		 const char *hint,
		 const char *units)
{
    char timebuf[32];

    if (var->type != ASN_TIMETICKS){
	sprintf(buf, "Wrong Type (should be Timeticks): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS)) {
        sprintf(buf,"%lu", *(u_long *)(var->val.integer));
        return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "Timeticks: (%lu) ", *(u_long *)(var->val.integer));
	buf += strlen(buf);
    }
    sprintf(buf, "%s", uptimeString(*(u_long *)(var->val.integer), timebuf));
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_timeticks(u_char **buf, size_t *buf_len, size_t *out_len,
			 int allow_realloc,
			 struct variable_list *var,
			 struct enum_list *enums,
			 const char *hint,
			 const char *units)
{
  char timebuf[32];

  if (var->type != ASN_TIMETICKS) {
    const char str[] = 	"Wrong Type (should be Timeticks): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_NUMERIC_TIMETICKS)) {
    char str[16];
    sprintf(str, "%lu", *(u_long *)var->val.integer);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    char str[32];
    sprintf(str, "Timeticks: (%lu) ", *(u_long *)var->val.integer);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  uptimeString(*(u_long *)(var->val.integer), timebuf);
  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, timebuf)) {
    return 0;
  }
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_hinted_integer (char *buf,
		       long val,
		       const char *hint,
		       const char *units)
{
    char code;
    int shift, len;
    char tmp[256];
    char fmt[10];

    code = hint[0];
    if (hint [1] == '-') {
        shift = atoi (hint+2);
    }
    else shift = 0;
    fmt[0] = '%';
    fmt[1] = 'l';
    fmt[2] = code;
    fmt[3] = 0;
    sprintf (tmp, fmt, val);
    if (shift != 0) {
	len = strlen (tmp);
	if (shift <= len) {
	    tmp[len+1] = 0;
	    while (shift--) {
		tmp[len] = tmp[len-1];
		len--;
	    }
	    tmp[len] = '.';
	}
	else {
	    tmp[shift+1] = 0;
	    while (shift) {
		if (len-- > 0) tmp [shift] = tmp [len];
		else tmp[shift] = '0';
		shift--;
	    }
	    tmp[0] = '.';
	}
    }
    strcpy (buf, tmp);
}

int
sprint_realloc_hinted_integer (u_char **buf, size_t *buf_len, size_t *out_len,
			       int allow_realloc,
			       long val,
			       const char *hint,
			       const char *units)
{
  char code, fmt[10] = "%l@", tmp[256];
  int shift, len;

  code = hint[0];
  if (hint[1] == '-') {
    shift = atoi(hint+2);
  } else {
    shift = 0;
  }
  fmt[2] = code;
  sprintf(tmp, fmt, val);
  if (shift != 0) {
    len = strlen(tmp);
    if (shift <= len) {
      tmp[len+1] = 0;
      while (shift--) {
	tmp[len] = tmp[len-1];
	len--;
      }
      tmp[len] = '.';
    } else {
      tmp[shift+1] = 0;
      while (shift) {
	if (len-- > 0) {
	  tmp[shift] = tmp[len];
	} else {
	  tmp[shift] = '0';
	}
	shift--;
      }
      tmp[0] = '.';
    }
  }
  return snmp_strcat(buf, buf_len, out_len, allow_realloc, tmp);
}

void
sprint_integer(char *buf,
	       struct variable_list *var,
	       struct enum_list *enums,
	       const char *hint,
	       const char *units)
{
    char    *enum_string = NULL;

    if (var->type != ASN_INTEGER){
	sprintf(buf, "Wrong Type (should be INTEGER): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
/*
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer){
	    enum_string = enums->label;
	    break;
	}
 */
    if (enum_string == NULL ||
        ds_get_boolean(DS_LIBRARY_ID,DS_LIB_PRINT_NUMERIC_ENUM)) {
	if (hint) sprint_hinted_integer(buf, *var->val.integer, hint, units);
	else sprintf(buf, "%ld", *var->val.integer);
    }
    else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%s", enum_string);
    else
	sprintf(buf, "%s(%ld)", enum_string, *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}


int
sprint_realloc_integer(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units)
{
  char *enum_string = NULL;

  if (var->type != ASN_INTEGER) {
    const char str[] = "Wrong Type (should be INTEGER): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }
/*
  for (; enums; enums = enums->next) {
    if (enums->value == *var->val.integer) {
      enum_string = enums->label;
      break;
    }
  }
 */

  if (enum_string == NULL ||
      ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
    if (hint) {
      return sprint_realloc_hinted_integer(buf, buf_len, out_len,
					   allow_realloc,
					   *var->val.integer, hint, units);
    } else {
      char str[16];
      sprintf(str, "%ld", *var->val.integer);
      if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
	return 0;
      }
    }
  } else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, enum_string)) {
      return 0;
    }
  } else {
    char str[16];
    sprintf(str, "(%ld)", *var->val.integer);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, enum_string)) {
      return 0;
    }
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_uinteger(char *buf,
		struct variable_list *var,
		struct enum_list *enums,
		const char *hint,
		const char *units)
{
    char    *enum_string = NULL;

    if (var->type != ASN_UINTEGER){
	sprintf(buf, "Wrong Type (should be UInteger32): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
/*
    for (; enums; enums = enums->next)
	if (enums->value == *var->val.integer){
	    enum_string = enums->label;
	    break;
	}
 */
    if (enum_string == NULL ||
        ds_get_boolean(DS_LIBRARY_ID,DS_LIB_PRINT_NUMERIC_ENUM))
	sprintf(buf, "%lu", *var->val.integer);
    else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%s", enum_string);
    else
	sprintf(buf, "%s(%lu)", enum_string, *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_uinteger(u_char **buf, size_t *buf_len, size_t *out_len,
			int allow_realloc,
			struct variable_list *var,
			struct enum_list *enums,
			const char *hint,
			const char *units)
{
  char *enum_string = NULL;

  if (var->type != ASN_UINTEGER){
    const char str[] = "Wrong Type (should be UInteger32): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

/*
  for (; enums; enums = enums->next) {
    if (enums->value == *var->val.integer) {
      enum_string = enums->label;
      break;
    }
  }
 */

  if (enum_string == NULL ||
      ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
    char str[16];
    sprintf(str, "%lu", *var->val.integer);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  } else if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, enum_string)) {
      return 0;
    }
  } else {
    char str[16];
    sprintf(str, "(%lu)", *var->val.integer);
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, enum_string)) {
      return 0;
    }
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_gauge(char *buf,
	     struct variable_list *var,
	     struct enum_list *enums,
	     const char *hint,
	     const char *units)
{
    if (var->type != ASN_GAUGE){
	sprintf(buf, "Wrong Type (should be Gauge32 or Unsigned32): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%lu", *var->val.integer);
    else
	sprintf(buf, "Gauge32: %lu", *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_gauge(u_char **buf, size_t *buf_len, size_t *out_len,
		     int allow_realloc,
		     struct variable_list *var,
		     struct enum_list *enums,
		     const char *hint,
		     const char *units)
{
  char tmp[32];
    
  if (var->type != ASN_GAUGE) {
    const char str[] = "Wrong Type (should be Gauge32 or Unsigned32): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "Gauge32: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  sprintf(tmp, "%lu", *var->val.integer);
  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, tmp)) {
      return 0;
  }
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_counter(char *buf,
	       struct variable_list *var,
	       struct enum_list *enums,
	       const char *hint,
	       const char *units)
{
    if (var->type != ASN_COUNTER){
	sprintf(buf, "Wrong Type (should be Counter32): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%lu", *var->val.integer);
    else
	sprintf(buf, "Counter32: %lu", *var->val.integer);
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

int
sprint_realloc_counter(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units)
{
  char tmp[32];
    
  if (var->type != ASN_COUNTER) {
    const char str[] = "Wrong Type (should be Counter32): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "Counter32: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  sprintf(tmp, "%lu", *var->val.integer);
  if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, tmp)) {
      return 0;
  }
  if (units) {
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, units);
  }
  return 1;
}

void
sprint_networkaddress(char *buf,
		      struct variable_list *var,
		      struct enum_list *enums,
		      const char *hint,
		      const char *units)
{
    int x, len;
    u_char *cp;

    if (var->type != ASN_IPADDRESS){
	sprintf(buf, "Wrong Type (should be NetworkAddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "Network Address: ");
	buf += strlen(buf);
    }
    cp = var->val.string;
    len = var->val_len;
    for(x = 0; x < len; x++){
	sprintf(buf, "%02X", *cp++);
	buf += strlen(buf);
	if (x < (len - 1))
	    *buf++ = ':';
    }
}

int
sprint_realloc_networkaddress(u_char **buf, size_t *buf_len, size_t *out_len,
			      int allow_realloc,
			      struct variable_list *var,
			      struct enum_list *enums,
			      const char *hint,
			      const char *units)
{
  size_t i;

  if (var->type != ASN_IPADDRESS) {
    const char str[] = "Wrong Type (should be NetworkAddress): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "Network Address: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }

  while ((*out_len + (var->val_len * 3) + 2) >= *buf_len) {
    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
      return 0;
    }
  }

  for (i = 0; i < var->val_len; i++) {
    sprintf((*buf + *out_len), "%02X", var->val.string[i]);
    *out_len += 2;
    if (i < var->val_len - 1) {
      *(*buf + *out_len) = ':';
      (*out_len)++;
    }
  }
  return 1;
}

void
sprint_ipaddress(char *buf,
		 struct variable_list *var,
		 struct enum_list *enums,
		 const char *hint,
		 const char *units)
{
    u_char *ip;

    if (var->type != ASN_IPADDRESS){
	sprintf(buf, "Wrong Type (should be IpAddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    ip = var->val.string;
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT))
	sprintf(buf, "%d.%d.%d.%d",ip[0], ip[1], ip[2], ip[3]);
    else
	sprintf(buf, "IpAddress: %d.%d.%d.%d",ip[0], ip[1], ip[2], ip[3]);
}

int
sprint_realloc_ipaddress(u_char **buf, size_t *buf_len, size_t *out_len,
			 int allow_realloc,
			 struct variable_list *var,
			 struct enum_list *enums,
			 const char *hint,
			 const char *units)
{
  u_char *ip = var->val.string;

  if (var->type != ASN_IPADDRESS) {
    const char str[] = "Wrong Type (should be IpAddress): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "IpAddress: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  while ((*out_len + 17) >= *buf_len) {
    if (!(allow_realloc && snmp_realloc(buf, buf_len))) {
      return 0;
    }
  }
  sprintf((*buf + *out_len), "%d.%d.%d.%d", ip[0], ip[1], ip[2], ip[3]);
  *out_len += strlen(*buf + *out_len);
  return 1;
}

void
sprint_null(char *buf,
	    struct variable_list *var,
	    struct enum_list *enums,
	    const char *hint,
	    const char *units)
{
    if (var->type != ASN_NULL){
	sprintf(buf, "Wrong Type (should be NULL): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    sprintf(buf, "NULL");
}

int
sprint_realloc_null(u_char **buf, size_t *buf_len, size_t *out_len,
		    int allow_realloc,
		    struct variable_list *var,
		    struct enum_list *enums,
		    const char *hint,
		    const char *units)
{
  if (var->type != ASN_NULL) {
    const char str[] = "Wrong Type (should be NULL): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  } else {
    const char str[] = "NULL";
    return snmp_strcat(buf, buf_len, out_len, allow_realloc, str);
  }
}

void
sprint_bitstring(char *buf,
		 struct variable_list *var,
		 struct enum_list *enums,
		 const char *hint,
		 const char *units)
{
    int len, bit;
    u_char *cp;
    char *enum_string;

    if (var->type != ASN_BIT_STR && var->type != ASN_OCTET_STR){
	sprintf(buf, "Wrong Type (should be BITS): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	*buf++ = '"';
	*buf = '\0';
    } else {
	sprintf(buf, "BITS: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.bitstring, var->val_len);
    buf += strlen(buf);

    if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	buf += strlen(buf);
	*buf++ = '"';
	*buf = '\0';
    } else {
	cp = var->val.bitstring;
	for(len = 0; len < (int)var->val_len; len++){
	    for(bit = 0; bit < 8; bit++){
		if (*cp & (0x80 >> bit)){
		    enum_string = NULL;
/*
		    for (; enums; enums = enums->next)
			if (enums->value == (len * 8) + bit){
			    enum_string = enums->label;
			    break;
			}
 */
		    if (enum_string == NULL ||
                        ds_get_boolean(DS_LIBRARY_ID,DS_LIB_PRINT_NUMERIC_ENUM))
			sprintf(buf, "%d ", (len * 8) + bit);
		    else
			sprintf(buf, "%s(%d) ", enum_string, (len * 8) + bit);
		    buf += strlen(buf);
		}
	    }
	    cp ++;
	}
    }
}

int
sprint_realloc_bitstring(u_char **buf, size_t *buf_len, size_t *out_len,
			   int allow_realloc,
			  struct variable_list *var,
			  struct enum_list *enums,
			  const char *hint,
			  const char *units)
{
  int len, bit;
  u_char *cp;
  char *enum_string;

  if (var->type != ASN_BIT_STR && var->type != ASN_OCTET_STR) {
    const char str[] = "Wrong Type (should be BITS): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "\"";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  } else {
    const char str[] = "BITS: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }
  if (!sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
				var->val.bitstring, var->val_len)) {
    return 0;
  }

  if (ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "\"";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  } else {
    cp = var->val.bitstring;
    for(len = 0; len < (int)var->val_len; len++) {
      for(bit = 0; bit < 8; bit++) {
	if (*cp & (0x80 >> bit)) {
	  enum_string = NULL;
/*
	  for (; enums; enums = enums->next) {
	    if (enums->value == (len * 8) + bit) {
	      enum_string = enums->label;
	      break;
	    }
	  }
 */
	  if (enum_string == NULL ||
	      ds_get_boolean(DS_LIBRARY_ID, DS_LIB_PRINT_NUMERIC_ENUM)) {
	    char str[16];
	    sprintf(str, "%d ", (len * 8) + bit);
	    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
	      return 0;
	    }
	  } else {
	    char str[16];
	    sprintf(str, "(%d) ", (len * 8) + bit);
	    if (!snmp_strcat(buf, buf_len,out_len,allow_realloc,enum_string)) {
	      return 0;
	    }
	    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
	      return 0;
	    }
	  }
	}
      }
      cp++;
    }
  }
  return 1;
}

void
sprint_nsapaddress(char *buf,
		   struct variable_list *var,
		   struct enum_list *enums,
		   const char *hint,
		   const char *units)
{
    if (var->type != ASN_NSAP){
	sprintf(buf, "Wrong Type (should be NsapAddress): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
	sprintf(buf, "NsapAddress: ");
	buf += strlen(buf);
    }
    sprint_hexstring(buf, var->val.string, var->val_len);
}

int
sprint_realloc_nsapaddress(u_char **buf, size_t *buf_len, size_t *out_len,
			   int allow_realloc,
			   struct variable_list *var,
			   struct enum_list *enums,
			   const char *hint,
			   const char *units)
{
  if (var->type != ASN_NSAP) {
    const char str[] = "Wrong Type (should be NsapAddress): ";
    if (snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return sprint_realloc_by_type(buf, buf_len, out_len, allow_realloc,
				    var, NULL, NULL, NULL);
    } else {
      return 0;
    }
  }

  if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)) {
    const char str[] = "NsapAddress: ";
    if (!snmp_strcat(buf, buf_len, out_len, allow_realloc, str)) {
      return 0;
    }
  }

  return sprint_realloc_hexstring(buf, buf_len, out_len, allow_realloc,
				  var->val.string, var->val_len);
}

void
sprint_counter64(char *buf,
		 struct variable_list *var,
		 struct enum_list *enums,
		 const char *hint,
		 const char *units)
{
    char a64buf[I64CHARSZ+1];

  if (var->type != ASN_COUNTER64
#ifdef OPAQUE_SPECIAL_TYPES
      && var->type != ASN_OPAQUE_COUNTER64
      && var->type != ASN_OPAQUE_I64
      && var->type != ASN_OPAQUE_U64
#endif
    ){
	sprintf(buf, "Wrong Type (should be Counter64): ");
	buf += strlen(buf);
	sprint_by_type(buf, var, NULL, NULL, NULL);
	return;
    }
    if (!ds_get_boolean(DS_LIBRARY_ID, DS_LIB_QUICK_PRINT)){
#ifdef OPAQUE_SPECIAL_TYPES
      if (var->type != ASN_COUNTER64) {
	sprintf(buf, "Opaque: ");
	buf += strlen(buf);
      }
#endif
#ifdef OPAQUE_SPECIAL_TYPES
        switch(var->type) {
          case ASN_OPAQUE_U64:
            sprintf(buf, "UInt64: ");
            break;
          case ASN_OPAQUE_I64:
            sprintf(buf, "Int64: ");
            break;
          case ASN_COUNTER64:
          case ASN_OPAQUE_COUNTER64:
#endif
            sprintf(buf, "Counter64: ");
#ifdef OPAQUE_SPECIAL_TYPES
        }
#endif
	buf += strlen(buf);
    }
#ifdef OPAQUE_SPECIAL_TYPES
    if (var->type == ASN_OPAQUE_I64)
    {
      printI64(a64buf, var->val.counter64);
      sprintf(buf, a64buf);
    }
    else
#endif
    {
      printU64(a64buf, var->val.counter64);
      sprintf(buf, a64buf);
    }
    buf += strlen (buf);
    if (units) sprintf (buf, " %s", units);
}

void
sprint_unknowntype(char *buf,
		   struct variable_list *var,
		   struct enum_list *enums,
		   const char *hint,
		   const char *units)
{
/*    sprintf(buf, "Variable has bad type"); */
    sprint_by_type(buf, var, NULL, NULL, NULL);
}

void
sprint_badtype(char *buf,
	       struct variable_list *var,
	       struct enum_list *enums,
	       const char *hint,
	       const char *units)
{
    sprintf(buf, "Variable has bad type");
}

int
sprint_realloc_badtype(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units)
{
  const char str[] = "Variable has bad type";

  return snmp_strcat(buf, buf_len, out_len, allow_realloc, str);
}

void
sprint_by_type(char *buf,
	       struct variable_list *var,
	       struct enum_list *enums,
	       const char *hint,
	       const char *units)
{
    switch (var->type){
	case ASN_INTEGER:
	    sprint_integer(buf, var, enums, hint, units);
	    break;
	case ASN_OCTET_STR:
	    sprint_octet_string(buf, var, enums, hint, units);
	    break;
	case ASN_BIT_STR:
	    sprint_bitstring(buf, var, enums, hint, units);
	    break;
	case ASN_OPAQUE:
	    sprint_opaque(buf, var, enums, hint, units);
	    break;
	case ASN_OBJECT_ID:
	    sprint_object_identifier(buf, var, enums, hint, units);
	    break;
	case ASN_TIMETICKS:
	    sprint_timeticks(buf, var, enums, hint, units);
	    break;
	case ASN_GAUGE:
	    sprint_gauge(buf, var, enums, hint, units);
	    break;
	case ASN_COUNTER:
	    sprint_counter(buf, var, enums, hint, units);
	    break;
	case ASN_IPADDRESS:
	    sprint_ipaddress(buf, var, enums, hint, units);
	    break;
	case ASN_NULL:
	    sprint_null(buf, var, enums, hint, units);
	    break;
	case ASN_UINTEGER:
	    sprint_uinteger(buf, var, enums, hint, units);
	    break;
	case ASN_COUNTER64:
#ifdef OPAQUE_SPECIAL_TYPES
	case ASN_OPAQUE_U64:
	case ASN_OPAQUE_I64:
	case ASN_OPAQUE_COUNTER64:
#endif /* OPAQUE_SPECIAL_TYPES */
	    sprint_counter64(buf, var, enums, hint, units);
	    break;
#ifdef OPAQUE_SPECIAL_TYPES
	case ASN_OPAQUE_FLOAT:
	    sprint_float(buf, var, enums, hint, units);
	    break;
	case ASN_OPAQUE_DOUBLE:
	    sprint_double(buf, var, enums, hint, units);
	    break;
#endif /* OPAQUE_SPECIAL_TYPES */
	default:
            DEBUGMSGTL(("sprint_by_type", "bad type: %d\n", var->type));
	    sprint_badtype(buf, var, enums, hint, units);
	    break;
    }
}

int
sprint_realloc_by_type(u_char **buf, size_t *buf_len, size_t *out_len,
		       int allow_realloc,
		       struct variable_list *var,
		       struct enum_list *enums,
		       const char *hint,
		       const char *units)
{
  DEBUGMSGTL(("output", "sprint_by_type, type %d\n", var->type));

  switch (var->type) {
  case ASN_INTEGER:
    return sprint_realloc_integer(buf, buf_len, out_len, allow_realloc,
				  var, enums, hint, units);
  case ASN_OCTET_STR:
    return sprint_realloc_octet_string(buf, buf_len, out_len, allow_realloc,
				       var, enums, hint, units);
  case ASN_BIT_STR:
    return sprint_realloc_bitstring(buf, buf_len, out_len, allow_realloc,
				    var, enums, hint, units);
  case ASN_OPAQUE:
    return sprint_realloc_opaque(buf, buf_len, out_len, allow_realloc,
				 var, enums, hint, units);
  case ASN_OBJECT_ID:
    return sprint_realloc_object_identifier(buf, buf_len, out_len,
				       allow_realloc, var, enums, hint, units);
  case ASN_TIMETICKS:
    return sprint_realloc_timeticks(buf, buf_len, out_len, allow_realloc,
				    var, enums, hint, units);
  case ASN_GAUGE:
    return sprint_realloc_gauge(buf, buf_len, out_len, allow_realloc,
				var, enums, hint, units);
  case ASN_COUNTER:
    return sprint_realloc_counter(buf, buf_len, out_len, allow_realloc,
				  var, enums, hint, units);
  case ASN_IPADDRESS:
    return sprint_realloc_ipaddress(buf, buf_len, out_len, allow_realloc,
				    var, enums, hint, units);
  case ASN_NULL:
    return sprint_realloc_null(buf, buf_len, out_len, allow_realloc,
			       var, enums, hint, units);
  case ASN_UINTEGER:
    return sprint_realloc_uinteger(buf, buf_len, out_len, allow_realloc,
				   var, enums, hint, units);
  case ASN_COUNTER64:
#ifdef OPAQUE_SPECIAL_TYPES
  case ASN_OPAQUE_U64:
  case ASN_OPAQUE_I64:
  case ASN_OPAQUE_COUNTER64:
#endif /* OPAQUE_SPECIAL_TYPES */
    return sprint_realloc_counter64(buf, buf_len, out_len, allow_realloc,
				    var, enums, hint, units);
#ifdef OPAQUE_SPECIAL_TYPES
  case ASN_OPAQUE_FLOAT:
    return sprint_realloc_float(buf, buf_len, out_len, allow_realloc,
				var, enums, hint, units);
  case ASN_OPAQUE_DOUBLE:
    return sprint_realloc_double(buf, buf_len, out_len, allow_realloc,
				 var, enums, hint, units);
#endif /* OPAQUE_SPECIAL_TYPES */
  default:
    DEBUGMSGTL(("sprint_by_type", "bad type: %d\n", var->type));
    return sprint_realloc_badtype(buf, buf_len, out_len, allow_realloc,
				  var, enums, hint, units);
  }
}


