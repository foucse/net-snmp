#ifndef _UCD_UCD_CONVERT_H
#define _UCD_UCD_CONVERT_H

#include "ucd/ucd_api.h"

netsnmp_oid*     ucd_convert_oid(    u_long *name, int len          );
netsnmp_value*   ucd_convert_value(  struct variable_list *v        );
netsnmp_varbind* ucd_convert_varbind(struct variable_list *v        );
netsnmp_varbind* ucd_convert_vblist( struct variable_list *var_list );
netsnmp_pdu*     ucd_convert_pdu(    struct snmp_pdu      *pdu      );

int                   ucd_revert_oid(    netsnmp_oid     *oid, u_long *name );
struct variable_list* ucd_revert_value(  netsnmp_value   *val   );
struct variable_list* ucd_revert_varbind(netsnmp_varbind *vb    );
struct variable_list* ucd_revert_vblist( netsnmp_varbind *vblist);
struct snmp_pdu*      ucd_revert_pdu(    netsnmp_pdu     *pdu   );

#endif /* _UCD_UCD_CONVERT_H */
