
typedef struct old_api_info_s {
   struct variable *var;
   size_t varsize;
   size_t numvars;

   /* old stuff */
   struct snmp_session *ss;
   int flags;
} old_api_info;


int register_old_api(const char *moduleName,
                     struct variable *var,
                     size_t varsize,
                     size_t numvars,
                     oid *mibloc,
                     size_t mibloclen,
                     int priority,
                     int range_subid,
                     oid range_ubound,
                     struct snmp_session *ss,
                     const char *context,
                     int timeout,
                     int flags);
NodeHandler old_api_helper;

