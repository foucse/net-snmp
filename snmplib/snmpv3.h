#ifndef SNMPV3_H
#define SNMPV3_H

void engineBoots_conf(char *, char *);
void init_snmpv3(char *);
void shutdown_snmpv3(char *type);
int snmpv3_get_engine_boots(void);

#endif /* SNMPV3_H */
