#include <config.h>

#include <stdio.h>

static int engineBoots=0;

void
engineBoots_conf(char *word, char *cptr)
{
  engineBoots = atoi(cptr)+1;
  DEBUGP("engineBoots: %d\n",engineBoots);
}

void
init_snmpv3(char *type) {
  register_config_handler(type,"engineBoots", engineBoots_conf, NULL);
}

void
shutdown_snmpv3(char *type) {
  char line[512];
  sprintf(line, "engineBoots %d", engineBoots);
  read_config_store(type, line);
}

int
snmpv3_get_engine_boots(void) {
  return engineBoots;
}
