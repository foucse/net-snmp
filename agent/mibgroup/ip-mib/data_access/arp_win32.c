/*
 *  Interface MIB architecture support
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/arp.h>
#include <net-snmp/data_access/interface.h>

#include <iphlpapi.h>
#include "iphlpapi_missing.h"
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

/**
 */
int
netsnmp_access_arp_container_arch_load(netsnmp_container *container)
{
    int rc = 0, idx_offset = 0;

    rc = _load_v4(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_ARP_FREE_KEEP_CONTAINER;
        netsnmp_access_arp_container_free(container, flags);
    }

#if defined (NETSNMP_ENABLE_IPV6)
    idx_offset = (rc < 0) ? 0 : rc;

    rc = _load_v6(container, idx_offset);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_ARP_FREE_KEEP_CONTAINER;
        netsnmp_access_arp_container_free(container, flags);
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if(rc > 0)
        rc = 0;

    return rc;
}

/**
 */
static int
_load_v4(netsnmp_container *container, int idx_offset)
{
    int						rc = 0;
	int						retry;
	DWORD					arp_table_size;
	PMIB_IPNETTABLE         arp_table;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	arp_table_size = sizeof (MIB_IPNETTABLE);
	if ((arp_table = malloc(arp_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		switch (GetIpNetTable(arp_table, &arp_table_size, TRUE)) {
		case NO_ERROR:
			goto found;
		case ERROR_INSUFFICIENT_BUFFER:
			if (retry < 4) {
				free(arp_table);
				if ((arp_table = malloc(arp_table_size)) == NULL) {
					snmp_log(LOG_ERR, "Out of memory.\n");
					return -3;
				}
			} else {
				snmp_log(LOG_ERR, "Could not allocate enough memory to get the arp table.\n");
				return -2;
			}
			break;
		default:
			snmp_log(LOG_ERR, "Error when using GetIPNetTable.\n");
			return -2;
		}
	}
found:

	for (i = 0; i < arp_table->dwNumEntries; i++) {
        netsnmp_arp_entry *entry;

        /*
         */
		if ((entry = netsnmp_access_arp_entry_create()) == NULL) {
            rc = -3;
            break;
        }

		entry->if_index = arp_table->table[i].dwIndex;
		entry->arp_ipaddress_len = 4;
		memcpy(entry->arp_ipaddress, &arp_table->table[i].dwAddr, entry->arp_ipaddress_len);
		entry->arp_physaddress_len = 6;
		memcpy(entry->arp_physaddress, &arp_table->table[i].bPhysAddr, entry->arp_physaddress_len);

		switch (arp_table->table[i].dwType) {
		case MIB_IPNET_TYPE_OTHER:
			entry->arp_type = INETNETTOMEDIATYPE_STATIC;
			entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
			break;
		case MIB_IPNET_TYPE_INVALID:
			entry->arp_type = INETNETTOMEDIATYPE_STATIC;
			entry->arp_state = INETNETTOMEDIASTATE_UNKNOWN;
			break;
		case MIB_IPNET_TYPE_DYNAMIC:
			entry->arp_type = INETNETTOMEDIATYPE_DYNAMIC;
			entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
			break;
		case MIB_IPNET_TYPE_STATIC:
			entry->arp_type = INETNETTOMEDIATYPE_STATIC;
			entry->arp_state = INETNETTOMEDIASTATE_REACHABLE;
			break;
		}

      
        /*
         * add entry to container
         */
//        entry->ns_ia_index = CONTAINER_SIZE(container) + 1;
		entry->ns_arp_index = ++idx_offset;
        CONTAINER_INSERT(container, entry);
    }

	free(arp_table);

	if (rc < 0) {
		return rc;
	}

	return idx_offset;
}

#if defined (NETSNMP_ENABLE_IPV6)
static int
_load_v6(netsnmp_container *container, int idx_offset)
{
    return 0;
}
#endif

