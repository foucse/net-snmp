/*
 *  Interface MIB architecture support
 *
 * $Id: route_linux.c 17099 2008-07-02 12:39:23Z jsafranek $
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/interface.h>
#include <net-snmp/data_access/route.h>
#include <net-snmp/data_access/ipaddress.h>

#include "ip-forward-mib/data_access/route_ioctl.h"
#include "ip-forward-mib/inetCidrRouteTable/inetCidrRouteTable_constants.h"
#include "if-mib/data_access/interface_ioctl.h"

#include <iphlpapi.h>
#include "iphlpapi_missing.h"
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static int
_load_ipv4(netsnmp_container* container, u_long *index )
{
    int						rc = 0;
	int						retry;
	DWORD					ipf_table_size;
	PMIB_IPFORWARDTABLE     ipf_table;
	DWORD					mask;
	int						pfx_len;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	ipf_table_size = sizeof (MIB_IPFORWARDTABLE);
	if ((ipf_table = malloc(ipf_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		switch (GetIpForwardTable(ipf_table, &ipf_table_size, TRUE)) {
		case NO_ERROR:
			goto found;
		case ERROR_INSUFFICIENT_BUFFER:
			if (retry < 4) {
				free(ipf_table);
				if ((ipf_table = malloc(ipf_table_size)) == NULL) {
					snmp_log(LOG_ERR, "Out of memory.\n");
					return -3;
				}
			} else {
				snmp_log(LOG_ERR, "Could not allocate enough memory to get the ip table.\n");
				return -2;
			}
			break;
		default:
			snmp_log(LOG_ERR, "Error when using GetIPAddrTable.\n");
			return -2;
		}
	}
found:

	for (i = 0; i < ipf_table->dwNumEntries; i++) {
        netsnmp_route_entry *entry;

        /*
         */
		if ((entry = netsnmp_access_route_entry_create()) == NULL) {
            rc = -3;
            break;
        }


		entry->if_index = ipf_table->table[i].dwForwardIfIndex;
		entry->rt_dest_type = INETADDRESSTYPE_IPV4;
		entry->rt_nexthop_type = INETADDRESSTYPE_IPV4;
		entry->rt_dest_len = 4;
		entry->rt_nexthop_len = 4;
		memcpy(entry->rt_dest, &ipf_table->table[i].dwForwardDest, entry->rt_dest_len);
		memcpy(entry->rt_nexthop, &ipf_table->table[i].dwForwardNextHop, entry->rt_dest_len);
		entry->rt_nexthop_as = ipf_table->table[i].dwForwardNextHopAS;
		entry->rt_metric1 = ipf_table->table[i].dwForwardMetric1;
		entry->rt_metric2 = ipf_table->table[i].dwForwardMetric2;
		entry->rt_metric3 = ipf_table->table[i].dwForwardMetric3;
		entry->rt_metric4 = ipf_table->table[i].dwForwardMetric4;
		entry->rt_metric5 = ipf_table->table[i].dwForwardMetric5;
		entry->rt_type = ipf_table->table[i].dwForwardType;
		entry->rt_proto = ipf_table->table[i].dwForwardProto;
		entry->rt_age = ipf_table->table[i].dwForwardAge;

#ifdef USING_IP_FORWARD_MIB_IPCIDRROUTETABLE_IPCIDRROUTETABLE_MODULE
		entry->rt_mask = ip_table->table[i].dwForwardMask;
		entry->rt_policy = ipf_table->table[i].dwForwardPolicy;
		entry->rt_policy_len = 1;
        entry->flags = NETSNMP_ACCESS_ROUTE_POLICY_STATIC;
#endif

		// Convert mask to prefix length.
		mask = ntohl(ipf_table->table[i].dwForwardMask);
        entry->rt_pfx_len = netsnmp_ipaddress_ipv4_prefix_len(mask);

		entry->ns_rt_index = ++(*index);
        CONTAINER_INSERT(container, entry);
    }

	free(ipf_table);

	if (rc < 0) {
		return rc;
	}

	return 0;
}

#ifdef NETSNMP_ENABLE_IPV6
static int
_load_ipv6(netsnmp_container* container, u_long *index )
{
    return 0;
}
#endif

/** arch specific load
 * @internal
 *
 * @retval  0 success
 * @retval -1 no container specified
 * @retval -2 could not open data file
 */
int
netsnmp_access_route_container_arch_load(netsnmp_container* container,
                                         u_int load_flags)
{
    u_long          count = 0;
    int             rc;

    DEBUGMSGTL(("access:route:container",
                "route_container_arch_load (flags %x)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_route\n");
        return -1;
    }

    rc = _load_ipv4(container, &count);
    
#ifdef NETSNMP_ENABLE_IPV6
    if((0 != rc) || (load_flags & NETSNMP_ACCESS_ROUTE_LOAD_IPV4_ONLY))
        return rc;

    /*
     * load ipv6. ipv6 module might not be loaded,
     * so ignore -2 err (file not found)
     */
    rc = _load_ipv6(container, &count);
    if (-2 == rc)
        rc = 0;
#endif

    return rc;
}

/*
 * create a new entry
 */
int
netsnmp_arch_route_create(netsnmp_route_entry *entry)
{
	return 0;
}

/*
 * create a new entry
 */
int
netsnmp_arch_route_delete(netsnmp_route_entry *entry)
{
	return 0;
}


