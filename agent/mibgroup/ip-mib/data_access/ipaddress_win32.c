/*
 *  Interface MIB architecture support
 *
 * $Id: ipaddress_linux.c 17255 2008-10-14 09:44:26Z jsafranek $
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include "mibII/mibII_common.h"

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/ipaddress.h>
#include <net-snmp/data_access/interface.h>

#include "ip-mib/ipAddressTable/ipAddressTable_constants.h"
#include "ip-mib/ipAddressPrefixTable/ipAddressPrefixTable_constants.h"
#include "mibgroup/util_funcs.h"

#include <iphlpapi.h>
#include "iphlpapi_missing.h"
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

#ifdef SUPPORT_PREFIX_FLAGS
extern prefix_cbx *prefix_head_list;
extern pthread_mutex_t prefix_mutex_lock;
#endif

/*
 * initialize arch specific storage
 *
 * @retval  0: success
 * @retval <0: error
 */
int
netsnmp_arch_ipaddress_entry_init(netsnmp_ipaddress_entry *entry)
{   
    return 0;
}

/*
 * cleanup arch specific storage
 */
void
netsnmp_arch_ipaddress_entry_cleanup(netsnmp_ipaddress_entry *entry)
{
}

/*
 * copy arch specific storage
 */
int
netsnmp_arch_ipaddress_entry_copy(netsnmp_ipaddress_entry *lhs,
                                  netsnmp_ipaddress_entry *rhs)
{
    return 0;
}

/*
 * create a new entry
 */
int
netsnmp_arch_ipaddress_create(netsnmp_ipaddress_entry *entry)
{
    if (NULL == entry)
        return -1;

    return 0;
}

/*
 * create a new entry
 */
int
netsnmp_arch_ipaddress_delete(netsnmp_ipaddress_entry *entry)
{
    return 0;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_ipaddress_container_load(netsnmp_container *container,
                                      u_int load_flags)
{
    int rc = 0, idx_offset = 0;

    if (0 == (load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV6_ONLY)) {
        rc = _load_v4(container, idx_offset);
        if(rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
        }
    }

#if defined (NETSNMP_ENABLE_IPV6)

    if (0 == (load_flags & NETSNMP_ACCESS_IPADDRESS_LOAD_IPV4_ONLY)) {
        if (rc < 0)
            rc = 0;

        idx_offset = rc;

        /*
         * load ipv6, ignoring errors if file not found
         */
        rc = _load_v6(container, idx_offset);
        if (-2 == rc)
            rc = 0;
        else if(rc < 0) {
            u_int flags = NETSNMP_ACCESS_IPADDRESS_FREE_KEEP_CONTAINER;
            netsnmp_access_ipaddress_container_free(container, flags);
        }
    }
#endif

    /*
     * return no errors (0) if we found any interfaces
     */
    if(rc > 0)
        rc = 0;

    return rc;
}

int
_load_v4(netsnmp_container *container, int idx_offset)
{
    int						rc = 0;
	int						retry;
	DWORD					ip_table_size;
	PMIB_IPADDRTABLE        ip_table;
	DWORD					mask;
	int						pfx_len;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	ip_table_size = sizeof (MIB_IPADDRTABLE);
	if ((ip_table = malloc(ip_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		switch (GetIpAddrTable(ip_table, &ip_table_size, TRUE)) {
		case NO_ERROR:
			goto found;
		case ERROR_INSUFFICIENT_BUFFER:
			if (retry < 4) {
				free(ip_table);
				if ((ip_table = malloc(ip_table_size)) == NULL) {
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

	for (i = 0; i < ip_table->dwNumEntries; i++) {
        netsnmp_ipaddress_entry *entry;

        /*
         */
		if ((entry = netsnmp_access_ipaddress_entry_create()) == NULL) {
            rc = -3;
            break;
        }

        /** oddly enough, these appear to already be in network order */
		entry->ia_address_len = 4;
		memcpy(entry->ia_address, &ip_table->table[i].dwAddr, entry->ia_address_len);
		entry->if_index = ip_table->table[i].dwIndex;
		entry->ia_status = IPADDRESSSTATUSTC_PREFERRED;
        entry->ia_type = IPADDRESSTYPE_UNICAST;
        entry->ia_prefered_lifetime = 0;
        entry->ia_valid_lifetime = 0;
        entry->ia_storagetype = 0;
        entry->ia_onlink_flag = 1;  /*Set by default as true*/
        entry->ia_autonomous_flag = 2; /*Set by default as false*/

		if (ip_table->table[i].wType == MIB_IPADDR_DYNAMIC) {
			entry->ia_origin = IPADDRESSORIGINTC_DHCP;
		} else {
			entry->ia_origin = IPADDRESSORIGINTC_MANUAL;
		}

		// Convert mask to prefix length.
		mask = ntohl(ip_table->table[i].dwMask);
		for (pfx_len = 0; pfx_len < 32; pfx_len++) {
			if (((mask << pfx_len) & 0x80000000UL) == 0) {
				// found a zero bit.
				break;
			}
		}
        entry->ia_prefix_len = pfx_len;

        
        /*
         * add entry to container
         */
//        entry->ns_ia_index = CONTAINER_SIZE(container) + 1;
		entry->ns_ia_index = ++idx_offset;
        CONTAINER_INSERT(container, entry);
    }

	free(ip_table);

	if (rc < 0) {
		return rc;
	}

	return idx_offset;
}

#if defined (NETSNMP_ENABLE_IPV6)
/**
 */
int
_load_v6(netsnmp_container *container, int idx_offset)
{

}

#endif

