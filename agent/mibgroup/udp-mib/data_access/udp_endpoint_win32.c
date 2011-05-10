/*
 *  udpEndpointTable MIB architecture support
 *
 * $Id: udp_endpoint_linux.c 17723 2009-08-05 20:07:38Z dts12 $
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/file_utils.h>
#include <net-snmp/library/text_utils.h>

#include <net-snmp/data_access/ipaddress.h>
#include <net-snmp/data_access/udp_endpoint.h>

#include "udp-mib/udpEndpointTable/udpEndpointTable_constants.h"
#include "udp_endpoint_private.h"

#include <fcntl.h>

#include <iphlpapi.h>
#include "iphlpapi_missing.h"
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static pGetExtendedUdpTable_t pGetExtendedUdpTable = NULL;

static int _load4(netsnmp_container *container, u_int flags);
#if defined (NETSNMP_ENABLE_IPV6)
static int _load6(netsnmp_container *container, u_int flags);
#endif

/*
 * initialize arch specific storage
 *
 * @retval  0: success
 * @retval <0: error
 */
int
netsnmp_arch_udp_endpoint_entry_init(netsnmp_udp_endpoint_entry *entry)
{
    /*
     * init
     */
    return 0;
}

/*
 * cleanup arch specific storage
 */
void
netsnmp_arch_udp_endpoint_entry_cleanup(netsnmp_udp_endpoint_entry *entry)
{
    /*
     * cleanup
     */
}

/*
 * copy arch specific storage
 */
int
netsnmp_arch_udp_endpoint_entry_copy(netsnmp_udp_endpoint_entry *lhs,
                                  netsnmp_udp_endpoint_entry *rhs)
{
    return 0;
}

/*
 * delete an entry
 */
int
netsnmp_arch_udp_endpoint_delete(netsnmp_udp_endpoint_entry *entry)
{
    if (NULL == entry)
        return -1;
    /** xxx-rks:9 udp_endpoint delete not implemented */
    return -1;
}


/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_udp_endpoint_container_load(netsnmp_container *container,
                                    u_int load_flags )
{
    int rc = 0;

    rc = _load4(container, load_flags);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_UDP_ENDPOINT_FREE_KEEP_CONTAINER;
        netsnmp_access_udp_endpoint_container_free(container, flags);
        return rc;
    }

#if defined (NETSNMP_ENABLE_IPV6)
    rc = _load6(container, load_flags);
    if(rc < 0) {
        u_int flags = NETSNMP_ACCESS_UDP_ENDPOINT_FREE_KEEP_CONTAINER;
        netsnmp_access_udp_endpoint_container_free(container, flags);
        return rc;
    }
#endif

    return 0;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_initGetExtendedUdpTable(void) {
	HMODULE iphlpapi_m;

	if (pGetExtendedUdpTable != NULL) {
		return 0;
	}

	iphlpapi_m = LoadLibrary("iphlpapi.dll");

	pGetExtendedUdpTable = (pGetExtendedTcpTable_t)GetProcAddress(iphlpapi_m, "GetExtendedUdpTable");
	if (pGetExtendedUdpTable == NULL) {
		snmp_log(LOG_ERR, "Could not find GetExtendedTcpTable function.\n");
		return -1;
	}

	return 0;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_load4(netsnmp_container *container, u_int load_flags)
{
    int						rc = 0;
	int						retry;
	DWORD					udp_table_size;
	PMIB_UDPTABLE_OWNER_PID udp_table;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// Make sure GetExtendedTcpTable is loaded.
	if (_initGetExtendedUdpTable() != 0) {
		return -2;
	}

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	udp_table_size = sizeof (MIB_UDPTABLE);
	if ((udp_table = malloc(udp_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		switch (pGetExtendedUdpTable(udp_table, &udp_table_size, TRUE, AF_INET, UDP_TABLE_OWNER_PID, 0)) {
		case NO_ERROR:
			goto found;
		case ERROR_INSUFFICIENT_BUFFER:
			if (retry < 4) {
				free(udp_table);
				if ((udp_table = malloc(udp_table_size)) == NULL) {
					snmp_log(LOG_ERR, "Out of memory.\n");
					return -3;
				}
			} else {
				snmp_log(LOG_ERR, "Could not allocate enough memory to get the tcptable.\n");
				return -2;
			}
			break;
		default:
			snmp_log(LOG_ERR, "Error when using GetTcpTable.\n");
			return -2;
		}
	}
found:

	for (i = 0; i < udp_table->dwNumEntries; i++) {
        netsnmp_udp_endpoint_entry *entry;

        /*
         */
		if ((entry = netsnmp_access_udp_endpoint_entry_create()) == NULL) {
            rc = -3;
            break;
        }

        /** oddly enough, these appear to already be in network order */
		entry->loc_addr_len = 4;
		entry->rmt_addr_len = 4;
		memcpy(entry->loc_addr, &udp_table->table[i].dwLocalAddr, entry->loc_addr_len);
		memset(entry->rmt_addr, 0, entry->rmt_addr_len);
        entry->loc_port = ntohs((u_short)udp_table->table[i].dwLocalPort & 0xffff);
        entry->rmt_port = ntohs(0);
        entry->pid = udp_table->table[i].dwOwningPid;
		entry->state = 10; /* On linux this means listening on UDP. */
        
        /*
         * add entry to container
         */
        entry->index = CONTAINER_SIZE(container) + 1;
        CONTAINER_INSERT(container, entry);
    }

	free(udp_table);
    return rc;
}

#if defined (NETSNMP_ENABLE_IPV6)
/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_load6(netsnmp_container *container, u_int load_flags)
{
    return (NULL == container);
}
#endif /* NETSNMP_ENABLE_IPV6 */
