/*
 *  tcpConnTable MIB architecture support
 *
 * $Id: tcpConn_linux.c 17534 2009-04-23 06:41:55Z magfr $
 */
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>

#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/data_access/tcpConn.h>

#include "tcp-mib/tcpConnectionTable/tcpConnectionTable_constants.h"
#include "tcp-mib/data_access/tcpConn_private.h"

//#include <winsock2.h>
//#include <ws2tcpip.h>
#include <iphlpapi.h>
#include "iphlpapi_missing.h"
#include <stdio.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")

static pGetExtendedTcpTable_t pGetExtendedTcpTable = NULL;

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
netsnmp_arch_tcpconn_entry_init(netsnmp_tcpconn_entry *entry)
{
	return 0;
}

/*
 * cleanup arch specific storage
 */
void
netsnmp_arch_tcpconn_entry_cleanup(netsnmp_tcpconn_entry *entry)
{
    /*
     * cleanup
     */
}

/*
 * copy arch specific storage
 */
int
netsnmp_arch_tcpconn_entry_copy(netsnmp_tcpconn_entry *lhs,
                                  netsnmp_tcpconn_entry *rhs)
{
    return 0;
}

/*
 * delete an entry
 */
int
netsnmp_arch_tcpconn_delete(netsnmp_tcpconn_entry *entry)
{
    if (NULL == entry)
        return -1;
    /** xxx-rks:9 tcpConn delete not implemented */
    return -1;
}


/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
int
netsnmp_arch_tcpconn_container_load(netsnmp_container *container,
                                    u_int load_flags )
{
    int rc = 0;

    DEBUGMSGTL(("access:tcpconn:container",
                "tcpconn_container_arch_load (flags %x)\n", load_flags));

    if (NULL == container) {
        snmp_log(LOG_ERR, "no container specified/found for access_tcpconn\n");
        return -1;
    }

    rc = _load4(container, load_flags);

#if defined (NETSNMP_ENABLE_IPV6)
    if((0 != rc) || (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_IPV4_ONLY))
        return rc;

    /*
     * load ipv6. ipv6 module might not be loaded,
     * so ignore -2 err (file not found)
     */
    rc = _load6(container, load_flags);
    if (-2 == rc)
        rc = 0;
#endif

    return rc;
}

/**
 *
 * @retval  0 no errors
 * @retval !0 errors
 */
static int
_initGetExtendedTcpTable(void) {
	HMODULE iphlpapi_m;

	if (pGetExtendedTcpTable != NULL) {
		return 0;
	}

	iphlpapi_m = LoadLibrary("iphlpapi.dll");

	pGetExtendedTcpTable = (pGetExtendedTcpTable_t)GetProcAddress(iphlpapi_m, "GetExtendedTcpTable");
	if (pGetExtendedTcpTable == NULL) {
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
	DWORD					tcp_table_size;
	PMIB_TCPTABLE_OWNER_PID tcp_table;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// Make sure GetExtendedTcpTable is loaded.
	if (_initGetExtendedTcpTable() != 0) {
		return -2;
	}

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	tcp_table_size = sizeof (MIB_TCPTABLE);
	if ((tcp_table = malloc(tcp_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		switch (pGetExtendedTcpTable(tcp_table, &tcp_table_size, TRUE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0)) {
		case NO_ERROR:
			goto found;
		case ERROR_INSUFFICIENT_BUFFER:
			if (retry < 4) {
				free(tcp_table);
				if ((tcp_table = malloc(tcp_table_size)) == NULL) {
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

	for (i = 0; i < tcp_table->dwNumEntries; i++) {
        netsnmp_tcpconn_entry *entry;

        /*
         */
		if ((entry = netsnmp_access_tcpconn_entry_create()) == NULL) {
            rc = -3;
            break;
        }

        /*
         * check if we care about listen state
         */
		switch (tcp_table->table[i].dwState) {
        case MIB_TCP_STATE_CLOSED:
			entry->tcpConnState = TCPCONNECTIONSTATE_CLOSED;
            break;
        case MIB_TCP_STATE_LISTEN:
			entry->tcpConnState = TCPCONNECTIONSTATE_LISTEN;
            break;
        case MIB_TCP_STATE_SYN_SENT:
			entry->tcpConnState = TCPCONNECTIONSTATE_SYNSENT;
            break;
        case MIB_TCP_STATE_SYN_RCVD:
			entry->tcpConnState = TCPCONNECTIONSTATE_SYNRECEIVED;
            break;
        case MIB_TCP_STATE_ESTAB:
			entry->tcpConnState = TCPCONNECTIONSTATE_ESTABLISHED;
            break;
        case MIB_TCP_STATE_FIN_WAIT1:
			entry->tcpConnState = TCPCONNECTIONSTATE_FINWAIT1;
            break;
        case MIB_TCP_STATE_FIN_WAIT2:
			entry->tcpConnState = TCPCONNECTIONSTATE_FINWAIT2;
            break;
        case MIB_TCP_STATE_CLOSE_WAIT:
			entry->tcpConnState = TCPCONNECTIONSTATE_CLOSEWAIT;
            break;
        case MIB_TCP_STATE_CLOSING:
			entry->tcpConnState = TCPCONNECTIONSTATE_CLOSING;
            break;
        case MIB_TCP_STATE_LAST_ACK:
			entry->tcpConnState = TCPCONNECTIONSTATE_LASTACK;
            break;
        case MIB_TCP_STATE_TIME_WAIT:
			entry->tcpConnState = TCPCONNECTIONSTATE_TIMEWAIT;
            break;
        case MIB_TCP_STATE_DELETE_TCB:
			entry->tcpConnState = TCPCONNECTIONSTATE_DELETETCB;
            break;
        default:
			entry->tcpConnState = TCPCONNECTIONSTATE_CLOSED;
            break;
        }

		if (load_flags) {
            if (TCPCONNECTIONSTATE_LISTEN == entry->tcpConnState) {
                if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_NOLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping listen\n"));
                    continue;
                }
            }
            else if (load_flags & NETSNMP_ACCESS_TCPCONN_LOAD_ONLYLISTEN) {
                    DEBUGMSGT(("verbose:access:tcpconn:container",
                               " skipping non-listen\n"));
                    continue;
            }
        }

        /** oddly enough, these appear to already be in network order */
		entry->loc_addr_len = 4;
		entry->rmt_addr_len = 4;
		memcpy(entry->loc_addr, &tcp_table->table[i].dwLocalAddr, entry->loc_addr_len);
		memcpy(entry->rmt_addr, &tcp_table->table[i].dwRemoteAddr, entry->rmt_addr_len);
        entry->loc_port = ntohs((u_short)tcp_table->table[i].dwLocalPort & 0xffff);
        entry->rmt_port = ntohs((u_short)tcp_table->table[i].dwRemotePort & 0xffff);
        entry->pid = tcp_table->table[i].dwOwningPid;
        
        /*
         * add entry to container
         */
        entry->arbitrary_index = CONTAINER_SIZE(container) + 1;
        CONTAINER_INSERT(container, entry);
    }

	free(tcp_table);
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
    int             rc = 0;

    return rc;
}
#endif /* NETSNMP_ENABLE_IPV6 */
