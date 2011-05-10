/*
 * swrun_cygwin.c:
 *     hrSWRunTable data access:
 *     Cygwin interface 
 */
#include <net-snmp/net-snmp-config.h>

#include <stdio.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif

#define PSAPI_VERSION 1

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <net-snmp/net-snmp-includes.h>
#include <net-snmp/agent/net-snmp-agent-includes.h>
#include <net-snmp/library/container.h>
#include <net-snmp/library/snmp_debug.h>
#include <net-snmp/data_access/swrun.h>
#include <net-snmp/data_access/swrun.h>

#pragma comment(lib, "Kernel32.lib")
#pragma comment(lib, "Psapi.lib")

#define FACTOR (0x19db1ded53ea710LL)
#define NSPERSEC 10000000LL
#define NSPERMSEC 10000LL

static time_t   __stdcall
to_time_t(PFILETIME ptr)
{
    long            rem;
    long long       x =
        ((long long) ptr->dwHighDateTime << 32) +
        ((unsigned) ptr->dwLowDateTime);
    x -= FACTOR;
    rem = x % NSPERSEC;
    rem += NSPERSEC / 2;
    x /= NSPERSEC;
    x += rem / NSPERSEC;
    return x;
}

static long
to_msec(PFILETIME ptr)
{
    long long       x =
        ((long long) ptr->dwHighDateTime << 32) +
        (unsigned) ptr->dwLowDateTime;
    x /= NSPERMSEC;
    return x;
}

OSVERSIONINFO   ver;
HMODULE         h;

/* ---------------------------------------------------------------------
 */
void
netsnmp_arch_swrun_init(void)
{
}

static int
_load_single_process(netsnmp_swrun_entry *entry, HANDLE h)
{
	int						rc = 0;
	int						i;
	int						retry;
	DWORD					mod_table_size;
	DWORD					mod_table_size_out;
	int						mod_table_length;
	HMODULE		            *mod_table;
	HMODULE					main_module;
	TCHAR					path[MAX_PATH];
    char                    *cp1, *cp2;
    FILETIME                ct, et, kt, ut;
    PROCESS_MEMORY_COUNTERS pmc;

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	mod_table_size = 1024 * sizeof (DWORD);
	if ((mod_table = malloc(mod_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		if (EnumProcessModules(h, mod_table, mod_table_size, &mod_table_size_out) == TRUE) {
			if (mod_table_size == mod_table_size_out) {
				// Not enough buffer space in the pid table.
				if (retry < 4) {
					free(mod_table);
					mod_table_size = mod_table_size_out * 10;	// make it 10 times larger.
					if ((mod_table = malloc(mod_table_size)) == NULL) {
						snmp_log(LOG_ERR, "Out of memory.\n");
						return -3;
					}
				} else {
					snmp_log(LOG_ERR, "Could not allocate enough memory to get the module table.\n");
					return -2;
				}
			} else {
				// The amount of memory was enough.
				goto found;
			}
				
		} else {
			return 0;
			snmp_log(LOG_ERR, "Error when using EnumProcessModules.\n");
			return -2;
		}
	}
found:
	mod_table_length = mod_table_size_out / sizeof (HMODULE);

	if (mod_table_length < 1) {
		snmp_log(LOG_ERR, "No modules found for this process.\n");
		return -2;
	}

	main_module = mod_table[0];

	// Get the filename of the process.
	if (GetModuleFileNameEx(h, main_module, path, MAX_PATH) == FALSE) {
		snmp_log(LOG_ERR, "No filename for this process.\n");
		return -2;
	}
	entry->hrSWRunPath_len = snprintf(entry->hrSWRunPath, sizeof (entry->hrSWRunPath) - 1, "%s", path);
	for (i = 0; i < entry->hrSWRunPath_len; i++) {
		entry->hrSWRunPath[i] = (entry->hrSWRunPath[i] == '\\') ? '/' : entry->hrSWRunPath[i];
	}

    /*
     * Set hrSWRunName to be the last component of hrSWRunPath,
     *    but without any file extension
     */
    if ( entry->hrSWRunPath_len ) {
        cp1 = strrchr( entry->hrSWRunPath, '.' );
        if ( cp1 )
            *cp1 = '\0';    /* Mask the file extension */

        cp2  = strrchr( entry->hrSWRunPath, '/' );
        if (cp2) 
            cp2++;           /* Find the final component ... */
        else
            cp2 = entry->hrSWRunPath;          /* ... if any */
        entry->hrSWRunName_len = snprintf(entry->hrSWRunName,
                                   sizeof(entry->hrSWRunName)-1, "%s", cp2);

        if ( cp1 )
            *cp1 = '.';     /* Restore the file extension */
    }

	if (GetProcessTimes(h, &ct, &et, &kt, &ut) == FALSE) {
		snmp_log(LOG_ERR, "No process time information for this process.\n");
		return -2;
	}
    entry->hrSWRunPerfCPU = (to_msec(&kt) + to_msec(&ut)) / 10;

	if (GetProcessMemoryInfo(h, &pmc, sizeof pmc) == FALSE) {
		snmp_log(LOG_ERR, "No process memory information for this process.\n");
		return -2;
	}
    entry->hrSWRunPerfMem = pmc.WorkingSetSize / 1024;

	/* Not sure how to get this information. */
	entry->hrSWRunStatus = HRSWRUNSTATUS_RUNNABLE;
}

/* ---------------------------------------------------------------------
 */
int
netsnmp_arch_swrun_container_load( netsnmp_container *container, u_int flags)
{
    int						rc = 0;
	int						retry;
	DWORD					pid_table_size;
	DWORD					pid_table_size_out;
	int						pid_table_length;
	PDWORD			        pid_table;
	unsigned int			i;

    netsnmp_assert(NULL != container);

	// First allocate a tcptable structure, this will be too small, but we will retry it later.
	pid_table_size = 1024 * sizeof (DWORD);
	if ((pid_table = malloc(pid_table_size)) == NULL) {
		snmp_log(LOG_ERR, "Out of memory.\n");
		return -3;
	}

	// We have to retry the GetTcpTable function a few times, until we have allocated enough
	// memory.
	for (retry = 0; ; retry++) {
		// Return the table of tcp connections. We do not care about the ordering of this list.
		if (EnumProcesses(pid_table, pid_table_size, &pid_table_size_out) == TRUE) {
			if (pid_table_size == pid_table_size_out) {
				// Not enough buffer space in the pid table.
				if (retry < 4) {
					free(pid_table);
					pid_table_size = pid_table_size_out * 10;	// make it 10 times larger.
					if ((pid_table = malloc(pid_table_size)) == NULL) {
						snmp_log(LOG_ERR, "Out of memory.\n");
						return -3;
					}
				} else {
					snmp_log(LOG_ERR, "Could not allocate enough memory to get the pid table.\n");
					return -2;
				}
			} else {
				// The amount of memory was enough.
				goto found;
			}
				
		} else {
			snmp_log(LOG_ERR, "Error when using EnumProcesses.\n");
			return -2;
		}
	}
found:
	pid_table_length = pid_table_size_out / sizeof (DWORD);

	for (i = 0; i < pid_table_length; i++) {
        netsnmp_swrun_entry *entry;
		DWORD				pid;
		HANDLE              h;

		pid = pid_table[i];
		if ((h = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid)) == NULL) {
			// Process no longer exists.
			continue;
		}

		if ((entry = netsnmp_swrun_entry_create(pid)) == NULL) {
            rc = -3;
            break;
        }
		entry->hrSWRunIndex = pid;

		if ((rc = _load_single_process(entry, h)) < 0) {
			break;
		}

        CloseHandle(h);
        rc = CONTAINER_INSERT(container, entry);
	}

    DEBUGMSGTL(("swrun:load:arch"," loaded %d entries\n",
                CONTAINER_SIZE(container)));

    return rc;
}
