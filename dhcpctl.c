#include <stdlib.h>
#include <string.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include <sqlite3.h>

#include "db.h"
#include "error.h"

sqlite3 *db = NULL;
extern char **environ;

static int main_lease(int argc, char **argv);
static int main_lease_add(int argc, char **argv);
static int main_lease_show(int argc, char **argv);
static int main_lease_remove(int argc, char **argv);
static int main_start(int argc, char **argv);
static int main_stop(int argc, char **argv);
static int main_restart(int argc, char **argv);
static int main_flush(int argc, char **argv);
static int main_help(int argc, char **argv);
static int main_mkdb(int argc, char **argv);

int main(int argc, char **argv)
{
	int (*command)(int, char **) = main_help;
	if (1 < argc)
	{
		char *arg = argv[1];

		if (!strcmp(arg, "lease"))
			command = main_lease;
		else if (!strcmp(arg, "leases"))
			command = main_lease;
		else if (!strcmp(arg, "start"))
			command = main_start;
		else if (!strcmp(arg, "stop"))
			command = main_stop;
		else if (!strcmp(arg, "restart"))
			command = main_restart;
		else if (!strcmp(arg, "flush"))
			command = main_flush;
		else if (!strcmp(arg, "help"))
			command = main_help;
		else if (!strcmp(arg, "mkdb"))
			command = main_mkdb;
	}

	return command(argc - 1, argv + 1);
}

static int main_mkdb(int argc, char **argv)
{
	if (argc < 3)
		return main_help(argc, argv);

	if (!strcmp(argv[1], "file"))
	{
		if (sqlite3_open(argv[2], &db) != SQLITE_OK)
			dhcpd_error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(db));
	}
	else if (!strcmp(argv[1], "interface") || !strcmp(argv[1], "if"))
	{
		size_t db_file_len = strlen(argv[2]) + sizeof ".db" + 1;
		char db_file[db_file_len];

		strcpy(db_file, argv[2]);
		strcpy(db_file + db_file_len - sizeof ".db" - 1, ".db");
		db_file[db_file_len - 1] = 0;
		
		if (sqlite3_open(db_file, &db) != SQLITE_OK)
			dhcpd_error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(db));
	}

	db_init(db);
	sqlite3_close(db);

	return 0;
}

static int main_lease(int argc, char **argv)
{
	(void)argc, (void)argv;

	int (*command)(int, char **) = NULL;

	struct {
		char *db;
		char *interface;
		char *command;
	} dhcpctl_lease = {
		.db = NULL,
		.interface = NULL,
		.command = NULL
	};

	int i = 1;
	{
		int state = 0;
		for (; i < argc; ++i)
		{
			char *arg = argv[i];
			switch (state)
			{
				case 0:
					if (arg[0] != '-')
					{
						dhcpctl_lease.command = arg;
						goto end_loop;
					}

					if (!strcmp(arg, "-db"))
						state = 1;
					else if (!strcmp(arg, "-interface"))
						state = 2;
					else if (!strcmp(arg, "-if"))
						state = 2;
					break;
				case 1:
					dhcpctl_lease.db = arg;
					state = 0;
					break;
				case 2:
					dhcpctl_lease.interface = arg;
					state = 0;
					break;
			}
			continue;
end_loop:
			break;
		}
	}

	if (dhcpctl_lease.command)
	{
		if (!strcmp(dhcpctl_lease.command, "add"))
			command = main_lease_add;
		else if (!strcmp(dhcpctl_lease.command, "get"))
			command = main_lease_show;
		else if (!strcmp(dhcpctl_lease.command, "show"))
			command = main_lease_show;
		else if (!strcmp(dhcpctl_lease.command, "remove"))
			command = main_lease_remove;
	}

	if (dhcpctl_lease.db)
	{
		if (sqlite3_open(dhcpctl_lease.db, &db) != SQLITE_OK)
			dhcpd_error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(db));
	}
	else if (dhcpctl_lease.interface)
	{
		size_t db_file_len = strlen(dhcpctl_lease.interface) + sizeof ".db" + 1;
		char db_file[db_file_len];

		strcpy(db_file, dhcpctl_lease.interface);
		strcpy(db_file + db_file_len - sizeof ".db" - 1, ".db");
		db_file[db_file_len - 1] = 0;
		
		if (sqlite3_open(db_file, &db) != SQLITE_OK)
			dhcpd_error(1, 0, "Error while opening lease database: %s", sqlite3_errmsg(db));
	}
	else
		return main_help(argc, argv);

	db_init(db);

	if (command)
		return command(argc - i, argv + i);

	return main_help(argc, argv);
}

static int main_lease_add(int argc, char **argv)
{
	struct {
		char *hwaddr;
		char *ipaddr;
		char **routers;
		size_t routers_cnt;
		char **nameservers;
		size_t nameservers_cnt;
		uint32_t leasetime;
		uint8_t prefix;
	} dhcpctl_lease_add = {
		.hwaddr = NULL,
		.ipaddr = NULL,
		.routers = NULL,
		.routers_cnt = 0,
		.nameservers = NULL,
		.nameservers_cnt = 0,
		.leasetime = 3600,
		.prefix = 24
	};

	(void)dhcpctl_lease_add;

	if (argc < 3)
		return main_help(argc, argv);

	dhcpctl_lease_add.hwaddr = argv[1];
	dhcpctl_lease_add.ipaddr = argv[2];

	{
		int state = 0;
		for (int i = 3; i < argc; ++i)
		{
			char *arg = argv[i];
			switch (state)
			{
				case 0:
					if (!strcmp(arg, "router"))
						state = 1;
					else if (!strcmp(arg, "nameserver"))
						state = 2;
					else if (!strcmp(arg, "leasetime"))
						state = 3;
					else if (!strcmp(arg, "prefix"))
						state = 4;
					break;
				case 1:
					dhcpctl_lease_add.routers = realloc(dhcpctl_lease_add.routers,
						++dhcpctl_lease_add.routers_cnt * sizeof(char*));
					dhcpctl_lease_add.routers[dhcpctl_lease_add.routers_cnt-1] = arg;
					state = 0;
					break;
				case 2:
					dhcpctl_lease_add.nameservers = realloc(dhcpctl_lease_add.nameservers,
						++dhcpctl_lease_add.nameservers_cnt * sizeof(char*));
					dhcpctl_lease_add.nameservers[dhcpctl_lease_add.nameservers_cnt-1] = arg;
					state = 0;
					break;
				case 3:
					dhcpctl_lease_add.leasetime = atoi(arg);
					state = 0;
					break;
				case 4:
					dhcpctl_lease_add.prefix = atoi(arg);
					state = 0;
					break;
			}
		}
	}

	struct db_lease db_lease = {
		.id = 0,
		.address = dhcpctl_lease_add.ipaddr,
		.prefixlen = dhcpctl_lease_add.prefix,
		.hwaddr = dhcpctl_lease_add.hwaddr,
		.routers = (dhcpctl_lease_add.routers_cnt > 0) ?
			dhcpctl_lease_add.routers[0] : NULL,
		.nameservers = (dhcpctl_lease_add.nameservers_cnt > 0) ? 
			dhcpctl_lease_add.nameservers[0] : NULL,
		.leasetime = dhcpctl_lease_add.leasetime,
		.allocated = 0,
		.allocated_at = 0
	};

	int sqlerr;
	if ((sqlerr = db_insert(db, &db_lease)) != SQLITE_DONE)
		dhcpd_error(1, 0, "sqlite3: %s\n", sqlite3_errstr(sqlerr));

	return 0;
}

static int main_lease_show(int argc, char **argv)
{
	(void)argc, (void)argv;
	return 0;
}

static int main_lease_remove(int argc, char **argv)
{
	struct db_lease db_lease = DB_LEASE_EMPTY;
	for (int i = 1; i < argc; ++i)
	{
		db_lease.id = atoi(argv[i]);
		db_lease_delete(db, &db_lease);
	}
	return 0;
}

static int main_start(int argc, char **argv)
{
	struct {
		bool daemon;
		char *binary;
		char *pidfile;
		char *config;
		int argc;
		char **argv;
	} dhcpctl_start = {
		.daemon = true,
		.binary = "dhcpd",
		.pidfile = "dhcpd.pid",
		.config = NULL,
		.argc = 0,
		.argv = NULL
	};

	{
		int state = 0;
		for (int i = 1; i < argc; ++i)
		{
			char *arg = argv[i];
			switch (state)
			{
				case 0:
					if (!strcmp(arg, "nodaemon"))
						dhcpctl_start.daemon = false;
					else if (!strcmp(arg, "daemon"))
						dhcpctl_start.daemon = true;
					else if (!strcmp(arg, "nopidfile"))
						dhcpctl_start.pidfile = NULL;
					else if (!strcmp(arg, "binary"))
						state = 1;
					else if (!strcmp(arg, "pidfile"))
						state = 2;
					else if (!strcmp(arg, "config"))
						state = 3;
					else if (!strcmp(arg, "--"))
					{
						dhcpctl_start.argc = argc - i - 1;
						dhcpctl_start.argv = argv + i + 1;
						goto loop_end;
					}
					break;
				case 1:
					dhcpctl_start.binary = arg;
					state = 0;
					break;
				case 2:
					dhcpctl_start.pidfile = arg;
					state = 0;
					break;
				case 3:
					dhcpctl_start.config = arg;
					state = 0;
					break;
			}
			continue;
loop_end:
			break;
		}
	}

	if (dhcpctl_start.daemon)
	{
		pid_t pid = fork();
		if (pid == -1)
			dhcpd_error(1, errno, "Fork failed");
		else if (pid != 0)
			return 0;
	}

	if (dhcpctl_start.pidfile)
	{
		FILE *pidfile = fopen(dhcpctl_start.pidfile, "w");
		if (!pidfile)
			dhcpd_error(1, errno, "Opening pidfile %s failed", dhcpctl_start.pidfile);
		fprintf(pidfile, "%u\n", getpid());
		fclose(pidfile);
	}

	if (dhcpctl_start.argc < 0)
		dhcpctl_start.argc = 0;
	char **execargv = malloc(sizeof(char*) * (1 + dhcpctl_start.argc + 1));
	execargv[0] = dhcpctl_start.binary;
	execargv[1 + dhcpctl_start.argc] = NULL;
	if (dhcpctl_start.argc > 0)
		memcpy(execargv + 1, dhcpctl_start.argv, dhcpctl_start.argc * sizeof(char*));

	execve(dhcpctl_start.binary, execargv, environ);

	dhcpd_error(1, errno, "execve failed");

	return 0;
}

static int main_stop(int argc, char **argv)
{
	(void)argc, (void)argv;
	return 0;
}

static int main_restart(int argc, char **argv)
{
	(void)argc, (void)argv;
	return 0;
}

static int main_flush(int argc, char **argv)
{
	(void)argc, (void)argv;
	return 0;
}

static int main_help(int argc, char **argv)
{
	(void)argc, (void)argv;
	printf(
		"dhcpctl leases [-db FILE] [-if IF] show [ID]...\n"
		"dhcpctl leases [-db FILE] [-if IF] add HWADDR IPADDR [router IPADDR]...\n"
		"\t[namserver IPADDR]... [leasetime INT] [prefix INT]\n"
		"dhcpctl leases [-db FILE] [-if IF] remove ID...\n"
		"dhcpctl start [nodaemon] [binary FILE] [pidfile FILE] [config FILE] [-- [ARG]...]\n"
		"dhcpctl stop [pidfile FILE]\n"
		"dhcpctl restart [nodaemon] [binary FILE] [pidfile FILE] [config FILE] [-- [ARG]...]\n"
		"dhcpctl flush [pidfile FILE]\n"
		"dhcpctl mkdb [interface IF|file FILE]\n"
		"dhcpctl help\n");
	return 0;
}
