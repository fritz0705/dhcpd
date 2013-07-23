#include "argv.h"

#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static struct option long_options[] =
	{
		{"version",     no_argument,       0, 'V'},
		{"help",        no_argument,       0, 'h'},

		{"user",        required_argument, 0, 'u'},
		{"group",       required_argument, 0, 'g'},

		{"debug",       no_argument,       0, 'd'},
//		{"log",         no_argument,       0, 'l'},

		{"interface",   required_argument, 0, 'i'},

		{"prefix",      required_argument, 0, 'p'},
		{"range",       required_argument, 0, 'r'},
		{"leasetime",   required_argument, 0, 't'},
		{"ltime",       required_argument, 0, 't'},

		{"gw",          required_argument, 0, 0x10000},
		{"gateway",     required_argument, 0, 0x10000},
		{"ns",          required_argument, 0, 0x10001},
		{"nameserver",  required_argument, 0, 0x10001},

		{0, 0, 0, 0}
	};

static const void *(* argv_realloc)(void *, size_t) = realloc;

bool argv_parse(int argc, char **argv, struct argv *out)
{
	out->argv = argv;
	out->argc = argc;
	out->arg0 = argv[0];

	optind = 0;

	while(1) {
		/* getopt_long stores the option index here. */
		int option_index = 0;

		int idx = getopt_long (argc, argv, "Vdg:hi:r:t:u:", long_options, &option_index);

		if(-1 == idx) {
			break;
		}

		switch (state)
		{
			case 'h':
				out->help = true;
				break;

			case 'V':
				out->version = true;
				break;

			case 'd':
				out->debug = true;
				break;

			case 't':
				out->argerror = optarg;
				break;

			case 'i':
				out->interface = optarg;
				break;

			case 'u':
				out->user = optarg;
				break;

			case 'g':
				out->group = optarg;
				break;

			case 'p':
				out->iprange[0] = optarg;
				break;

			case 'r':
				out->iprange[1] = optarg;
				break;

			case 't':
				out->leasetime = optarg;
				break;

			case 0x10000:
				out->routers = argv_realloc(
					out->routers,
					++out->routers_cnt * sizeof(char*));
				out->routers[out->routers_cnt - 1] = optarg;
				break;

			case 0x10001:
				out->nameservers = argv_realloc(
					out->nameservers,
					++out->nameservers_cnt * sizeof(char*));
				out->nameservers[out->nameservers_cnt - 1] = optarg;
				break;

			default:
				out->argerror = -1;
				return false;
		}
	}

	if (optind < argc) {
		printf ("non-option ARGV-elements: ");
		while (optind < argc) {
			printf ("%s ", argv[optind++]);
			putchar ('\n');
		}

		out->argerror = -1;
		return false;
	}

	return true;
}
