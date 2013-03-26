#include <unistd.h>
#include "../db.h"
int main()
{
	write(1, DB_SCHEMA, sizeof DB_SCHEMA);
	return 0;
}
