#include <stdio.h>
#include <unistd.h>

void print_greetings_patched(int var)
{
	printf("Hello. This is a PATCHED version\n");
	printf("Hello. <newly_added_var=0x%08x>\n", var);
}

void print_greetings(void)
{
	printf("Hello. This is an UNPATCHED version\n");
}

int main()
{
	while (1) {
		print_greetings();
		sleep(1);
	}

	return 0;
}
