/******************************************************************************
 * 2021.10.13 - test: fix some problems in UT tests
 * Huawei Technologies Co., Ltd. <yubihong@huawei.com>
 ******************************************************************************/


#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

int *p;
int __thread v;

void print_greetings(void)
{
	printf("TLS UNPATCHED\n");
}

int main()
{
	v = 0xDEADBEAF;
	p = &v;

	while (1) {
		print_greetings();
		sleep(1);
	}
	return 0;
}
