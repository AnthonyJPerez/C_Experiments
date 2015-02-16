#include <stdio.h>
#include "main.h"

void __attribute__((constructor)) onLoad (void)
{
	printf("constructor()\n");
}


void __attribute__((destructor)) onUnload (void)
{
	printf("destructor()\n");
}


int main (int argc, char * argv[])
{
	printf("Starting main\n");
	return 0;
}

