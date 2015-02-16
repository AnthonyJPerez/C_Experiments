#include <dlfcn.h>
#include <elf.h>
#include <link.h>
#include <stdio.h>
#include "main.h"

typedef void (*fp_destructor_t)(void);

// Using stackoverflow.com/questions/17620751/use-dlinfo-to-print-all-symbols-in-a-library
void ParseElf (const struct link_map * pLinkMap)
{
	// Grab a pointer to the dynamic section:
	const ElfW(Dyn) * const dyn_start = pLinkMap->l_ld;
	const ElfW(Addr) load_addr = pLinkMap->l_addr;
	fp_destructor_t * fpDestructorPtr = NULL;
	ElfW(Word) segmentSize = 0;

	printf("Module loaded at: %p\n", (void*)load_addr);
	// Look for the DT_FINI_ARRAY section:
	for (	const ElfW(Dyn) * dyn = dyn_start;
		dyn->d_tag != DT_NULL;
		++dyn)
	{
		if (DT_FINI_ARRAY == dyn->d_tag)
		{
			printf("Found DT_FINI_ARRAY section\n");
			printf("tag: %d, ptr: %p, startAddr: %p\n",
				(int) dyn->d_tag, 
				(const void *)dyn->d_un.d_ptr, 
				(const void *)(dyn->d_un.d_ptr + load_addr));
			fpDestructorPtr = (fp_destructor_t*)(dyn->d_un.d_ptr + load_addr);
		}
		else if (DT_FINI_ARRAYSZ == dyn->d_tag)
		{
			printf("Found DT_FINI_ARRAYSZ section\n");
			printf("tag: %d, val: %u\n",
				(int) dyn->d_tag,
				(int) dyn->d_un.d_val);
			segmentSize = dyn->d_un.d_val;
		}
	}

	fp_destructor_t fpDestructor = *(fpDestructorPtr + (segmentSize / sizeof(fp_destructor_t) - 1));
	printf("destructor located at: %p\n", fpDestructor);
	fpDestructor();
	fpDestructor();
}


int main (int argc, char * argv[])
{
	char * szLibName = argv[1];
	printf("Starting main with library: %s\n", szLibName);
	
	printf("About to dlopen(%s)\n", szLibName);
	void * handle = dlopen(szLibName, RTLD_NOW);
	if (NULL == handle)
	{
		printf("dlopen failed: %s\n", dlerror());
		goto CLEANUP;	
	}

	printf("Grabbing the link_map structure\n");
	struct link_map * linkMap = NULL;
	int ret = dlinfo(handle, RTLD_DI_LINKMAP, &linkMap);
	if (NULL == linkMap)
	{
		printf("dlinfo failed: %s\n", dlerror());
		goto CLEANUP;
	}

	ParseElf(linkMap);	
	

CLEANUP:
	return 0;
}

