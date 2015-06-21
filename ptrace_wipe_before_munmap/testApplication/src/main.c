
#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include "main.h"


void * 
getNewMap (
    size_t size
)
{
    void * memoryMapPtr = NULL;
    
    assert (size != 0);

    memoryMapPtr = mmap (
            NULL,    // Let the OS choose our address
            size,    // Map size
            PROT_READ | PROT_WRITE,        // Memory Permissions
            MAP_SHARED | MAP_ANONYMOUS,    // flags
            -1,        // File Descriptor is -1 for anonymous maps
            0);        // offset is ignored for anonymous maps
    
    if (MAP_FAILED == memoryMapPtr)
    {
        fprintf(stderr, "Error during mmap: %s\n", strerror(errno));
        return NULL;
    }

    printf("Memory map created at %p\n", memoryMapPtr);
    return memoryMapPtr;
}


void
freeMap (
    void * memoryMapPtr,
    size_t size
)
{
    assert (NULL != memoryMapPtr);
    assert(size != 0);

    int status = munmap(memoryMapPtr, size);

    if (-1 == status)
    {
        fprintf(stderr, "Error during munmap: %s\n", strerror(errno));
        return;
    }    

    printf("Freed the memory map of size %zu located at %p\n", size, memoryMapPtr);
}


int main (int argc, char * argv[])
{
    bool done = false;
    printf("Starting TestApplication\n");

    do
    {
        printf("\nHit a key to mmap then munmap (Q to quit)\n");
        int selection = getchar();
        getchar(); // Clear the newline

        switch (selection)
        {
            case 'q':
            case 'Q':
                done = true;
                break;

            default:
                {
                    int mapSize = 100;
                    void * memoryMapPtr = getNewMap(mapSize);
                    freeMap(memoryMapPtr, mapSize);
                }
                break;
        }

    } while (!done);
    
    printf("Exiting...\n");
    return 0;
}
