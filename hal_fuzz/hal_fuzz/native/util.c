#include <inttypes.h>
#include <unistd.h>
#include <string.h>

void *memmem(const char *haystack, size_t haystacklen,
                    const char *needle, size_t needlelen) {
    if(!needle || haystacklen < needlelen) {
        return NULL;
    }

    const char *prev_haystack = haystack;

    while((haystack = memchr(prev_haystack, needle[0], haystacklen))) {        
        haystacklen -= (haystack - prev_haystack);
        if(needlelen > haystacklen) {
            break;
        }

        if(!memcmp(haystack, needle, needlelen)) {
            // found
            return (void *) haystack;
        }
        
        prev_haystack = haystack+1;
        --haystacklen;
    }

    return NULL;
}