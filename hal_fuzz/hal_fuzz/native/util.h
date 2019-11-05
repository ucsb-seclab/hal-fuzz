#ifndef NATIVE_UTIL_H
#define NATIVE_UTIL_H

#include <unistd.h>

#define min(a, b) (a < b ? a : b)

void *memmem(const char *haystack, size_t haystacklen, const char *needle, size_t needlelen);

#endif