#pragma once
#include <stdlib.h>

void *libssh_malloc(size_t size);
void *libssh_realloc(void* ptr, size_t size);
void *libssh_calloc(size_t count, size_t size);
void libssh_free(void* ptr);
char *libssh_strdup(const char *s);
char *libssh_strndup(const char *s, size_t n);
