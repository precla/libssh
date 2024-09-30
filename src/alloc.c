#include "libssh/libssh.h"
#include "libssh/alloc.h"
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
  libssh_malloc_func malloc;
  libssh_realloc_func realloc;
  libssh_calloc_func calloc;
  libssh_free_func free;
  libssh_strdup_func strdup;
  libssh_strndup_func strndup;
} libssh__allocator_t;

static libssh__allocator_t libssh__allocator = {
  malloc,
  realloc,
  calloc,
  free,
  strdup,
  strndup,
};

int libssh_replace_allocator(libssh_malloc_func malloc_func,
                            libssh_realloc_func realloc_func,
                            libssh_calloc_func calloc_func,
                            libssh_free_func free_func,
                            libssh_strdup_func strdup_func,
                            libssh_strndup_func strndup_func) {
  if (malloc_func == NULL || realloc_func == NULL ||
      calloc_func == NULL || free_func == NULL ||
      strdup_func == NULL || strndup_func == NULL) {
    return EINVAL;
  }

  libssh__allocator.malloc = malloc_func;
  libssh__allocator.realloc = realloc_func;
  libssh__allocator.calloc = calloc_func;
  libssh__allocator.free = free_func;
  libssh__allocator.strdup = strdup_func;
  libssh__allocator.strndup = strndup_func;

  return 0;
}

void* libssh_malloc(size_t size) {
    if (size > 0)
        return libssh__allocator.malloc(size);
    return NULL;
}

void* libssh_realloc(void* ptr, size_t size) {
  if (size > 0)
    return libssh__allocator.realloc(ptr, size);
  libssh_free(ptr);
  return NULL;
}


void* libssh_calloc(size_t count, size_t size) {
  return libssh__allocator.calloc(count, size);
}

void libssh_free(void* ptr) {
  int saved_errno;

  /* The system allocator the assumption that errno is not modified but custom
   * allocators may not be so careful.
   */
  saved_errno = errno;
  libssh__allocator.free(ptr);
  errno = saved_errno;
}

char *libssh_strdup(const char *s) {
  return libssh__allocator.strdup(s);
}

char *libssh_strndup(const char *s, size_t n) {
  return libssh__allocator.strndup(s, n);
}
