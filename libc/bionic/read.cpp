/*
 * Copyright (C) 2026
 *
 * Custom read wrapper for bionic.
 */

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>

#include "private/bionic_defs.h"

extern "C" ssize_t __read(int fd, void* buf, size_t count);


static const char* FAKE_MOUNTS = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n";
static const char* FAKE_CONTEXT = "u:r:untrusted_app:s0\n";

#define MAX_FDS 2048
typedef struct {
    int type; // 1: mounts, 2: enforce, 3: context
    size_t index; 
} HookState;

static HookState g_states[MAX_FDS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;

extern "C" void __register_selinux_fd(int fd, int type) {
    if (fd >= 0 && fd < MAX_FDS) {
        pthread_mutex_lock(&g_lock);
        g_states[fd].type = type;
        g_states[fd].index = 0;
        pthread_mutex_unlock(&g_lock);
    }
}

extern "C" void __unregister_selinux_fd(int fd) {
    if (fd >= 0 && fd < MAX_FDS) {
        pthread_mutex_lock(&g_lock);
        g_states[fd].type = 0;
        g_states[fd].index = 0;
        pthread_mutex_unlock(&g_lock);
    }
}

static inline const char* get_fake_data_for_type(int type) {
  switch (type) {
    case 1: return FAKE_MOUNTS;
    case 2: return FAKE_CONTEXT;
    default: return nullptr;
  }
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE
ssize_t read(int fd, void* buf, size_t count) {
    if (count == 0) {
    return __read(fd, buf, count);
  }

  if (fd >= 0 && fd < MAX_FDS) {
    pthread_mutex_lock(&g_lock);

    int type = g_states[fd].type;
    size_t index = g_states[fd].index;

    if (type > 0) {
      const char* fake = get_fake_data_for_type(type);
      if (fake != nullptr) {
        size_t total_len = strlen(fake);

        if (index < total_len) {
          size_t remaining = total_len - index;
          size_t n = (count < remaining) ? count : remaining;
          memcpy(buf, fake + index, n);
          g_states[fd].index += n;
          pthread_mutex_unlock(&g_lock);
          return static_cast<ssize_t>(n);
        }

        pthread_mutex_unlock(&g_lock);
        if (strlen(fake) == strlen(FAKE_MOUNTS)){
            return __read(fd, buf, count);
        }else {
            return 0;
        }
      }
    }

    pthread_mutex_unlock(&g_lock);
  }

  return __read(fd, buf, count);
}
