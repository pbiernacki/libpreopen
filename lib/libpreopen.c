/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2023 Mysterious Code Ltd.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * Copyright (c) 2016-2017 Stanley Uche Godfrey
 * Copyright (c) 2016-2018 Jonathan Anderson
 * All rights reserved.
 *
 * This software was developed at Memorial University under the
 * NSERC Discovery program (RGPIN-2015-06048).
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/**
 * @file  libpreopen.c
 * Implementation of high-level libpreopen functions.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/limits.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <sys/wait.h>

#include <assert.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "libpreopen.h"

struct po_map_entry {
    const char  *name;
    int          fd;
    cap_rights_t rights;
};

struct po_map {
    int                  refcount;
    struct po_map_entry *entries;
    size_t               capacity;
    size_t               length;
};

struct po_packed_entry {
    int    fd;
    size_t offset;
    size_t len;
};

struct po_packed_map {
    size_t                 count;
    size_t                 tablelen;
    struct po_packed_entry entries[];
};

static bool po_isprefix(const char *dir, size_t dirlen, const char *path);
static void po_errormessage(const char *msg);
#ifdef NDEBUG
#define po_map_assertvalid(...)
#else
static void po_map_assertvalid(const struct po_map *map);
#endif
static struct po_map    *po_map_enlarge(struct po_map *map);
static struct po_relpath find_relative(const char *path, cap_rights_t *rights);
static struct po_map    *get_shared_map(void);

static char           error_buffer[1024];
static struct po_map *global_map;

// Native, not wrapped, functions
static struct {
    int (*po_connectat)(int, int, const struct sockaddr *, socklen_t);
    int (*po_faccessat)(int, const char *, int, int);
    int (*po_fstatat)(int, const char *, struct stat *, int);
    int (*po_funlinkat)(int, const char *, int, int);
    int (*po_openat)(int, const char *, int, int);
    int (*po_renameat)(int, const char *, int, const char *);
} po_nf;

// API
struct po_map *
po_map_create(size_t capacity)
{
    struct po_map *map;

    map = malloc(sizeof(struct po_map));
    if (map == NULL) {
        return (NULL);
    }

    map->entries = calloc(sizeof(struct po_map_entry), capacity);
    if (map->entries == NULL) {
        free(map);
        return (NULL);
    }

    map->refcount = 1;
    map->capacity = capacity;
    map->length = 0;

    po_map_assertvalid(map);

    return (map);
}

void
po_map_release(struct po_map *map)
{
    if (map == NULL) {
        return;
    }

    po_map_assertvalid(map);

    map->refcount -= 1;

    if (map->refcount == 0) {
        free(map->entries);
        free(map);
    }
}

size_t
po_map_foreach(const struct po_map *map, po_map_iter_cb cb)
{
    struct po_map_entry *entry;
    size_t               n;

    po_map_assertvalid(map);

    for (n = 0; n < map->length; n++) {
        entry = map->entries + n;

        if (!cb(entry->name, entry->fd, entry->rights)) {
            break;
        }
    }

    return (n);
}

struct po_map *
po_add(struct po_map *map, const char *path, int fd)
{
    struct po_map_entry *entry;

    po_map_assertvalid(map);

    if (path == NULL || fd < 0) {
        return (NULL);
    }

    if (map->length == map->capacity) {
        map = po_map_enlarge(map);
        if (map == NULL) {
            return (NULL);
        }
    }

    entry = map->entries + map->length;
    map->length++;

    entry->name = strdup(path);
    entry->fd = fd;

    if (cap_rights_get(fd, &entry->rights) != 0) {
        return (NULL);
    }

    po_map_assertvalid(map);

    return (map);
}

struct po_map *
po_map_enlarge(struct po_map *map)
{
    struct po_map_entry *enlarged;
    enlarged = calloc(sizeof(struct po_map_entry), 2 * map->capacity);
    if (enlarged == NULL) {
        return (NULL);
    }
    memcpy(enlarged, map->entries, map->length * sizeof(*enlarged));
    free(map->entries);
    map->entries = enlarged;
    map->capacity = 2 * map->capacity;
    return map;
}

int
po_preopen(struct po_map *map, const char *path, int flags, ...)
{
    va_list args;
    int     fd, mode;

    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);

    po_map_assertvalid(map);

    if (path == NULL) {
        return (-1);
    }

    fd = po_nf.po_openat(AT_FDCWD, path, flags, mode);
    if (fd == -1) {
        return (-1);
    }

    if (po_add(map, path, fd) == NULL) {
        return (-1);
    }

    po_map_assertvalid(map);

    return (fd);
}

struct po_relpath
po_find(struct po_map *map, const char *path, cap_rights_t *rights)
{
    const char       *relpath;
    struct po_relpath match = {.relative_path = NULL, .dirfd = -1};
    size_t            bestlen = 0;
    int               best = -1;

    po_map_assertvalid(map);

    if (path == NULL) {
        return (match);
    }

    for (size_t i = 0; i < map->length; i++) {
        const struct po_map_entry *entry = map->entries + i;
        const char                *name = entry->name;
        size_t                     len = strnlen(name, MAXPATHLEN);

        if ((len <= bestlen) || !po_isprefix(name, len, path)) {
            continue;
        }

        if (rights && !cap_rights_contains(&entry->rights, rights)) {
            continue;
        }

        best = entry->fd;
        bestlen = len;
    }

    relpath = path + bestlen;

    while (*relpath == '/') {
        relpath++;
    }

    if (*relpath == '\0') {
        relpath = ".";
    }

    match.relative_path = relpath;
    match.dirfd = best;

    return match;
}

const char *
po_last_error(void)
{
    return (error_buffer);
}

int
po_pack(struct po_map *map)
{
    struct po_packed_entry *entry;
    struct po_packed_map   *packed;
    char                   *strtab;
    size_t chars; // total characters to be copied into string table
    size_t i, offset, size;
    int    fd;

    po_map_assertvalid(map);

    fd = shm_open(SHM_ANON, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        po_errormessage("failed to shm_open SHM for packed map");
        return (-1);
    }

    chars = 0;
    for (i = 0; i < map->length; i++) {
        chars += strlen(map->entries[i].name) + 1;
    }

    size = sizeof(struct po_packed_map) +
            map->length * sizeof(struct po_packed_entry) + chars;
    if (__predict_false(size > OFF_MAX)) {
        return (-1);
    }

    if (ftruncate(fd, (off_t)size) != 0) {
        po_errormessage("failed to truncate shared memory segment");
        close(fd);
        return (-1);
    }

    packed = mmap(0, size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (packed == MAP_FAILED) {
        po_errormessage("shm_open");
        close(fd);
        return (-1);
    }

    packed->count = map->length;
    packed->tablelen = chars;
    strtab = ((char *)packed) + size - chars;
    offset = 0;

    for (i = 0; i < map->length; i++) {
        entry = packed->entries + i;

        entry->fd = map->entries[i].fd;
        entry->offset = offset;
        entry->len = strlen(map->entries[i].name);
        strlcpy(strtab + offset, map->entries[i].name, chars - offset);

        offset += entry->len;
    }

    return fd;
}

struct po_map *
po_unpack(int fd)
{
    struct stat           sb;
    struct po_map_entry  *entry;
    struct po_map        *map;
    struct po_packed_map *packed;
    char                 *strtab;
    size_t                i;

    if (fstat(fd, &sb) < 0) {
        po_errormessage("failed to fstat() shared memory segment");
        return (NULL);
    }

    packed = mmap(0, (size_t)sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd,
            0);
    if (packed == MAP_FAILED) {
        po_errormessage("mmap");
        return (NULL);
    }

    strtab = ((char *)packed->entries) +
            packed->count * sizeof(struct po_packed_entry);
    assert(strtab - ((char *)packed) <= sb.st_size);

    map = malloc(sizeof(struct po_map));
    if (map == NULL) {
        munmap(packed, (size_t)sb.st_size);
        return (NULL);
    }

    map->entries = calloc(packed->count, sizeof(struct po_map_entry));
    if (map->entries == NULL) {
        munmap(packed, (size_t)sb.st_size);
        free(map);
        return (NULL);
    }

    map->refcount = 1;
    map->capacity = packed->count;
    map->length = packed->count;
    for (i = 0; i < map->length; i++) {
        entry = map->entries + i;

        entry->fd = packed->entries[i].fd;
        entry->name = strndup(strtab + packed->entries[i].offset,
                packed->entries[i].len);
    }

    po_map_assertvalid(map);

    return map;
}

bool
po_print_entry(const char *name, int fd, cap_rights_t rights __unused)
{
    printf(" - name: '%s', fd: %d, rights: <rights>\n", name, fd);
    return (true);
}

// PRIVATE

static bool
po_isprefix(const char *dir, size_t dirlen, const char *path)
{
    size_t i;
    assert(dir != NULL);
    assert(path != NULL);
    for (i = 0; i < dirlen; i++) {
        if (path[i] != dir[i])
            return false;
    }
    return path[i] == '/' || path[i] == '\0';
}

#if !defined(NDEBUG)
static void
po_map_assertvalid(const struct po_map *map)
{
    const struct po_map_entry *entry;
    size_t                     i;

    assert(map->refcount > 0);
    assert(map->length <= map->capacity);
    assert(map->entries != NULL || map->capacity == 0);

    for (i = 0; i < map->length; i++) {
        entry = map->entries + i;

        assert(entry->name != NULL);
        assert(entry->fd >= 0);
    }
}
#endif /* !defined(NDEBUG) */

static void
po_errormessage(const char *msg)
{
    snprintf(error_buffer, sizeof(error_buffer), "%s: error %d", msg, errno);
}

static struct po_relpath
find_relative(const char *path, cap_rights_t *rights __unused)
{
    struct po_relpath rel;
    struct po_map    *map;

    map = get_shared_map();
    if (map == NULL) {
        rel.dirfd = AT_FDCWD;
        rel.relative_path = path;
    } else {
        rel = po_find(map, path, NULL);
    }

    return (rel);
}

static struct po_map *
get_shared_map(void)
{
    struct po_map *map;
    char          *end, *env;
    long           fd;

    // Do we already have a default map?
    if (global_map) {
        po_map_assertvalid(global_map);
        return (global_map);
    }

    // Attempt to unwrap po_map from a shared memory segment specified by
    // SHAREDMEM_FD
    env = getenv(SHAREDMEM_FD);
    if (env == NULL || *env == '\0') {
        return (NULL);
    }

    // We expect this environment variable to be an integer and nothing but
    // an integer.
    fd = strtol(env, &end, 10);
    if (*end != '\0') {
        return (NULL);
    }
    // In the unlike event that file descriptor we got passed on seems
    // suspiciously too large...
    if (__predict_false(fd > INT_MAX)) {
        return (NULL);
    }

    map = po_unpack((int)fd);
    if (map == NULL) {
        return (NULL);
    }

    global_map = map;

    return (map);
}

// Wrappers around system calls:
/**
 * Capability-safe wrapper around the `openat(2)` family of functions.
 */

int
openat(int fd, const char *path, int flags, ...)
{
    struct po_relpath rel;
    va_list           args;
    int               mode;

    va_start(args, flags);
    mode = va_arg(args, int);
    va_end(args);

    if (fd == AT_FDCWD) {
        rel = find_relative(path, NULL);
        if (strcmp(rel.relative_path, ".") == 0) {
            return (dup(rel.dirfd));
        }
        return (po_nf.po_openat(rel.dirfd, rel.relative_path, flags, mode));
    }
    return (po_nf.po_openat(fd, path, flags, mode));
}

/*
 * Non-interposed-in-libc version of open(2).  The export here is needed
 * because it's not exported in any header but used by some external software.
 */
extern int _open(const char *path, int flags, ...);

int
_open(const char *path, int flags, ...)
{
    va_list args;
    int     mode;

    mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    return (openat(AT_FDCWD, path, flags, mode));
}

int
open(const char *path, int flags, ...)
{
    va_list args;
    int     mode;

    mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_start(args, flags);
        mode = va_arg(args, int);
        va_end(args);
    }
    return (openat(AT_FDCWD, path, flags, mode));
}

/**
 * Capability-safe wrapper around the `faccessat(2)` family of functions.
 */

int
faccessat(int fd, const char *path, int mode, int flag)
{
    struct po_relpath rel;

    if (fd == AT_FDCWD) {
        rel = find_relative(path, NULL);
        return (po_nf.po_faccessat(rel.dirfd, rel.relative_path, mode, flag));
    }
    return (po_nf.po_faccessat(fd, path, mode, flag));
}

int
access(const char *path, int mode)
{
    return (faccessat(AT_FDCWD, path, mode, 0));
}

int
eaccess(const char *path, int mode)
{
    return (faccessat(AT_FDCWD, path, mode, AT_EACCESS));
}

/**
 * Capability-safe wrapper around the `connectat(2)` system call.
 */
int
connectat(int fd, int s, const struct sockaddr *name, socklen_t namelen)
{
    struct po_relpath rel;

    if (name->sa_family == AF_UNIX && fd == AT_FDCWD) {
        struct sockaddr_un *usock = __DECONST(struct sockaddr_un *, name);
        rel = find_relative(usock->sun_path, NULL);
        strlcpy(usock->sun_path, rel.relative_path, sizeof(usock->sun_path));
        return (po_nf.po_connectat(rel.dirfd, s, name, namelen));
    }
    return (po_nf.po_connectat(fd, s, name, namelen));
}

int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
    if (name->sa_family == AF_UNIX) {
        return connectat(AT_FDCWD, s, name, namelen);
    }
    return connectat(AT_FDCWD, s, name, namelen);
}

/**
 * Capability-safe wrapper around the `fstatat(2)` family of functions.
 */

int
fstatat(int fd, const char *path, struct stat *sb, int flag)
{
    struct po_relpath rel;

    if (fd == AT_FDCWD) {
        rel = find_relative(path, NULL);
        return (po_nf.po_fstatat(rel.dirfd, rel.relative_path, sb, flag));
    }
    return (po_nf.po_fstatat(fd, path, sb, flag));
}

int
lstat(const char *path, struct stat *st)
{
    struct po_relpath rel = find_relative(path, NULL);

    return fstatat(rel.dirfd, rel.relative_path, st, AT_SYMLINK_NOFOLLOW);
}

int
stat(const char *path, struct stat *st)
{
    struct po_relpath rel = find_relative(path, NULL);

    return fstatat(rel.dirfd, rel.relative_path, st, AT_SYMLINK_NOFOLLOW);
}

/**
 * Capability-safe wrapper around the `renameat(2)` system call.
 */

int
renameat(int fromfd, const char *from, int tofd, const char *to)
{
    struct po_relpath rel_from, rel_to;

    if (fromfd == AT_FDCWD) {
        rel_from = find_relative(from, NULL);
        fromfd = rel_from.dirfd;
        from = rel_from.relative_path;
    }
    if (tofd == AT_FDCWD) {
        rel_to = find_relative(to, NULL);
        tofd = rel_to.dirfd;
        to = rel_to.relative_path;
    }
    return (po_nf.po_renameat(fromfd, from, tofd, to));
}

int
rename(const char *from, const char *to)
{
    return renameat(AT_FDCWD, from, AT_FDCWD, to);
}

/**
 * Capability-safe wrapper around the `funlinkat(2)` system call.
 */

int
funlinkat(int dfd, const char *path, int fd, int flag)
{
    struct po_relpath rel;

    if (dfd == AT_FDCWD) {
        rel = find_relative(path, NULL);
        return (po_nf.po_funlinkat(rel.dirfd, rel.relative_path, fd, 0));
    }
    return (po_nf.po_funlinkat(dfd, path, fd, flag));
}

int
unlinkat(int dfd, const char *path, int flag)
{
    return (funlinkat(dfd, path, FD_NONE, flag));
}

int
unlink(const char *path)
{
    struct po_relpath rel = find_relative(path, NULL);

    return (funlinkat(rel.dirfd, rel.relative_path, FD_NONE, 0));
}

/**
 * Capability-safe wrapper around the `dlopen(3)` libc function.
 *
 * `dlopen(3)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `fdlopen(3)` if
 * possible. If the current po_map does not contain the sought-after path, this
 * wrapper will call `fdlopen(openat(AT_FDCWD, original_path), ...)`, which is
 * the same as the unwrapped `dlopen(3)` call (i.e., will fail with `ECAPMODE`).
 */
void *
dlopen(const char *path, int mode)
{
    struct po_relpath rel = find_relative(path, NULL);

    return fdlopen(po_nf.po_openat(rel.dirfd, rel.relative_path, 0, mode),
            mode);
}

/* Provide tests with mechanism to set our static po_map */
void
po_set_libc_map(struct po_map *map)
{
    po_map_assertvalid(map);

    map->refcount += 1;

    if (global_map != NULL) {
        po_map_release(global_map);
    }

    global_map = map;
}

// Constructor that is run when libpreopen is initialised by the rtld.
#define PO_DLSYM(name) po_nf.po_##name = dlsym(RTLD_NEXT, #name)

__attribute__((constructor)) static void
po_init(void)
{
    PO_DLSYM(connectat);
    PO_DLSYM(faccessat);
    PO_DLSYM(fstatat);
    PO_DLSYM(funlinkat);
    PO_DLSYM(openat);
    PO_DLSYM(renameat);
}
