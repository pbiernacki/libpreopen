/*-
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
 *
 * The functions defined in this source file are the highest-level API calls
 * that client code will mostly use (plus po_map_create and po_map_release).
 * po_isprefix is also defined here because it doesn't fit anywhere else.
 */

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/types.h>
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

#ifdef WITH_CAPSICUM
#include <sys/capsicum.h>
#endif

/**
 * An entry in a po_map.
 *
 * @internal
 */
struct po_map_entry {
    /**
     * The name this file or directory is mapped to.
     *
     * This name should look like a path, but it does not necessarily need
     * match to match the path it was originally obtained from.
     */
    const char *name;

    /** File descriptor (which may be a directory) */
    int fd;

#ifdef WITH_CAPSICUM
    /** Capability rights associated with the file descriptor */
    cap_rights_t rights;
#endif
};

// Documented in external header file
struct po_map {
    //! @internal
    int                  refcount;
    struct po_map_entry *entries;
    size_t               capacity;
    size_t               length;
};

/**
 * Is a directory a prefix of a given path?
 *
 * @param   dir     a directory path, e.g., `/foo/bar`
 * @param   dirlen  the length of @b dir
 * @param   path    a path that may have @b dir as a prefix,
 *                  e.g., `/foo/bar/baz`
 *
 * @internal
 */
bool po_isprefix(const char *dir, size_t dirlen, const char *path);

/**
 * Check that a @ref po_map is valid (assert out if it's not).
 *
 * @internal
 */
#ifdef NDEBUG
#define po_map_assertvalid(...)
#else
void po_map_assertvalid(const struct po_map *);
#endif

/**
 * Enlarge a @ref po_map's capacity.
 *
 * This results in new memory being allocated and existing entries being copied.
 * If the allocation fails, the function will return NULL but the original
 * map will remain valid.
 *
 * @internal
 */
struct po_map *po_map_enlarge(struct po_map *map);

/**
 * Store an error message in the global "last error message" buffer.
 *
 * @internal
 */
void po_errormessage(const char *msg);

/**
 * Set the default map used by the libpreopen libc wrappers.
 *
 * If there is an existing default map, it will be freed before it is replaced.
 * Passing NULL to this function will thus clear the default map.
 */
void po_set_libc_map(struct po_map *);

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

#ifdef WITH_CAPSICUM
    if (cap_rights_get(fd, &entry->rights) != 0) {
        return (NULL);
    }
#endif

    po_map_assertvalid(map);

    return (map);
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

#ifdef WITH_CAPSICUM
        if (rights && !cap_rights_contains(&entry->rights, rights)) {
            continue;
        }
#endif

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

bool
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

int
po_preopen(struct po_map *map, const char *path, int flags, ...)
{
    va_list args;
    int     fd, mode;

    va_start(args, flags);
    mode = va_arg(args, int);

    po_map_assertvalid(map);

    if (path == NULL) {
        return (-1);
    }

    fd = openat(AT_FDCWD, path, flags, mode);
    if (fd == -1) {
        return (-1);
    }

    if (po_add(map, path, fd) == NULL) {
        return (-1);
    }

    po_map_assertvalid(map);

    return (fd);
}

bool
po_print_entry(const char *name, int fd, cap_rights_t rights)
{
    printf(" - name: '%s', fd: %d, rights: <rights>\n", name, fd);
    return (true);
}

static char error_buffer[1024];

#if !defined(NDEBUG)
void
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

void
po_errormessage(const char *msg)
{
    snprintf(error_buffer, sizeof(error_buffer), "%s: error %d", msg, errno);
}

const char *
po_last_error()
{
    return (error_buffer);
}

/**
 * A default po_map that can be used implicitly by libc wrappers.
 *
 * @internal
 */
static struct po_map *global_map;

/**
 * Find a relative path within the po_map given by SHARED_MEMORYFD (if it
 * exists).
 *
 * @returns  a struct po_relpath with dirfd and relative_path as set by po_find
 *           if there is an available po_map, or AT_FDCWD/path otherwise
 */
static struct po_relpath find_relative(const char *path, cap_rights_t *);

/**
 * Get the map that was handed into the process via `SHARED_MEMORYFD`
 * (if it exists).
 */
static struct po_map *get_shared_map(void);

/*
 * Wrappers around system calls:
 */

/**
 * Capability-safe wrapper around the `_open(2)` system call.
 *
 * `_open(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `openat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `openat(AT_FDCWD, original_path, ...)`, which is
 * the same as the unwrapped `open(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
_open(const char *path, int flags, ...)
{
    struct po_relpath rel;
    va_list           args;
    int               mode;

    va_start(args, flags);
    mode = va_arg(args, int);
    rel = find_relative(path, NULL);

    // If the file is already opened, no need of relative opening!
    if (strcmp(rel.relative_path, ".") == 0)
        return dup(rel.dirfd);
    else
        return openat(rel.dirfd, rel.relative_path, flags, mode);
}

/**
 * Capability-safe wrapper around the `access(2)` system call.
 *
 * `access(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `faccessat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `faccessat(AT_FDCWD, original_path, ...)`, which is
 * the same as the unwrapped `access(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
access(const char *path, int mode)
{
    struct po_relpath rel = find_relative(path, NULL);

    return faccessat(rel.dirfd, rel.relative_path, mode, 0);
}

/**
 * Capability-safe wrapper around the `connect(2)` system call.
 *
 * `connect(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `connectat(2)` if
 * possible. If the current po_map does not contain the sought-after path, this
 * wrapper will call `connectat(AT_FDCWD, original_path, ...)`, which is the
 * same as the unwrapped `connect(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
connect(int s, const struct sockaddr *name, socklen_t namelen)
{
    struct po_relpath rel;

    if (name->sa_family == AF_UNIX) {
        struct sockaddr_un *usock = (struct sockaddr_un *)name;
        rel = find_relative(usock->sun_path, NULL);
        strlcpy(usock->sun_path, rel.relative_path, sizeof(usock->sun_path));
        return connectat(rel.dirfd, s, name, namelen);
    }

    return connectat(AT_FDCWD, s, name, namelen);
}

/**
 * Capability-safe wrapper around the `eaccess(2)` system call.
 *
 * `eaccess(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `faccessat(2)` if
 * possible. If the current po_map does not contain the sought-after path, this
 * wrapper will call `faccessat(AT_FDCWD, original_path, ...)`, which is the
 * same as the unwrapped `eaccess(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
eaccess(const char *path, int mode)
{
    struct po_relpath rel = find_relative(path, NULL);

    return faccessat(rel.dirfd, rel.relative_path, mode, 0);
}

/**
 * Capability-safe wrapper around the `lstat(2)` system call.
 *
 * `lstat(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `fstatat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `fstatat(AT_FDCWD, original_path, ...)`, which is
 * the same as the unwrapped `lstat(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
lstat(const char *path, struct stat *st)
{
    struct po_relpath rel = find_relative(path, NULL);

    return fstatat(rel.dirfd, rel.relative_path, st, AT_SYMLINK_NOFOLLOW);
}

/**
 * Capability-safe wrapper around the `open(2)` system call.
 *
 * `open(2)` will behave just like `_open(2)` if the varargs are unpacked and
 *  passed.
 */
int
open(const char *path, int flags, ...)
{
    va_list args;
    int     mode;

    va_start(args, flags);
    mode = va_arg(args, int);
    return _open(path, flags, mode);
}

/**
 * Capability-safe wrapper around the `rename(2)` system call.
 *
 * `rename(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `renameat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `renameat(AT_FDCWD, original_path, ...)`, which is
 * the same as the unwrapped `rename(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
rename(const char *from, const char *to)
{
    struct po_relpath rel_from = find_relative(from, NULL);
    struct po_relpath rel_to = find_relative(to, NULL);

    return renameat(rel_from.dirfd, rel_from.relative_path, rel_to.dirfd,
            rel_to.relative_path);
}

/**
 * Capability-safe wrapper around the `stat(2)` system call.
 *
 * `stat(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `fstatat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `fstatat(AT_FDCWD, original_path, ...)`, which is
 * the same as the unwrapped `stat(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
stat(const char *path, struct stat *st)
{
    struct po_relpath rel = find_relative(path, NULL);

    return fstatat(rel.dirfd, rel.relative_path, st, AT_SYMLINK_NOFOLLOW);
}

/**
 * Capability-safe wrapper around the `unlink(2)` system call.
 *
 * `unlink(2)` accepts a path argument that can reference the global filesystem
 * namespace. This is not a capability-safe operation, so this wrapper function
 * attempts to look up the path (or a prefix of it) within the current global
 * po_map and converts the call into the capability-safe `unlinkat(2)` if
 * possible. If the current po_map does not contain the sought-after path,
 * this wrapper will call `unlinkat(AT_FDCWD, original_path, 0) which is
 * the same as the unwrapped `unlink(2)` call (i.e., will fail with `ECAPMODE`).
 */
int
unlink(const char *path)
{
    struct po_relpath rel = find_relative(path, NULL);

    return unlinkat(rel.dirfd, rel.relative_path, 0);
}

/*
 * Wrappers around other libc calls:
 */

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

    return fdlopen(openat(rel.dirfd, rel.relative_path, 0, mode), mode);
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

static struct po_relpath
find_relative(const char *path, cap_rights_t *rights)
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
get_shared_map()
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
    // SHARED_MEMORYFD
    env = getenv("SHARED_MEMORYFD");
    if (env == NULL || *env == '\0') {
        return (NULL);
    }

    // We expect this environment variable to be an integer and nothing but
    // an integer.
    fd = strtol(env, &end, 10);
    if (*end != '\0') {
        return (NULL);
    }

    map = po_unpack(fd);
    if (map == NULL) {
        return (NULL);
    }

    global_map = map;

    return (map);
}

struct po_map *
po_map_create(int capacity)
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

/**
 * An entry in a po_packed_map.
 *
 * @internal
 */
struct po_packed_entry {
    /** Integer file descriptor */
    int fd;

    /** Offset of the entry's name within the po_packed_map's string table */
    int offset;

    /** Length of the entry's name (not including any null terminator) */
    int len;
};

/**
 * Packed-in-a-buffer representation of a po_map.
 *
 * An object of this type will be immediately followed in memory by a string
 * table of length `tablelen`.
 *
 * @internal
 */
struct po_packed_map {
    /** The number of po_packed_entry values in the packed map */
    int count;

    /**
     * Length of the name string table that follows this po_packed_map in the
     * shared memory segment.
     */
    int tablelen;

    /** The actual packed entries */
    struct po_packed_entry entries[0];
};

int
po_pack(struct po_map *map)
{
    struct po_packed_entry *entry;
    struct po_packed_map   *packed;
    char                   *strtab;
    size_t chars; /* total characters to be copied into string table */
    size_t size;
    int    fd, i, offset;

    po_map_assertvalid(map);

    fd = shm_open(SHM_ANON, O_CREAT | O_RDWR, 0600);
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

    if (ftruncate(fd, size) != 0) {
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
    int                   i;

    if (fstat(fd, &sb) < 0) {
        po_errormessage("failed to fstat() shared memory segment");
        return (NULL);
    }

    packed = mmap(0, sb.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
    if (packed == MAP_FAILED) {
        po_errormessage("mmap");
        return (NULL);
    }

    strtab = ((char *)packed->entries) +
            packed->count * sizeof(struct po_packed_entry);
    assert(strtab - ((char *)packed) <= sb.st_size);

    map = malloc(sizeof(struct po_map));
    if (map == NULL) {
        munmap(packed, sb.st_size);
        return (NULL);
    }

    map->entries = calloc(packed->count, sizeof(struct po_map_entry));
    if (map->entries == NULL) {
        munmap(packed, sb.st_size);
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
