#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <unistd.h>
#include <stdarg.h>
#include <pthread.h>
#include <libgen.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <linux/limits.h>

extern int errno;

#define PPCAT_NX(A, B) A ## B
#define RND_FUNC(A, B) PPCAT_NX(A, B)
#define RND_VAR(A, B) PPCAT_NX(A, B)

#ifndef CLEAR_WHEN_CREATE
#define CLEAR_WHEN_CREATE 0
#endif

#ifndef DO_CLEAR_CACHE
#define DO_CLEAR_CACHE 0
#endif

#ifndef CONFOUNDING_FACTOR
#define CONFOUNDING_FACTOR bsfrlcnhgrv0dxe6m7le
#endif

#ifndef DIRECTORY_CACHE_SIZE
#define DIRECTORY_CACHE_SIZE 1024
#endif

#ifndef MAX_CACHE_ENTRIES_PER_DIRECTORY
#define MAX_CACHE_ENTRIES_PER_DIRECTORY 1024
#endif

pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static struct {
		char *dir_name;
		char *entries[MAX_CACHE_ENTRIES_PER_DIRECTORY];
		int deleted;
} RND_VAR(cache, CONFOUNDING_FACTOR)[DIRECTORY_CACHE_SIZE];
static int RND_VAR(last_written_index, CONFOUNDING_FACTOR) = 0;

inline int RND_FUNC(str_containers, CONFOUNDING_FACTOR) (const char *parent, const char *sub)
{
		if (strstr(parent, sub) != NULL)
				return 1;
		return 0;
}

inline int RND_FUNC(str_starts_with, CONFOUNDING_FACTOR) (const char *parent, const char *sub) {
		if (strncmp(parent, sub, strlen(sub)) == 0)
				return 1;
		return 0;
}

char *RND_FUNC(get_path_from_fd, CONFOUNDING_FACTOR) (int fd) {
		char proc_path[PATH_MAX + 1];
		char file_path[PATH_MAX + 1];
		snprintf(proc_path, PATH_MAX, "/proc/self/fd/%d", fd);
		if (readlink(proc_path, file_path, (size_t) PATH_MAX) < 0) {
				return NULL;
		}
		return strdup(file_path);
}

int RND_FUNC(is_relative_path, CONFOUNDING_FACTOR) (const char *file_path) {
		if ((!RND_FUNC(str_starts_with, CONFOUNDING_FACTOR) (file_path, "/"))
			|| RND_FUNC(str_containers, CONFOUNDING_FACTOR) (file_path, "./")) {
				return 1;
		}
		return 0;
}

char *RND_FUNC(path_join, CONFOUNDING_FACTOR) (const char *parent, const char *sub) {
		const size_t parent_len = strlen(parent);
		const size_t sub_len = strlen(sub);
		char *result = malloc(parent_len + sub_len + 2);
		memcpy(result, parent, parent_len);
		result[parent_len] = '/';
		memcpy(result + parent_len + 1, sub, sub_len + 1);
		return result;
}

char *RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (int dirfd, const char *file_path) {
		char *abs_path = NULL;
		if (RND_FUNC(is_relative_path, CONFOUNDING_FACTOR) (file_path) == 1) {
				if (dirfd == AT_FDCWD) {
						abs_path = realpath(file_path, NULL);
				} else {
						char *ref_path = RND_FUNC(get_path_from_fd, CONFOUNDING_FACTOR) (dirfd);
						if (ref_path != NULL) {
								char *rel_path = RND_FUNC(path_join, CONFOUNDING_FACTOR) (ref_path, file_path);
								free(ref_path);
								ref_path = NULL;
								abs_path = realpath(rel_path, NULL);
								free(rel_path);
								rel_path = NULL;
						}
				}
		} else {
				abs_path = strdup(file_path);
		}
		return abs_path;
}

void RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (const char *file_path) {
	 if (DO_CLEAR_CACHE) {
		char *base_dirs = strdup(getenv("LD_CASE_SENSITIVE_AUTOFIX_BASES"));
		char *file_abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (AT_FDCWD, file_path);
		if (file_abs_path != NULL && base_dirs != NULL && base_dirs[0] != '\0') {
				char *base_dir = strtok(base_dirs, ":");
				while (base_dir != NULL) {
						if (RND_FUNC(str_starts_with, CONFOUNDING_FACTOR) (file_abs_path, base_dir))
								break;
						base_dir = strtok(NULL, ":");
				}
				if (base_dir != NULL) {
						char *file_abs_path_copy = strdup(file_abs_path);
						char *dir_name = dirname(file_abs_path_copy);
						pthread_mutex_lock(&mutex);
						int try_index = RND_VAR(last_written_index, CONFOUNDING_FACTOR);
						for (int tries = 0; RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name != NULL && RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].deleted != 1 && tries < MAX_CACHE_ENTRIES_PER_DIRECTORY; tries++) {
								if (strcmp(file_abs_path, RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name) == 0 || strcmp(dir_name, RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name) == 0) {
										RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].deleted = 1;
										break;
								}
								try_index = (try_index - 1 + DIRECTORY_CACHE_SIZE) % DIRECTORY_CACHE_SIZE;
						}
						pthread_mutex_unlock(&mutex);
						free(file_abs_path_copy);
				}
				free(base_dirs);
				base_dirs = NULL;
		}
		free(file_abs_path);
	}

}

int RND_FUNC(_has_conflict_case_exist, CONFOUNDING_FACTOR) (const char *file_path) {
		int result = 0;
		int resolved = 0;
		char *file_path_copy1 = strdup(file_path);
		char *file_path_copy2 = strdup(file_path);
		char *dir_name = dirname(file_path_copy1);
		char *base_name = basename(file_path_copy2);

		pthread_mutex_lock(&mutex);

		int try_index = RND_VAR(last_written_index, CONFOUNDING_FACTOR);
		for (int tries = 0; RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name != NULL && tries < MAX_CACHE_ENTRIES_PER_DIRECTORY && resolved == 0; tries++) {
				if (RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].deleted != 1 && strcmp(RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name, dir_name) == 0) {
						for (int i = 0; RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i] != NULL; i++) {
								const char *entry = RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i];
								if (strcasecmp(entry, base_name) == 0) {
										if (strcmp(entry, base_name) != 0)
												result = 1;
										else
												result = 0;
										break;
								}
						}
						resolved = 1;
						break;
				}
				try_index = (try_index - 1 + DIRECTORY_CACHE_SIZE) % DIRECTORY_CACHE_SIZE;
		}

		if (resolved == 0) {
				RND_VAR(last_written_index, CONFOUNDING_FACTOR) = try_index = (RND_VAR(last_written_index, CONFOUNDING_FACTOR) + 1) % DIRECTORY_CACHE_SIZE;
				if (RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name != NULL) {
						char *tmp = RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name;
						RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name = NULL;
						free(tmp);
						tmp = NULL;
						for (int i = 0; RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i] != NULL; i++) {
								tmp = RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i];
								RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i] = NULL;
								free(tmp);
								tmp = NULL;
						}
				}

				DIR *dirp = opendir(dir_name);
				struct dirent *dp;
				if (dirp) {
						for (int i = 0; i < MAX_CACHE_ENTRIES_PER_DIRECTORY, (dp = readdir(dirp)) != NULL;) {
								if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0)
										continue;
								RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i++] = strdup(dp->d_name);
						}
						(void)closedir(dirp);
				}

				RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].dir_name = strdup(dir_name);
				for (int i = 0; RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i] != NULL; i++) {
						const char *entry = RND_VAR(cache, CONFOUNDING_FACTOR)[try_index].entries[i];
						if (strcasecmp(entry, base_name) == 0) {
								resolved = 1;
								if (strcmp(entry, base_name) != 0)
										result = 1;
								else
										result = 0;
								break;
						}
				}
		}
		pthread_mutex_unlock(&mutex);
		free(file_path_copy1);
		free(file_path_copy2);
		file_path_copy1 = NULL;
		file_path_copy2 = NULL;
		return result;
}

int RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (const char *file_path) {
		int result = 0;
		char *base_dirs = strdup(getenv("LD_CASE_SENSITIVE_AUTOFIX_BASES"));
		char *file_abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (AT_FDCWD, file_path);
		if (file_abs_path != NULL && base_dirs != NULL && base_dirs[0] != '\0') {
				char *base_dir = strtok(base_dirs, ":");
				while (base_dir != NULL) {
						if (RND_FUNC(str_starts_with, CONFOUNDING_FACTOR) (file_abs_path, base_dir))
								break;
						base_dir = strtok(NULL, ":");
				}
				if (base_dir != NULL) {
						char *segs = strdup(file_abs_path + strlen(base_dir) + 1);
						char *seg = strtok(segs, "/");
						char *check_path = strdup(base_dir);
						while (seg != NULL) {
								check_path = RND_FUNC(path_join, CONFOUNDING_FACTOR) (check_path, seg);
								if (RND_FUNC(_has_conflict_case_exist, CONFOUNDING_FACTOR) (check_path) == 1) {
										result = 1;
										break;
								} else {
								}
								seg = strtok(NULL, "/");
						}
						free(check_path);
						free(segs);
						check_path = NULL;
						segs = NULL;
				}
				free(base_dirs);
				base_dirs = NULL;
		}
		free(file_abs_path);
		file_abs_path = NULL;
		return result;
}

typedef int (*orig_open_f_type) (const char *pathname, int flags, ...);
static orig_open_f_type orig_open;

int open(const char *pathname, int flags, ...)
{
		if (flags & O_RDONLY != 0) {
				if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (pathname)) {
						errno = ENOENT;
						return -1;
				}
		} else if (CLEAR_WHEN_CREATE && flags & O_CREAT != 0) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (pathname);
		}

		if (orig_open == NULL) {
				orig_open = (orig_open_f_type) dlsym(RTLD_NEXT, "open");
		}
		va_list ap;
		va_start(ap, flags);
		if (flags & O_CREAT) {
				mode_t mode = va_arg(ap, mode_t);
				return orig_open(pathname, flags, mode);
		} else {
				return orig_open(pathname, flags, 0);
		}
}

typedef int (*orig_open64_f_type) (const char *pathname, int flags, ...);
static orig_open64_f_type orig_open64;

int open64(const char *pathname, int flags, ...)
{
		if (flags & O_RDONLY != 0) {
				if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (pathname)) {
						errno = ENOENT;
						return -1;
				}
		} else if (CLEAR_WHEN_CREATE && flags & O_CREAT != 0) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (pathname);
		}
		if (orig_open64 == NULL) {
				orig_open64 = (orig_open64_f_type) dlsym(RTLD_NEXT, "open64");
		}
		va_list ap;
		va_start(ap, flags);
		if (flags & O_CREAT) {
				mode_t mode = va_arg(ap, mode_t);
				return orig_open64(pathname, flags | O_LARGEFILE, mode);
		} else {
				return orig_open64(pathname, flags | O_LARGEFILE, 0);
		}
}

typedef FILE *(*orig_fopen64_f_type) (const char *filename, const char *type);
static orig_fopen64_f_type orig_fopen64;

FILE *fopen64(const char *filename, const char *type)
{

		if (RND_FUNC(str_containers, CONFOUNDING_FACTOR) (type, "r") && RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (filename)) {
				errno = ENOENT;
				return NULL;
		} else if (CLEAR_WHEN_CREATE && RND_FUNC(str_containers, CONFOUNDING_FACTOR) (type, "w")) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (filename);
		}
		if (orig_fopen64 == NULL) {
				orig_fopen64 = (orig_fopen64_f_type) dlsym(RTLD_NEXT, "fopen64");
		}
		return orig_fopen64(filename, type);
}

typedef int (*orig_stat64_f_type) (const char *path, struct stat64 * buf);
static orig_stat64_f_type orig_stat64;

int stat64(const char *path, struct stat64 *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_stat64 == NULL) {
				orig_stat64 = (orig_stat64_f_type) dlsym(RTLD_NEXT, "stat64");
		}
		return orig_stat64(path, buf);
}

typedef int (*orig_stat_f_type) (const char *path, struct stat * buf);
static orig_stat_f_type orig_stat;

int stat(const char *path, struct stat *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_stat == NULL) {
				orig_stat = (orig_stat_f_type) dlsym(RTLD_NEXT, "stat");
		}
		return orig_stat(path, buf);
}

typedef int (*orig_lstat64_f_type) (const char *path, struct stat64 * buf);
static orig_lstat64_f_type orig_lstat64;

int lstat64(const char *path, struct stat64 *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_lstat64 == NULL)
				orig_lstat64 = (orig_lstat64_f_type) dlsym(RTLD_NEXT, "lstat64");
		return orig_lstat64(path, buf);
}

typedef int (*orig_lstat_f_type) (const char *path, struct stat * buf);
static orig_lstat_f_type orig_lstat;

int lstat(const char *path, struct stat *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_lstat == NULL)
				orig_lstat = (orig_lstat_f_type) dlsym(RTLD_NEXT, "lstat");
		return orig_lstat(path, buf);
}

typedef FILE *(*orig_fopen_f_type) (const char *file, const char *mode);
static orig_fopen_f_type orig_fopen;

FILE *fopen(const char *file, const char *mode)
{
		if (RND_FUNC(str_containers, CONFOUNDING_FACTOR) (mode, "r") && RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (file)) {
				errno = ENOENT;
				return NULL;
		} else if (CLEAR_WHEN_CREATE && RND_FUNC(str_containers, CONFOUNDING_FACTOR) (mode, "w")) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (file);
		}
		if (orig_fopen == NULL)
				orig_fopen = (orig_fopen_f_type) dlsym(RTLD_NEXT, "fopen");
		return orig_fopen(file, mode);
}

typedef ssize_t(*orig_readlink_f_type) (const char *pathname, char *buf, size_t bufsiz);

static orig_readlink_f_type orig_readlink;
ssize_t readlink(const char *pathname, char *buf, size_t bufsiz)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (pathname)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_readlink == NULL)
				orig_readlink = (orig_readlink_f_type) dlsym(RTLD_NEXT, "readlink");
		ssize_t x = orig_readlink(pathname, buf, bufsiz);
		return x;
}

typedef int (*orig_statfs_f_type) (const char *path, struct statfs * buf);
static orig_statfs_f_type orig_statfs;

int statfs(const char *path, struct statfs *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_statfs == NULL)
				orig_statfs = (orig_statfs_f_type) dlsym(RTLD_NEXT, "statfs");
		return orig_statfs(path, buf);
}

typedef int (*orig_statfs64_f_type) (const char *path, struct statfs64 * buf);
static orig_statfs64_f_type orig_statfs64;

int statfs64(const char *path, struct statfs64 *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (path)) {
				errno = ENOENT;
				return -1;
		}
		if (orig_statfs64 == NULL)
				orig_statfs64 = (orig_statfs64_f_type) dlsym(RTLD_NEXT, "statfs64");
		return orig_statfs64(path, buf);
}

typedef int (*orig___lxstat_f_type) (int vers, const char *name, struct stat * buf);
static orig___lxstat_f_type orig___lxstat;

int __lxstat(int vers, const char *name, struct stat *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (name)) {
				errno = ENOENT;
				return -1;
		}
		if (orig___lxstat == NULL)
				orig___lxstat = (orig___lxstat_f_type) dlsym(RTLD_NEXT, "__lxstat");
		return orig___lxstat(vers, name, buf);
}

typedef int (*orig___lxstat64_f_type) (int vers, const char *name, struct stat64 * buf);
static orig___lxstat64_f_type orig___lxstat64;

int __lxstat64(int vers, const char *name, struct stat64 *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (name)) {
				errno = ENOENT;
				return -1;
		}
		if (orig___lxstat64 == NULL)
				orig___lxstat64 = (orig___lxstat64_f_type) dlsym(RTLD_NEXT, "__lxstat64");
		return orig___lxstat64(vers, name, buf);
}

typedef int (*orig___xstat_f_type) (int vers, const char *name, struct stat * buf);

static orig___xstat_f_type orig___xstat;
int __xstat(int vers, const char *name, struct stat *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (name)) {
				errno = ENOENT;
				return -1;
		}
		if (orig___xstat == NULL)
				orig___xstat = (orig___xstat_f_type) dlsym(RTLD_NEXT, "__xstat");
		return orig___xstat(vers, name, buf);
}

typedef int (*orig___xstat64_f_type) (int vers, const char *name, struct stat64 * buf);

static orig___xstat64_f_type orig___xstat64;
int __xstat64(int vers, const char *name, struct stat64 *buf)
{
		if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (name)) {
				errno = ENOENT;
				return -1;
		}
		if (orig___xstat64 == NULL)
				orig___xstat64 = (orig___xstat64_f_type) dlsym(RTLD_NEXT, "__xstat64");
		return orig___xstat64(vers, name, buf);
}

typedef int (*orig_unlink_f_type) (const char *pathname);

static orig_unlink_f_type orig_unlink;
int unlink(const char *pathname)
{
		char *abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (AT_FDCWD, pathname);
		if (abs_path != NULL) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (abs_path);
				free(abs_path);
				abs_path = NULL;
		}
		if (orig_unlink == NULL)
				orig_unlink = (orig_unlink_f_type) dlsym(RTLD_NEXT, "unlink");
		return orig_unlink(pathname);
}

typedef int (*orig_rmdir_f_type) (const char *pathname);

static orig_rmdir_f_type orig_rmdir;
int rmdir(const char *pathname)
{
		char *abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (AT_FDCWD, pathname);
		if (abs_path != NULL) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (abs_path);
				free(abs_path);
				abs_path = NULL;
		}
		if (orig_rmdir == NULL)
				orig_rmdir = (orig_rmdir_f_type) dlsym(RTLD_NEXT, "rmdir");
		return orig_rmdir(pathname);
}

typedef int (*orig_unlinkat_f_type) (int dirfd, const char *pathname, int flags);

static orig_unlinkat_f_type orig_unlinkat;
int unlinkat(int dirfd, const char *pathname, int flags)
{
		char *abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (dirfd, pathname);
		if (abs_path != NULL) {
				RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (abs_path);
				free(abs_path);
				abs_path = NULL;
		}

		if (orig_unlinkat == NULL)
				orig_unlinkat = (orig_unlinkat_f_type) dlsym(RTLD_NEXT, "unlinkat");
		return orig_unlinkat(dirfd, pathname, flags);
}

typedef int (*orig_openat_f_type) (int dirfd, const char *pathname, int flags, ...);
static orig_openat_f_type orig_openat;
int openat(int dirfd, const char *pathname, int flags, ...)
{
		if (flags & O_RDONLY != 0 || flags & O_CREAT != 0) {
				char *abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (dirfd, pathname);
				if (abs_path != NULL) {
						if (flags & O_RDONLY != 0) {
								if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (abs_path)) {
										errno = ENOENT;
										return -1;
								}
						} else if (CLEAR_WHEN_CREATE && flags & O_CREAT != 0) {
								RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (abs_path);
						}
						free(abs_path);
						abs_path = NULL;
				}
		}
		if (orig_openat == NULL)
				orig_openat = (orig_openat_f_type) dlsym(RTLD_NEXT, "openat");
		va_list ap;
		va_start(ap, flags);
		if (flags & O_CREAT) {
				mode_t mode = va_arg(ap, mode_t);
				return orig_openat(dirfd, pathname, flags, mode);
		} else {
				return orig_openat(dirfd, pathname, flags, 0);
		}
}

typedef int (*orig_openat64_f_type) (int dirfd, const char *pathname, int flags, ...);
static orig_openat64_f_type orig_openat64;
int openat64(int dirfd, const char *pathname, int flags, ...)
{
		if (flags & O_RDONLY != 0 || flags & O_CREAT != 0) {
				char *abs_path = RND_FUNC(get_abs_path, CONFOUNDING_FACTOR) (dirfd, pathname);
				if (abs_path != NULL) {
						if (flags & O_RDONLY != 0) {
								if (RND_FUNC(has_conflict_case_exist, CONFOUNDING_FACTOR) (abs_path)) {
										errno = ENOENT;
										return -1;
								}
						} else if (CLEAR_WHEN_CREATE && flags & O_CREAT != 0) {
								RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (abs_path);
						}
						free(abs_path);
						abs_path = NULL;
				}
		}
		if (orig_openat64 == NULL)
				orig_openat64 = (orig_openat64_f_type) dlsym(RTLD_NEXT, "openat64");
		va_list ap;
		va_start(ap, flags);
		if (flags & O_CREAT) {
				mode_t mode = va_arg(ap, mode_t);
				return orig_openat64(dirfd, pathname, flags, mode);
		} else {
				return orig_openat64(dirfd, pathname, flags, 0);
		}
}

typedef int (*orig_creat_f_type) (const char *pathname, mode_t mode);
static orig_creat_f_type orig_creat;

int creat(const char *pathname, mode_t mode)
{
        if (CLEAR_WHEN_CREATE) {
            RND_FUNC(clear_dir_cache, CONFOUNDING_FACTOR) (pathname);
            if (orig_creat == NULL) {
                    orig_creat = (orig_creat_f_type) dlsym(RTLD_NEXT, "creat");
            }

        }
		return orig_creat(pathname, mode);
}
