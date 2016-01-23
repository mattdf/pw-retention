/*
 * Copyright (c) 2016 by Matthew Di Ferrante
 */

#define _XOPEN_SOURCE 700
#ifdef _POSIX_C_SOURCE
#undef _POSIX_C_SOURCE
#endif
#define _POSIX_C_SOURCE 200809L


#include "fs.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <pwd.h>
#include <unistd.h>
#include <errno.h>

#include <limits.h>
#include <string.h>


static int datadirfd;

int fs_datadir_init(char *DATA_DIR){

	const char *homedir;
	struct passwd *pw = getpwuid(getuid());

	if ((homedir = getenv("HOME")) == NULL){
		homedir = pw->pw_dir;
	}

	DIR *dir = opendir(homedir);

	if (dir){
		int dfd = dirfd(dir);
		struct stat st = {0};

		if (fstatat(dfd, DATA_DIR, &st, 0) == -1)
			mkdirat(dfd, DATA_DIR, 0700);

		datadirfd = openat(dfd, DATA_DIR, O_DIRECTORY);

		if (datadirfd == -1)
			return errno;

		closedir(dir);

		return 0;
	}
	else
		return errno;

}

char *fs_datadir_getpath(){
	static char file_path[PATH_MAX];

	char file_fd[PATH_MAX] = {0};

	memset(file_path, 0x00, PATH_MAX);

	sprintf(file_fd, "/proc/self/fd/%d", datadirfd);
	if (readlink(file_fd, file_path, PATH_MAX) == -1)
		return NULL;
	else
		return file_path;
}

int fs_exists_relative(char *pathname){

	struct stat st = {0};

	if (fstatat(datadirfd, pathname, &st, 0) == -1)
		return -1;
	else
		return 0;

}
