/*
 * Copyright (c) 2016 by Matthew Di Ferrante
 */
#ifndef __FS_H
#define __FS_H

#include <stdio.h>

int fs_datadir_init();
int fs_exists_relative(char *pathname);
char *fs_datadir_getpath();

#endif
