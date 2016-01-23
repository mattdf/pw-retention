/*
 * Copyright (c) 2016 by Matthew Di Ferrante
 *
 *   This program is free software: you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, either version 3 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>
#include <sqlite3.h>
#include <unistd.h>
#include <sys/time.h>
#include <time.h>
#include <string.h>
#include <openssl/sha.h>
#include <limits.h>
#include <termios.h>

#include "fs.h"


#define DB_NAME "pw.db"
#define SALT_LEN 4096
#define SHA512_OUTPUT 129
#define DATA_DIR ".pwret"



static const char usage[] = 
"usage: pwret [options]\n\
  \n\
  -a\t\tAdd a password entry\n\
  -s\t\tShow passwords (enable echo when typing)\n\
	\n";


void gensalt(char *dest, size_t length) {
	srand(time(NULL));
	char charset[] = "0123456789"
		"abcdefghijklmnopqrstuvwxyz"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		":;?@[\\]^_`{|}$#!~%&*()=+-<>,./";

	while (length --> 0) {
		size_t index = (double) rand() / RAND_MAX * (sizeof charset - 1);
		*dest++ = charset[index];
	}
	*dest = '\0';
}

void sha512(char *string, char *salt, char outputBuffer[SHA512_OUTPUT])
{
	unsigned char hash[SHA512_DIGEST_LENGTH];
	SHA512_CTX sha512;
	SHA512_Init(&sha512);
	SHA512_Update(&sha512, string, strlen(string));
	/* Concatenate salt fo the password */
	SHA512_Update(&sha512, salt, strlen(salt));
	SHA512_Final(hash, &sha512);
	int i = 0;
	for(i = 0; i < SHA512_DIGEST_LENGTH; i++)
	{
		sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
	}
	outputBuffer[SHA512_OUTPUT-1] = 0;
}

int stdin_prompt(char *msg, char **buffer){

	char *line = NULL;
	size_t len = 0;
	ssize_t read;

	fprintf(stdout, "%s: ", msg);

	read = getline(&line, &len, stdin);
	if (read < 2){
		return -1;
	}
	*buffer = calloc(1, read+1);
	strncpy(*buffer, line, read-1);

	return 0;
}

int passcheck_cb(void *flag, int argc, char **argv, char **colnames){

	if (argc < 3)
		return 0;

	int showflag = *((int*)flag);

	char *label = argv[0];
	char *salt = argv[1];
	char *hash = argv[2];

	char *pass;
	char passhash[SHA512_OUTPUT] = {0};
	int correct = 0;

	struct termios term;
	tcgetattr(STDIN_FILENO, &term);
	term.c_lflag &= ~ECHO;

	while (correct != 1){

		if (!showflag) tcsetattr(STDIN_FILENO, TCSANOW, &term);
		int skip = stdin_prompt(label, &pass);
		if (!showflag) { term.c_lflag &= ~ECHO; tcsetattr(STDIN_FILENO, TCSANOW, &term);}

		if (skip != 0){
			fprintf(stdout, "\x1B[1;34;49mSkipping.\x1B[0;0;0m\n");
			break;
		}

		sha512(pass, salt, passhash);

		if (strcmp(hash, passhash) != 0){
			fprintf(stdout, "\x1B[1;31;49mWrong!\x1B[0;0;0m\n");
		}
		else {
			fprintf(stdout, "\x1B[1;32;49mCorrect!\x1B[0;0;0m\n");
			correct = 1;
		}

		free(pass);

	}

	return 0;

}

int main(int argc, char **argv){

	int err;
	char *err_msg;
	sqlite3 *db;
	char dbpath[PATH_MAX] = {0};

	int addflag = 0;
	int showflag = 0;
	int initdb = 0;
	int c;


	while ((c = getopt (argc, argv, "as")) != -1){
		switch (c){
			case 'a':
				addflag = 1;
				break;
			case 's':
				showflag = 1;
				break;
			default:
				fprintf(stdout, usage);
				exit(0);
		}
	}

	if (fs_datadir_init(DATA_DIR)){
		perror("Failed to open config directory");
		exit(1);
	}

	if (fs_exists_relative(DB_NAME) != 0){
		puts("First run, initializing db...");
		initdb = 1;
	}

	strcat(dbpath, fs_datadir_getpath());
	strcat(dbpath, "/");
	strcat(dbpath, DB_NAME);


	if ((err = sqlite3_open(dbpath, &db)) != SQLITE_OK){
		fprintf(stderr, "sqlite3_open failure: %s\n", sqlite3_errmsg(db));
		sqlite3_close(db);
		exit(1);
	}

	if (initdb){
		char *sql = "CREATE TABLE passwords (label TEXT, salt TEXT, hash TEXT, created DATETIME, last_success DATETIME);";
		err = sqlite3_exec(db, sql, 0, 0, &err_msg);
		if (err != SQLITE_OK){
			fprintf(stderr, "SQL error: %s\n", err_msg);
			sqlite3_free(err_msg);
			sqlite3_close(db);
			exit(1);
		}
	}

	if (addflag){

		char *label, *pass;
		time_t rawtime;
		struct tm *timeinfo;
		char timestr[24] = {0};
		char *sql_p = "INSERT INTO passwords (label, salt, hash, created, last_success) VALUES (?, ?, ?, ?, ?);";
		sqlite3_stmt *res;
		char hash[SHA512_OUTPUT];

		puts("Adding new password");

		if (stdin_prompt("label", &label) || stdin_prompt("pass", &pass)){
			fprintf(stderr, "stdin error");
			exit(1);
		}

		time(&rawtime);
		timeinfo = localtime(&rawtime);
		strftime(timestr, sizeof(timestr), "%Y-%m-%d %H:%M:%S", timeinfo);

		err = sqlite3_prepare_v2(db, sql_p, -1, &res, 0);

		if (err == SQLITE_OK){
			char salt[SALT_LEN+1];
			gensalt(salt, SALT_LEN);
			sha512(pass, salt, hash);
			sqlite3_bind_text(res, 1, label, strlen(label), NULL);
			sqlite3_bind_text(res, 2, salt, SALT_LEN, NULL);
			sqlite3_bind_text(res, 3, hash, strlen(hash), NULL);
			sqlite3_bind_text(res, 4, timestr, strlen(timestr), NULL);
			sqlite3_bind_text(res, 5, timestr, strlen(timestr), NULL);
		}
		else {
			fprintf(stderr, "Failed to prepare insert statement: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}


		err = sqlite3_step(res);

		free(label);
		free(pass);

		if (err != SQLITE_OK && err != SQLITE_DONE){
			fprintf(stderr, "Failed to execute prepared insert: %s\n", sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}

		sqlite3_finalize(res);

		puts("Entry added successfully.");

	}
	else {

		int entries = 0;
		sqlite3_stmt *res;

		err = sqlite3_prepare_v2(db, "SELECT count(*) from passwords", -1, &res, 0);
		if (err != SQLITE_OK){
			fprintf(stderr, "SQL prepare failure: %s\n",  sqlite3_errmsg(db));
			sqlite3_close(db);
			exit(1);
		}

		err = sqlite3_step(res);

		if (err == SQLITE_ROW){
			entries = sqlite3_column_int(res, 0);
		}

		sqlite3_finalize(res);

		if (entries == 0){
			fprintf(stderr, "No passwords in db\n");
			exit(0);
		}

		fprintf(stdout, "%d passwords in db.\n", entries);

		err = sqlite3_exec(db, "SELECT label, salt, hash FROM passwords ORDER BY RANDOM()", passcheck_cb, &showflag, &err_msg);

		if (err != SQLITE_OK){
			fprintf(stderr, "SQL SELECT error: %s\n", err_msg);
			sqlite3_free(err_msg);
			sqlite3_close(db);
			exit(1);
		}

		puts("Finished.");

	}

	sqlite3_close(db);

	return 0;
}
