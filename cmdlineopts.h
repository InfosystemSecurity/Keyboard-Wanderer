/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#ifndef __CMDLINEOPTS__
#define __CMDLINEOPTS__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <getopt.h>

#define MAXKEYBOARDKEYS 128

#define MAXPATHLEN 128
#define MAXWORDLEN 512

#define EMPTY_PATH NULL
#define EMPTY_DRYRUN 0
#define EMPTY_INFINITERUN 0
#define EMPTY_KEYS NULL
#define EMPTY_MIN -1
#define EMPTY_MAX -1
#define EMPTY_TIMEOUT -1
#define EMPTY_RESTART NULL


typedef struct {
    int dryrun; // dryrun flag
    char *afpath; // keyboard arrangements file path
    int infiniterun; // if != 0 pass it to a call to pause(2) before returning from main
    char *keys; // starting keys - one dfs for each key
    int min; // min length of words to print
    int max; // max length of words to print
    char *logfpath; // --logfile; log file full path
    int timeout; // --stop; stop timer; < 0 error, == 0 no timer set, > 0 # sec
    char *restart; // restart string - if not set default to NULL and restart mode is not used
} cmdlopts_t;

// fname: program name
void usage(const char *fname);

cmdlopts_t parse_args(int argc, char *argv[]);

void free_args(cmdlopts_t *c);

void log_args(cmdlopts_t opt, FILE *logfile);


#endif
