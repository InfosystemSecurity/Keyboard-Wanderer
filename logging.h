/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#ifndef __KBW_LOGGING__
#define __KBW_LOGGING__

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <assert.h>

// num words to generate before logging
#define WORDS_LIMIT 500000000

#define LOG_EXIT 0
#define LOG_CONT 1

void logmessage(int lexit, FILE *logfile, const char *format, ...);


#endif
