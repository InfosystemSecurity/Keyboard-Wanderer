/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#include "logging.h"


void logmessage(int lexit, FILE *logfile, const char *format, ...)
{
    va_list arglist;
    time_t t;
    struct tm *tm;
    char s[64];
    size_t ret;

    assert(logfile != NULL);

    // get current date and time
    t = time(NULL);
    tm = localtime(&t);
    ret = strftime(s, sizeof(s), "%F %A %T", tm);
    assert(ret);

    va_start(arglist, format);
    fprintf(logfile, "%s: ", s);
    vfprintf(logfile, format, arglist);
    va_end(arglist);
    fflush(logfile);

    sync();

    if (lexit == LOG_EXIT) {
        exit(1);
    }
}

