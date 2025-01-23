/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <assert.h>
#include <getopt.h>
#include <string.h>
#include <errno.h>
#include <signal.h>

#include <stdarg.h>
#include <time.h>

#include "patterns.h"
#include "keyboard.h"
#include "cmdlineopts.h"
#include "logging.h"
#include "stack.h"

uint64_t word_cnt;
time_t word_starttime;
time_t word_endtime;

char *word; // need global to print log in signal handler

FILE *flog; // global logfile

void sig_handler(int sigvalue)
{
    switch (sigvalue) {
        case SIGALRM:
            logmessage(LOG_CONT, flog, "****** RECEIVED SIGALRM ******\n");
            break;
        case SIGSEGV:
            logmessage(LOG_CONT, flog, "****** RECEIVED SIGSEGV ******\n");
            break;
        case SIGINT:
            logmessage(LOG_CONT, flog, "****** RECEIVED SIGINT ******\n");
            break;
        case SIGTERM:
            logmessage(LOG_CONT, flog, "****** RECEIVED SIGTERM ******\n");
            break;
        case SIGPIPE:
            logmessage(LOG_CONT, flog, "****** RECEIVED SIGPIPE ******\n");
            break;
        default:
            logmessage(LOG_CONT, flog, "------ ERROR ------\n");
            break;
    }

    word_endtime = time(NULL);
    if (word_starttime != 0) {
        logmessage(LOG_CONT, flog, "Generated %lu words in %lf seconds - last word: \"%s\"\n", word_cnt, difftime(word_endtime, word_starttime), word != NULL ? word : "");
    }

    fclose(flog);
    exit(0);
}

/* *
 * Counts how many strings will be generated starting from start
 * This method performs a partial DFS visiting just enough nodes to count the
 * number of total generated strings
 * */
void dry_run(key *start, int minlen, int depth)
{
    double acnt = 0; // tmp accumulator
    int i, mul; // index, multiplier and error code
    int curridx = 0;
    stack s;
    struct stackel *currstack;
    assert(start != NULL);
    assert(minlen > 0);
    assert(depth >= minlen);

    if (start->active == INACTIVE) {
        fprintf(stderr, "Can't start from an inactive key\n");
        exit(1); // wrong starting point
    }

    // init stack
    s.pos = 0;
    // add only base key other are just multiplied
    s.stack[s.pos].k = start;
    s.stack[s.pos].idx = curridx;
    s.stack[s.pos].type = -1;
    s.stack[s.pos].visited = 0;


    while (s.pos >= 0) {
        // get last stack elem
        currstack = &(s.stack[s.pos]);
        curridx = currstack->idx;

        // check if the value has already been computed
        if (currstack->k->counter[curridx] != 0) {
            s.pos--;
            continue;
        }

        if (currstack->visited == 0) {

            currstack->visited = 1;

            // adds neighbours (if max length not reached)
            if (curridx >= depth-1) { // never > depth-1
                acnt = 1;
                // count the number of variants
                acnt += currstack->k->lensv;

                if (currstack->k->counter[curridx] != 0 && currstack->k->counter[curridx] != acnt) {
                    fprintf(stderr, "something wrong with counters - found %lf should be either 0 or %lf\n", currstack->k->counter[curridx], acnt);
                    exit(1);
                } else {
                    currstack->k->counter[curridx] = acnt;
                }

                s.pos--;

                continue; // next iteration
            }

            if (s.pos == STACKSIZE-1) {
                fprintf(stderr, "reached max stack size\n");
                exit(1); // next iteration
            }

            // add all active reachable keys
            for (i = 0; i < currstack->k->nreach; i++) {
                // add base char
                if (currstack->k->reach[i]->active == ACTIVE) {
                    s.pos++;
                    assert(s.pos < STACKSIZE);
                    s.stack[s.pos].k = currstack->k->reach[i];
                    s.stack[s.pos].idx = curridx+1;
                    s.stack[s.pos].type = -1;
                    s.stack[s.pos].visited = 0;
                }
            }
        } else { // key already visited
            mul = 1;
            acnt = 0;
            // count number of variants
            mul += currstack->k->lensv;

            for (i = 0; i < currstack->k->nreach; i++) {
                if (currstack->k->reach[i]->counter[curridx+1] == 0) {
                    fprintf(stderr, "something wrong with counter at line %d\n", __LINE__);
                    exit(1);
                } else {
                    // accumulate number of suffixes
                    acnt += (currstack->k->reach[i]->counter[curridx+1]);
                }
            }

            acnt = mul * acnt; // multiply by the number of current keys (key + shift1 + shift2)

            if (curridx+1 >= minlen) {
                // for strings >= minlen we need to add 'mul' which counts the
                // last (curridx) considered character variants (key, shiftvar)
                currstack->k->counter[curridx] = acnt + mul;
            } else {
                // there are no strings with length < minlen
                currstack->k->counter[curridx] = acnt;
            }

            s.pos--;
        }
    }

    return;
}


/* *
 * Reinitialize the stack following the path defined by the initial string
 * 'word'. Only insert non visited nodes, visited one will be ignored in any
 * case. The last node (the one corresponding to the last character of word)
 * should be inserted as not visited so that all its neighbours will be inserted
 * and the search will continue from that point. It is ok if the search generates
 * words alredy generated in a previous run.
 * */
void reinitDFS(key *keyboard, int keyboardlen, stack *s, const char *word)
{
    int i, j, z;
    int len;
    key *k, *n;

    if (s == NULL || word == NULL) {
        logmessage(LOG_EXIT, flog, "Can't reinit the search - received NULL stack or initial string\n");
    }

    // assume word is correctly zero-terminated
    len = strnlen(word, MAXWORDLEN);
    s->pos = -1; // init to -1 to start from 0
    for (i = 0; i < len; i++) {
        // get pointer to current key
        k = getkey(keyboard, keyboardlen, word[i]);
        if (k == NULL) {
            logmessage(LOG_EXIT, flog, "Error searching a key for char %c\n", word[i]);
        }
        // always add current key to stack if it is the last char of word
        if (i == len-1) {
            // always add base character
            s->pos++;
            assert(s->pos < STACKSIZE);
            s->stack[s->pos].k = k;
            s->stack[s->pos].idx = i;
            s->stack[s->pos].type = -1;
            s->stack[s->pos].visited = 0;


            // add all shift variants from the first one to the one used
            if (k->c != word[i]) {
                for (j = 0; j < k->lensv; ++j) {
                    s->pos++;
                    assert(s->pos < STACKSIZE);
                    s->stack[s->pos].k = k;
                    s->stack[s->pos].idx = i;
                    s->stack[s->pos].type = j;
                    s->stack[s->pos].visited = 0;
                    // stop when the current character is found
                    if (k->shiftvar[j] == word[i]) break;
                }
            }
        } else {
            // otherwise only need to add the non-visited variants
            if (k->c != word[i]) {
                s->pos++;
                assert(s->pos < STACKSIZE);
                s->stack[s->pos].k = k;
                s->stack[s->pos].idx = i;
                s->stack[s->pos].type = -1;
                s->stack[s->pos].visited = 0;

                // all shift variants != word[i] but the last one
                for (j = 0; j < (k->lensv)-1; ++j) {
                    // stop at the current used shift variant
                    if (k->shiftvar[j] == word[i]) break;
                    // otherwise add the shift variant
                    s->pos++;
                    assert(s->pos < STACKSIZE);
                    s->stack[s->pos].k = k;
                    s->stack[s->pos].idx = i;
                    s->stack[s->pos].type = j;
                    s->stack[s->pos].visited = 0;
                }
            }
            
            // Add all the neighbours but the one used as next character
            n = getkey(keyboard, keyboardlen, word[i+1]);
            for (j = 0; j < k->nreach; ++j) {
                if (k->reach[j] == n) break;//do not insert the neighbour of the next character
                // only insert active neighbours
                // insert base char, shift1 and shift2 of all non visited
                // neighbours
                if (k->reach[j]->active == ACTIVE) {
                    // base character
                    s->pos++;
                    assert(s->pos < STACKSIZE);
                    s->stack[s->pos].k = k->reach[j];
                    s->stack[s->pos].idx = i+1;
                    s->stack[s->pos].type = -1;
                    s->stack[s->pos].visited = 0;

                    // shift variants
                    for (z = 0; z < k->reach[j]->lensv; ++z) {
                        s->pos++;
                        assert(s->pos < STACKSIZE);
                        s->stack[s->pos].k = k->reach[j];
                        s->stack[s->pos].idx = i+1;
                        s->stack[s->pos].type = z;
                        s->stack[s->pos].visited = 0;
                    }
                }
            }
        } 
    }

    return;

}

/* *
 * Perform DFS on the (directed) graph representing the keyboard.
 * The DFS follows every edge. If a back-edge is met the search will follow the
 * loop (until depth is reached, see depth argument)
 * start: is the starting key
 * minlen: minimul length of string to produce (strings shorter than minlen are not printed out)
 * depth: maximum length of string to produce, also maximum deep of the DFS
 * keyboard: the whole keyboard, needed to reinit the stack if restart != NULL
 * keyboardlen: length of keyboard
 * restart: restart string
 * */
void dfs(key *start, int minlen, int depth, key *keyboard, int keyboardlen, char *restart)
{
    int i,j; // index, multiplier and error code
    int curridx = 0;
    stack s;
    struct stackel *currstack;
    assert(start != NULL);
    assert(minlen > 0);
    assert(depth >= minlen);
    // we care about keyboard and keyboardlen parameters only if we need them
    if (restart != NULL) {
        assert(keyboard != NULL);
        assert(keyboardlen >= 0);
    }

    word_starttime = time(NULL);

    // reset word for this run
    if (word != NULL) {
        free(word);
        word = NULL;
    }

    if ((word = (char *)malloc(depth+1)) == NULL) {
        fprintf(stderr, "malloc() error\n");
        exit(1);
    }
    // if restart mode copy initial string
    if (restart != NULL) {
        strncpy(word, restart, depth+1);
    }

    if (restart == NULL) {
        if (start->active == INACTIVE) {
            fprintf(stderr, "Can't start from an inactive key\n");
            exit(1); // wrong starting point
        }

        // init stack
        s.pos = 0;
        // add initial key base character to the stack
        s.stack[s.pos].k = start;
        s.stack[s.pos].idx = curridx;
        s.stack[s.pos].type = -1;
        s.stack[s.pos].visited = 0;

        // add initial key shift variants to the stack
        for (i = 0; i < start->lensv; ++i) {
            s.pos++;
            s.stack[s.pos].k = start;
            s.stack[s.pos].idx = curridx;
            s.stack[s.pos].type = i;
            s.stack[s.pos].visited = 0;
        }
    } else { // restart from an interrupted state
        reinitDFS(keyboard, keyboardlen, &s, restart);
    }


    while (s.pos >= 0) {
        // get last stack elem
        currstack = &(s.stack[s.pos]);
        curridx = currstack->idx;

        if (currstack->visited == 0) {

            currstack->visited = 1;

            word[curridx+1] = '\0';
            if (currstack->type == -1) { // base char
                word[curridx] = currstack->k->c;
            } else if (currstack->type >= 0) { // shift variant
                word[curridx] = currstack->k->shiftvar[currstack->type];
            } else { // index < -1 not allowed
                fprintf(stderr, "Wrong character index: %d\n", currstack->type);
                exit(1);
            }

            // print current word
            if (curridx+1 >= minlen) {
                puts(word);

                word_cnt++;
                if (word_cnt == WORDS_LIMIT) {
                    word_cnt = 0;
                    word_endtime = time(NULL);
                    logmessage(LOG_CONT, flog, "Generated %lu words in %lf seconds - last word: \"%s\"\n", WORDS_LIMIT, difftime(word_endtime, word_starttime), word);
                    word_starttime = time(NULL);
                }

            }

            // adds neighbours (if max length not reached)
            if (curridx >= depth-1) {
                s.pos--;

                continue; // next iteration
            }

            if (s.pos == STACKSIZE-1) {
                fprintf(stderr, "reached max stack size\n");
                exit(1); // next iteration
            }

            for (i = 0; i < currstack->k->nreach; i++) {
                if (currstack->k->reach[i]->active == ACTIVE) {
                    s.pos++;
                    assert(s.pos < STACKSIZE);
                    s.stack[s.pos].k = currstack->k->reach[i];
                    s.stack[s.pos].idx = curridx+1;
                    s.stack[s.pos].type = -1; // base character
                    s.stack[s.pos].visited = 0;

                    // add shift variants
                    for (j = 0; j < currstack->k->reach[i]->lensv; ++j) {
                        s.pos++;
                        assert(s.pos < STACKSIZE);
                        s.stack[s.pos].k = currstack->k->reach[i];
                        s.stack[s.pos].idx = curridx+1;
                        s.stack[s.pos].type = j;
                        s.stack[s.pos].visited = 0;
                    }
                }
            }
        } else {
            s.pos--;
        }
    }

    word_endtime = time(NULL);
    logmessage(LOG_CONT, flog, "Ending DFS from %c, generated %lu words in %lf seconds - last word: \"%s\"\n", start->c, word_cnt, difftime(word_endtime, word_starttime), word);
    word_cnt = 0;


    return;
}

int main(int argc, char *argv[])
{
    key **startkeys = NULL;
    int i, lenkeys;
    key *tmpk;
    int err = 0;
    double total = 0; // for dry-run count total number of strings

    struct sigaction sa;

    key *keyboard = NULL; // represent the entire keyboard
    int numkeys = 0; // total number of keys in keyboard (array length)

    cmdlopts_t opt = parse_args(argc, argv);

    flog = fopen(opt.logfpath, "a"); // create first time, always append
    assert(flog != NULL);

    log_args(opt, flog);

    // install signal handlers
    memset(&sa, 0, sizeof(struct sigaction));

    // block all signals when handling
    if (sigfillset(&sa.sa_mask) != 0) {
        err = errno;
        fprintf(stderr, "sigfillset() failed with error %s\n", strerror(err));
        exit(1);
    }
    sa.sa_handler = sig_handler;

    if (sigaction(SIGSEGV, &sa, NULL) != 0) {
        err = errno;
        fprintf(stderr, "sigaction() failed with error %s\n", strerror(err));
        exit(1);
    }
    logmessage(LOG_CONT, flog, "Handler for SIGSEGV installed\n");

    if (sigaction(SIGINT, &sa, NULL) != 0) {
        err = errno;
        fprintf(stderr, "sigaction() failed with error %s\n", strerror(err));
        exit(1);
    }
    logmessage(LOG_CONT, flog, "Handler for SIGINT installed\n");

    if (sigaction(SIGTERM, &sa, NULL) != 0) {
        err = errno;
        fprintf(stderr, "sigaction() failed with error %s\n", strerror(err));
        exit(1);
    }
    logmessage(LOG_CONT, flog, "Handler for SIGTERM installed\n");

    if (sigaction(SIGALRM, &sa, NULL) != 0) {
        err = errno;
        fprintf(stderr, "sigaction() failed with error %s\n", strerror(err));
        exit(1);
    }
    logmessage(LOG_CONT, flog, "Handler for SIGALRM installed\n");

    if (sigaction(SIGPIPE, &sa, NULL) != 0) {
        err = errno;
        fprintf(stderr, "sigaction() failed with error %s\n", strerror(err));
        exit(1);
    }
    logmessage(LOG_CONT, flog, "Handler for SIGPIPE installed\n");

    // call alarm() with the set timeout
    if (opt.timeout > 0) { 
        // start timeout
        alarm(opt.timeout);
        logmessage(LOG_CONT, flog, "setting alarm(%d)\n", opt.timeout);
    }

    // failure managed inside parseFile()
    keyboard = parseFile(opt.afpath, &numkeys, opt.dryrun ? opt.max : 0);

    lenkeys = strnlen(opt.keys, numkeys); // at most numkeys 
    startkeys = (key **)malloc(lenkeys * sizeof(key *));
    if (startkeys == NULL) {
        fprintf(stderr, "malloc() error\n");
        exit(1);
    }
    for (i = 0; i < lenkeys; i++) {
        tmpk = getkey(keyboard, numkeys, opt.keys[i]);
        if (tmpk == NULL) {
            fprintf(stderr, "can't find key %c\n", opt.keys[i]);
            goto term;
        }
        startkeys[i] = tmpk;
    }

    i = 0; // init i in case opt.restart == NULL
    if (opt.restart != NULL) {
        tmpk = getkey(keyboard, numkeys, opt.restart[0]);
        for (i = 0; i < lenkeys; ++i) {
            if (tmpk == startkeys[i]) break;
        }
        if (i >= lenkeys) {
            fprintf(stderr, "Can't find initial char %c for restart word %s\n", opt.restart[0], opt.restart);
            exit(1);
        }
        logmessage(LOG_CONT, flog, "Restarting from word \"%s\", key index: %d\n", opt.restart, i);
    }

    while (i < lenkeys) {
        if (opt.dryrun) {
            dry_run(startkeys[i], opt.min, opt.max);
            fprintf(stdout, "%5c: %50.0lf\n", startkeys[i]->c, startkeys[i]->counter[0]);
            total += (double)(startkeys[i]->counter[0]);
        } else {
            dfs(startkeys[i], opt.min, opt.max, keyboard, numkeys, opt.restart);
            // restart only the first time
            free(opt.restart);
            opt.restart = NULL;
        }
        i++;
    }
    if (opt.dryrun) {
        fprintf(stdout, "Total: %50.0lf\n", total);
    }

    logmessage(LOG_CONT, flog, "Execution completed\n");

term:

    if (opt.afpath != NULL) {
        for (i = 0; i < numkeys; i++) {
            freekey(&keyboard[i]);
        }

    }
    if (keyboard != NULL) free(keyboard);

    free_args(&opt);

    // pause if infinite run is required
    if (opt.infiniterun == 1) pause();

    if (word != NULL) {
        free(word);
        word = NULL;
    }

    // assume it is not already closed - it can be closed in handling signals which
    // calls exit(), so it should never reach this point
    fclose(flog);

    return 0;
}