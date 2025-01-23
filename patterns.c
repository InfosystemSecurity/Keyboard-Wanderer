/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#include <ctype.h>

#include "patterns.h"
#include "keyboard.h"

int isemptybuff(char *buff, int len)
{
    int i;
    if (buff == NULL || len < 0) return 0;
    if (len == 0) return 1;
    for (i = 0; i < len; i++) if (!isspace(buff[i])) return 0;
    return 1;
}

void setup_neighbours(key *keys, int numkeys, const char *s)
{
    key *curr = NULL;
    int i = 0, j = 0;
    int nn = 0; //number of neighbours
    int nidx = 0; // neighbour index

    if (keys == NULL || s == NULL || *s == 0) {
        fprintf(stderr, "setup_neighbours: Parameter error\n");
        exit(1);
    }

    //search for the correct key
    for (i = 0; i < numkeys; i++) {
        if (keys[i].c == s[0]) {
            curr = keys+i;
            break;
        }
    }

    if (curr == NULL) {
        fprintf(stderr, "Can't find key %c\n", s[0]);
        exit(1);
    }

    nn = strnlen(s, MAXNEIGHBOURS);
    if (nn <= 2) return;

    if (curr->reach != NULL) {
        fprintf(stderr, "Found Repeated neighbourhood configuration for key \"%c\"\n", curr->c);
        exit(1);
    }

    neigh_initkey(curr, nn-2);

    // set the neighbours
    for (i = 2; i < nn; i++) {
        for (j = 0; j < numkeys; j++) {
            if (keys[j].c == s[i]) {
                break;
            }
        }
        if (j == numkeys) {
            fprintf(stderr, "Can't find key %c\n", s[i]);
            exit(1);
        }
        curr->reach[nidx] = &keys[j];
        nidx++;
    }

    return;
}

key *parseFile(const char *fpath, int *numkeys, int maxdepth)
{
    FILE *f = NULL;
    int ret = 0;
    size_t len = 0; // getline parameter
    size_t relen = 0; // string length
    char *buff = NULL;
    int state = -1;
    key *keys = NULL;
    int currkey = 0;
    int countsetup = 0;
    int i, j;


    if (fpath == NULL || *fpath == 0 || numkeys == NULL) {
        fprintf(stderr, "parseFile parameter error\n");
        exit(1);
    }

    *numkeys = 0;

    if ((f = fopen(fpath, "r")) == NULL) {
        fprintf(stderr, "Can't open file \"%s\"\n", fpath);
        exit(1);
    }

    while (ret >= 0) {
        ret = getline(&buff, &len, f);
        if (ret >= 0) {
            relen = strnlen(buff, MAXLINELEN);
            // remove newline
            if (buff[relen-1] == '\n') {
                buff[relen-1] = '\0';
                relen--;
            }
            if (state == -1) {
                if (buff[0] != '#' && !isemptybuff(buff, relen)) state = 0;
                else continue;
            }
            switch (state) {
                case 0: // first line
                    state++;
                    *numkeys = atoi(buff);
                    if (*numkeys <= 0) {
                        fprintf(stderr, "CONFIGURATION FILE ERROR - Invalid number of keys: %d\n", *numkeys);
                        exit(1);
                    }
                    keys = (key *)calloc(*numkeys, sizeof(key));
                    if (keys == NULL) {
                        fprintf(stderr, "malloc() failed\n");
                        exit(1);
                    }
                    break;
                case 1: // key definition
                    if (isemptybuff(buff, strnlen(buff, MAXLINELEN))) {
                        if (currkey != *numkeys) {
                            fprintf(stderr, "CONFIGURATION FILE ERROR - wrong number of keys - asked for %d, found %d\n", *numkeys, currkey);
                            exit(1);
                        }
                        state++;
                        continue;
                    }
                    if (currkey == *numkeys) {
                        fprintf(stderr, "CONFIGURATION FILE ERROR - too many keys - asked for %d, found %d\n", *numkeys, currkey + 1);
                        exit(1);
                    }
                    if (buff[0] == '\0') {
                        fprintf(stderr, "Parsing error - invalid base character\n");
                        exit(1);
                    }
                    if (buff[0] != '-') {
                        fprintf(stderr, "Key definition should start with '-'\n");
                        exit(1);
                    }
                    char_initkey(&keys[currkey], ACTIVE, buff[1], buff+2, maxdepth);
                    currkey++;
                    break;
                case 2: // neighbours definition
                    countsetup++;
                    if (countsetup > *numkeys) {
                        fprintf(stderr, "CONFIGURATION FILE ERROR - too many key configuration lines\n");
                        exit(1);
                    }
                    setup_neighbours(keys, *numkeys, buff);
                    break;
                default:
                    fprintf(stderr, "ERROR while reading configuration file - state: %d\n", state);
                    exit(1);
            }
        }
    }
    // reset buffer
    free(buff);
    buff = NULL;
    len = 0;

    // validation no repeated chars
    ret = validKey(&keys[0]);
    switch (ret) {
        case NULL_KEYERR:
            fprintf(stderr, "Invalid first NULL key\n");
            exit(1);
        case BASEINSV_KEYERR:
            fprintf(stderr, "Base key %c appreas in the set of its shift variants: \"%s\"\n", keys[0].c, keys[0].shiftvar);
            exit(1);
        case SHIFTVARREP_KEYERR:
            fprintf(stderr, "Base key %c has some repeated shift variant: \"%s\"\n", keys[0].c, keys[0].shiftvar);
            exit(1);
        case NEIGHREP_KEYERR:
            fprintf(stderr, "Base key %c has some repeated neighbour: \"", keys[0].c);
            for (i = 0; i < keys[0].nreach; ++i) {
                fprintf(stderr, "%c", keys[0].reach[i]->c);
            }
            fprintf(stderr, "\"\n");
            exit(1);
        case OK_KEY:
            break; // ok state
        default:
            fprintf(stderr, "CRITICAL - Invalid return value %d\n", ret);
            exit(1);
    }

    for (i = 1; i < *numkeys; ++i) {
        ret = validKey(&keys[i]);
        switch (ret) {
            case NULL_KEYERR:
                fprintf(stderr, "Invalid NULL key\n");
                exit(1);
            case BASEINSV_KEYERR:
                fprintf(stderr, "Base key %c appreas in the set of its shift variants: \"%s\"\n", keys[i].c, keys[i].shiftvar);
                exit(1);
            case SHIFTVARREP_KEYERR:
                fprintf(stderr, "Base key %c has some repeated shift variant: \"%s\"\n", keys[i].c, keys[i].shiftvar);
                exit(1);
            case NEIGHREP_KEYERR:
                fprintf(stderr, "Base key %c has some repeated neighbour: \"", keys[i].c);
                for (j = 0; j < keys[i].nreach; ++j) {
                    fprintf(stderr, "%c", keys[i].reach[j]->c);
                }
                fprintf(stderr, "\"\n");
                exit(1);
            case OK_KEY:
                break; // ok state
            default:
                fprintf(stderr, "CRITICAL - Invalid return value %d\n", ret);
                exit(1);
        }
        for (j = 0; j < i; ++j) {
            if (wrongKeys(&keys[i], &keys[j])) {
                fprintf(stderr, "Found repeated char in different keys.\n\
                        k1 base char: %c\n\
                        k1 shift var: %s\n\
                        k2 base char: %c\n\
                        k2 shift var: %s\n",
                        keys[j].c, keys[j].shiftvar, keys[i].c, keys[i].shiftvar);
                exit(1);
            }
        }
    }

    return keys;
}

