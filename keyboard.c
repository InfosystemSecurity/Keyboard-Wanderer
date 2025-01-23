/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include "keyboard.h"

// assume shiftvar is a '\0'-terminated string
void char_initkey(key *k, int active, char c, char *shiftvar, int maxdepth)
{
    int i;
    assert(k != NULL);
    assert(maxdepth >= 0);
    k->active = active;
    k->c = c;
    assert(k->shiftvar == NULL);
    assert(shiftvar != NULL);
    k->lensv = strnlen(shiftvar, MAXSHIFTVARS+1);
    assert(k->lensv >= 0 && k->lensv <= MAXSHIFTVARS);

    k->shiftvar = strdup(shiftvar);
    assert(k->shiftvar != NULL);

    assert(k->reach == NULL);
    k->nreach = 0;

    // dry-run setup
    assert(k->counter == NULL);
    k->maxdepth = maxdepth;
    if (maxdepth > 0) {
        k->counter = (double *)malloc(maxdepth * sizeof(double));
        assert(k->counter != NULL);
        for (i = 0; i < maxdepth; ++i) {
            k->counter[i] = 0;
        }
    }

    return;
}

// initialize key neighbours with empty array
void neigh_initkey(key *k, int numreach)
{
    assert(k != NULL);
    assert(numreach > 0);

    k->reach = (key **)malloc(numreach * sizeof(key *));
    assert(k->reach != NULL);

    k->nreach = numreach;


    return;
}

void initkey(key *k, int active, char c, char *shiftvar, int numreach, int maxdepth)
{
    char_initkey(k, active, c, shiftvar, maxdepth);
    neigh_initkey(k, numreach);

    return;
}

void printkey(key *k)
{
    int i = 0;
    printf("Active: %d\n", k->active);
    printf("Char: %c\n", k->c);
    while (k->shiftvar[i] != '\0') {
        printf("shift%d: %c\n", i+1, k->shiftvar[i]);
        ++i;
    }
    printf("numreach: %d\n", k->nreach);
    return;
}

void freekey(key *k)
{
    if (k == NULL) return;
    k->active = INACTIVE;
    k->c = 0;
    if (k->shiftvar != NULL) {
        free(k->shiftvar);
        k->shiftvar = NULL;
    }
    if (k->reach != NULL) {
        free(k->reach);
        k->reach = NULL;
    }

    if (k->counter != NULL) {
        free(k->counter);
        k->counter = NULL;
    }
}

// searches in list of length listlen for a key which either base character or
// a shift variant is equal to c if no key is found NULL is returned
key *getkey(key *list, int listlen, char c)
{
    int i;
    if (list == NULL || listlen <= 0) return NULL;
    for (i = 0; i < listlen; ++i) {
        if (list[i].c == c || strchr(list[i].shiftvar, c) != NULL) {
            return list+i;
        }
    }
    return NULL;
}

// check a and b do not share characters
// returns 0 if a and b are valid, != 0 otherwise
int wrongKeys(const key *a, const key *b)
{
    int i;
    if (a == NULL || b == NULL) return 1;

    if (a == b) return 2;

    // base char of a appears in b
    if (a->c == b->c || strchr(b->shiftvar, a->c)) return 3;

    // some shift variants of a appears in b
    for (i = 0; i < a->lensv; ++i) {
        if (a->shiftvar[i] == b->c || strchr(b->shiftvar, a->shiftvar[i]) != NULL) return 4;
    }

    // all chars in a checked against all chars in b; they do not share any char
    return 0;
}

// a key is valid if all its values are different (base value and shift variants)
// Return values are defined in keyboard.h
int validKey(const key *k)
{
    int i, j;
    if (k == NULL) return NULL_KEYERR;

    // base char against shift variants
    if (strchr(k->shiftvar, k->c) != NULL) return BASEINSV_KEYERR;

    // repeated shift variants
    for (i = 0; i < k->lensv-1; ++i) {
        for (j = i+1; j < k->lensv; ++j) {
            if (k->shiftvar[i] == k->shiftvar[j]) return SHIFTVARREP_KEYERR;
        }
    }

    // check there are no repeated neighbours
    for (i = 0; i < k->nreach-1; ++i) {
        for (j = i+1; j < k->nreach; ++j) {
            if (k->reach[i]->c == k->reach[j]->c) return NEIGHREP_KEYERR;
        }
    }

    return OK_KEY;
}
