/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#ifndef __KEYBOARDKBW__
#define __KEYBOARDKBW__

#include <stdint.h>

#define INACTIVE 0
#define ACTIVE 1

/* return values for key validation function */
// NULL key received
#define NULL_KEYERR -1

// base character appear in the list of shift variants
#define BASEINSV_KEYERR -2

// repeated character in the list of shift variants
#define SHIFTVARREP_KEYERR -3

// repeated neighbor key in the list of neighbours
#define NEIGHREP_KEYERR -4

// the key is valid
#define OK_KEY 1

/* *** */

// max number of shift variants per key
#define MAXSHIFTVARS 255

// max number of neighbours per key
#define MAXNEIGHBOURS 255

typedef struct key {
    double *counter; // array of counters - fidex size to maxdepth (max word length)
    struct key **reach; // array of pointer to keys
    int active; // whether this key is active or not
    int nreach; // length of reach
    int maxdepth; // used for dry-run
    char c; // character value
    char *shiftvar; // string containing shift variants ('\0'-terminated)
    int lensv; // length of shiftvar (excluding terminating char)
}key;

// if maxdepth <= 0 it is a normal execution, otherwise assume dry-run and use maxdepth
void initkey(key *k, int active, char c, char *shiftvar, int numreach, int maxdepth);
void printkey(key *k);
void freekey(key *k);

// same as initkey() but split in two separate calls to allow definition of
// characters first and definition of their neighbous at a different point
void char_initkey(key *k, int active, char c, char *shiftvar, int maxdepth);
void neigh_initkey(key *k, int numreach);

// search a key in list of length listlen where either the base char c or shift1
// or shift2 is equal to c
key *getkey(key *list, int listlen, char c);

// cheks base value, shift1 and shift2 for a and b keys, they should not share
// characters
int wrongKeys(const key *a, const key *b);

// a key is valid if all its values are different (base value, shift1 and
// shift2)
int validKey(const key *k);

#endif
