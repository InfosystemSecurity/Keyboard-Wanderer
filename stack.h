/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#ifndef __KBWSTACK__
#define __KBWSTACK__

#define STACKSIZE 4096


struct stackel {
    key *k;
    int idx;
    int type; // -1 = c, >= 0 shiftvar index
    int visited;
};

typedef struct stack {
    struct stackel stack[STACKSIZE];
    int pos;
}stack;

#endif
