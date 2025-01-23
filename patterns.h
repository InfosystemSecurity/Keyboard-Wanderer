/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#ifndef __KBWPATTERNS__
#define __KBWPATTERNS__
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "keyboard.h"

#define MAXLINELEN 1024

key *parseFile(const char *fpath, int *numkeys, int maxdepth);

#endif