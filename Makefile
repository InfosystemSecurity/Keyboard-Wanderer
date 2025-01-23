CC = gcc
CFLAGS = -Wall -O3

CTARGETS = cmdlineopts.c keyboard.c logging.c main.c patterns.c
OBJECTS = cmdlineopts.o keyboard.o logging.o main.o patterns.o

LDFLAGS = -static

EXENAME = kbw

${EXENAME}: ${OBJECTS}
	$(CC) $(CFLAGS) $(FLAGS) -o $(EXENAME) $(OBJECTS)

.PHONY: clean static help

static: FLAGS=$(LDFLAGS)
static: $(EXENAME)

cmdlineopts.o: cmdlineopts.h logging.h
keyboard.o: keyboard.h
logging.o: logging.h
main.o: patterns.h keyboard.h cmdlineopts.h logging.h stack.h
patterns.o: patterns.h keyboard.h


clean:
	rm -vf ${OBJECTS} $(EXENAME)

help:
	$(info ******************************************************************)
	$(info *    Makefile targets:                                           *)
	$(info *      kbw (default):  generate kbw executable                   *)
	$(info *      static:  generate statically linked kbw executable        *)
	$(info ******************************************************************)

