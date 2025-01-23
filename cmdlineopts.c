/* *
 * MIT License
 * Copyright (c) 2024 Infosystem Security s.r.l.
 * See the LICENSE file for full terms.
 * */
#include "cmdlineopts.h"
#include "logging.h"

void usage(const char *fname)
{
    fprintf(stderr, "usage: %s\n\
            -a,--arrangement    keyboard configuration file\n\
            -d,--dryrun         dry-run count number of generated words for eack key\n\
            -i,--infinite       pause the process before returning, waiting for a signal\n\
            -k,--keys           starting keys\n\
            -m,--min            min word length\n\
            -M,--max            max word length\n\
            -l,--logfile        log file path\n\
            -s,--stop           stop timer; < 0 error; == 0 no timer set; > 0 number of seconds\n\
            -w,--restart        restart string\n\
            \n\n\
            MIT License\n\
            Copyright (c) 2024 Infosystem Security s.r.l.\n\
            See the LICENSE file for full terms.\n\
            \n\n", fname);
    return;
}

cmdlopts_t init_cmdlopts(void)
{
    cmdlopts_t ret;
    ret.dryrun = EMPTY_DRYRUN;
    ret.afpath = EMPTY_PATH;
    ret.infiniterun = EMPTY_INFINITERUN;
    ret.keys = EMPTY_KEYS;
    ret.min = EMPTY_MIN;
    ret.max = EMPTY_MAX;
    ret.logfpath = EMPTY_PATH;
    ret.timeout = EMPTY_TIMEOUT;
    ret.restart = EMPTY_RESTART;

    return ret;
}

cmdlopts_t parse_args(int argc, char *argv[])
{
    cmdlopts_t ret = init_cmdlopts();
    int c;
    int i, j;

    if (argc <= 0 || argv == 0 || *argv == 0) {
        fprintf(stderr, "Can't parse arguments\n");
        exit(1);
    }

    while (1) { // from getopt_long manpage example
        int option_index = 0;
        static struct option long_options[] = {
            {"dryrun", no_argument, 0, 'd'},
            {"arrangement", required_argument, 0, 'a'},
            {"infinite", no_argument, 0, 'i'},
            {"keys", required_argument, 0, 'k'},
            {"min", required_argument, 0, 'm'},
            {"max", required_argument, 0, 'M'},
            {"logfile", required_argument, 0, 'l'},
            {"stop", required_argument, 0, 's'},
            {"restart", required_argument, 0, 'w'},
            {0, 0, 0, 0}
        };

        c = getopt_long(argc, argv, "a:dik:m:M:l:s:w:", long_options, &option_index);

        if (c == -1) break;

        switch(c) {
            case 'a':
                ret.afpath = strndup(optarg, MAXPATHLEN);
                if (ret.afpath == NULL) {
                    fprintf(stderr, "strndup() error on keyboard arrangement file path\n");
                    usage(argv[0]);
                    exit(1);
                }
                break;

            case 'd':
                ret.dryrun = 1;
                break;
            case 'i':
                ret.infiniterun = 1;
                break;
            case 'k':
                ret.keys = strndup(optarg, MAXKEYBOARDKEYS);
                if (ret.keys == NULL) {
                    fprintf(stderr, "strndup() error on keys\n");
                    exit(1);
                }
                break;
            case 'm':
                ret.min = atoi(optarg);
                break;
            case 'M':
                ret.max = atoi(optarg);
                break;
            case 'w':
                ret.restart = strndup(optarg, MAXWORDLEN);
                if (ret.restart == NULL) {
                    fprintf(stderr, "strndup() error on restart word\n");
                    exit(1);
                }
                break;
            case 'l':
                ret.logfpath = strndup(optarg, MAXPATHLEN);
                if (ret.logfpath == NULL) {
                    fprintf(stderr, "strndup() error on log file path\n");
                    exit(1);
                }
                break;
            case 's':
                ret.timeout = atoi(optarg);
                if (ret.timeout <= 0) {
                    fprintf(stderr, "timeout error, parameter -s,--stop should be > 0\n");
                    exit(1);
                }
                break;
            default:
                fprintf(stderr, "?? getopt returned character code 0%o ??\n", c);
                usage(argv[0]);
                exit(1);
        }
    }
    // ignores other parameters
    // check parameters in case they are still unset
    if (ret.afpath == NULL) {
        fprintf(stderr, "Must select a configuration file (option -a)\n");
        usage(argv[0]);
        exit(1);
    }

    if (ret.keys == NULL) {
        fprintf(stderr, "Must select at least one key -e.g. \"1234567890qwertyuiopasdfghjkl'zxcvbnm. ,\"\n");
        usage(argv[0]);
        exit(1);
    } else { // validate
        for (i = 1; ret.keys[i] != '\0'; ++i) {
            for (j = 0; j < i; ++j) {
                if (ret.keys[i] == ret.keys[j]) {
                    fprintf(stderr, "Reapeted initial key (%c) selected! Please avoid repeating the same key\n", ret.keys[i]);
                    exit(1);
                }
            }
        }
    }

    // open logfile
    if (ret.logfpath == NULL) {
        fprintf(stderr, "Option -l, --logfile log file path required\n");
        usage(argv[0]);
        exit(1);
    }

    if (ret.min <= 0) {
        fprintf(stderr, "mandatory minimum length -m must be > 0\n");
        usage(argv[0]);
        exit(1);
    }

    if (ret.max <= 0) {
        fprintf(stderr, "mandatory maximum length -M must be > 0\n");
        usage(argv[0]);
        exit(1);
    }

    if (ret.max < ret.min) {
        fprintf(stderr, "-m should be <= -M\n");
        usage(argv[0]);
        exit(1);
    }

    // restart is an optional argument
    if (ret.restart != NULL) {
        i = strnlen(ret.restart, MAXWORDLEN);
        if (i > ret.max || i < ret.min) {
            fprintf(stderr, "-w word has length %d, it must be >= %d and <= %d\n", i, ret.min, ret.max);
            usage(argv[0]);
            exit(1);
        }
    }

    return ret;
}

void free_args(cmdlopts_t *c)
{
    if (c == NULL) return;
    if (c->keys != NULL) free(c->keys);
    if (c->afpath != NULL) free(c->afpath);
    if (c->logfpath != NULL) {
        free(c->logfpath);
        c->logfpath = NULL;
    }
    if (c->restart != NULL) {
        free(c->restart);
        c->restart = NULL;
    }
}

void log_args(cmdlopts_t opt, FILE *logfile)
{
    if (logfile == NULL) logfile = stdout;
    if (opt.afpath != EMPTY_PATH ) logmessage(LOG_CONT, logfile, "--arrangement \"%s\"\n", opt.afpath);
    logmessage(LOG_CONT, logfile, "--dryrun \"%d\"\n", opt.dryrun);
    if (opt.infiniterun != EMPTY_INFINITERUN ) logmessage(LOG_CONT, logfile, "--infinite \"%d\"\n", opt.infiniterun);
    if (opt.keys != EMPTY_KEYS ) logmessage(LOG_CONT, logfile, "--keys \"%s\"\n", opt.keys);
    if (opt.min != EMPTY_MIN ) logmessage(LOG_CONT, logfile, "--min \"%d\"\n", opt.min);
    if (opt.max != EMPTY_MAX ) logmessage(LOG_CONT, logfile, "--max \"%d\"\n", opt.max);
    if (opt.logfpath != EMPTY_PATH ) logmessage(LOG_CONT, logfile, "--logfile \"%s\"\n", opt.logfpath);
    if (opt.timeout != EMPTY_TIMEOUT ) logmessage(LOG_CONT, logfile, "--stop \"%d\"\n", opt.timeout);
    if (opt.restart != EMPTY_RESTART ) logmessage(LOG_CONT, logfile, "--restart \"%s\"\n", opt.restart);
    return;
}