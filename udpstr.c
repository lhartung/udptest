#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

const char *OPTSTRING = "SCr:h";

const struct option LONGOPTS[] = {
    {.name = "server",      .has_arg = 0,   .flag = 0,  .val = 'S'},
    {.name = "client",      .has_arg = 0,   .flag = 0,  .val = 'C'},
    {.name = "length",      .has_arg = 1,   .flag = 0,  .val = 'l'},
    {.name = "rate",        .has_arg = 1,   .flag = 0,  .val = 'r'},
    {.name = "help",        .has_arg = 0,   .flag = 0,  .val = 'h'},
    {.name = 0,             .has_arg = 0,   .flag = 0,  .val =  0},
};

enum {
    MODE_SERVER,
    MODE_CLIENT,
};

static int mode = MODE_SERVER;
static int packet_length = 0;
static long sending_rate = 0;

static long parse_rate(const char *rate_str)
{
    char *end;

    long rate = strtol(rate_str, &end, 10);
    if((errno == ERANGE && (rate == LONG_MAX || rate == LONG_MIN)) ||
            (errno != 0 && rate == 0)) {
        perror("strtol");
        return -1;
    }

    while(end && *end) {
        if(isalpha(*end)) {
            switch(*end) {
                case 'G':
                    rate *= 1e9;
                    break;
                case 'M':
                    rate *= 1e6;
                    break;
                case 'k':
                    rate *= 1e3;
                    break;
                default:
                    return -1;
            }
        }
        end++;
    }

    return rate;
}

static void print_usage(const char *cmd)
{
    printf("Usage: %s <--server | --client> [--length bytes] [--rate value[kMG]]\n");
}

static int parse_args(int argc, char *argv[])
{
    int opt;

    opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL);
    while(opt > 0) {
        switch(opt) {
            case 'S':
                mode = MODE_SERVER;
                break;
            case 'C':
                mode = MODE_CLIENT;
                break;
            case 'l':
                packet_length = atoi(optarg);
                break;
            case 'r':
                sending_rate = parse_rate(optarg);
                break;
            case 'h':
                print_usage(argv[0]);
                return -1;
            default:
                fprintf(stderr, "Invalid option: %c\n", opt);
                print_usage(argv[0]);
                return -1;
        }

        opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL);
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int result;

    result = parse_args(argc, argv);
    if(result < 0)
        exit(EXIT_FAILURE);

    printf("length: %d, rate: %ld\n", packet_length, sending_rate);

    return 0;
}

