#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#define PACKET_BUFFER_LEN 2048

struct packet_info {
    uint32_t    seq;
    uint32_t    sent_sec;
    uint32_t    sent_usec;
} __attribute__((__packed__));

const char *OPTSTRING = "SCr:h";

const struct option LONGOPTS[] = {
    {.name = "server",      .has_arg = 0,   .flag = 0,  .val = 'S'},
    {.name = "client",      .has_arg = 0,   .flag = 0,  .val = 'C'},
    {.name = "dest",        .has_arg = 1,   .flag = 0,  .val = 'd'},
    {.name = "port",        .has_arg = 1,   .flag = 0,  .val = 'p'},
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
static const char *server_addr = "127.0.0.1";
static int server_port = 5005;
static long packet_length = 1400;
static long sending_rate = 1000000;

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
    printf("Usage: %s <--server | --client> [--port <port>] [--length <bytes>] [--rate <rate[kMG]>]\n");
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
            case 'd':
                server_addr = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'l':
                packet_length = atoi(optarg);
                break;
            case 'r':
                sending_rate = parse_rate(optarg);
                if(sending_rate < 0) {
                    fprintf(stderr, "Invalid rate: %s\n", optarg);
                    exit(EXIT_FAILURE);
                }
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

/*
 * Compute packet spacing to achieve desired rate.
 * rate in bits/second, length in bits, spacing in microseconds.
 */
static long compute_spacing(long rate, long length)
{
    if(length < LONG_MAX / 1000000) {
        long spacing_usecs = (1000000 * length) / rate;
        return spacing_usecs;
    } else if(length < LONG_MAX / 1000) {
        long spacing_msecs = (1000 * length) / rate;
        return (1000 * spacing_msecs);
    } else {
        long spacing_secs = length / rate;
        return (1000000 * spacing_secs);
    }
}

int main(int argc, char *argv[])
{
    int result;

    result = parse_args(argc, argv);
    if(result < 0)
        exit(EXIT_FAILURE);

    switch(mode) {
        case MODE_SERVER:
            return server_main();
        case MODE_CLIENT:
            return client_main();
    }

    return 0;
}

int server_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    int buffer_len = packet_length > PACKET_BUFFER_LEN ?
        packet_length : PACKET_BUFFER_LEN;

    snprintf(port_str, sizeof(port_str), "%d", server_port);

    const struct addrinfo hints = {
        .ai_flags = AI_PASSIVE | AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0,
    };

    result = getaddrinfo(NULL, port_str, &hints, &addrinfo);
    if(result < 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(EXIT_FAILURE);
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    result = bind(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if(result < 0) {
        perror("bind");
        exit(EXIT_FAILURE);
    }

    buffer = malloc(buffer_len);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        exit(EXIT_FAILURE);
    }

    while(1) {
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        result = recvfrom(sockfd, buffer, buffer_len, 0, 
                (struct sockaddr *)&from_addr, &from_addr_len);
        if(result < 0) {
            perror("recvfrom");
            exit(EXIT_FAILURE);
        } else {
            struct packet_info *info = (struct packet_info *)buffer;
            struct timeval received;

            gettimeofday(&received, NULL);

            printf("%9d.%06d %6u %6u %9d.%06d\n",
                    received.tv_sec, received.tv_usec,
                    result, ntohl(info->seq),
                    ntohl(info->sent_sec), ntohl(info->sent_usec));
        }
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

int client_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    long spacing;
    uint32_t next_seq = 0;

    snprintf(port_str, sizeof(port_str), "%d", server_port);

    const struct addrinfo hints = {
        .ai_flags = AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_DGRAM,
        .ai_protocol = 0,
    };

    result = getaddrinfo(server_addr, port_str, &hints, &addrinfo);
    if(result < 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        exit(EXIT_FAILURE);
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        exit(EXIT_FAILURE);
    }

    spacing = compute_spacing(sending_rate, 8 * packet_length);

    while(1) {
        struct timeval start;
        struct timeval end;
        long delay = spacing;

        gettimeofday(&start, NULL);

        struct packet_info *info = (struct packet_info *)buffer;
        info->seq = htonl(next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_usec = htonl(start.tv_usec);

        result = sendto(sockfd, buffer, packet_length, 0,
                addrinfo->ai_addr, addrinfo->ai_addrlen);
        if(result < 0) {
            perror("sendto");
            exit(EXIT_FAILURE);
        }

        gettimeofday(&end, NULL);

        delay -= (end.tv_sec - start.tv_sec) * 1000000;
        delay -= (end.tv_usec - start.tv_usec);
        
        if(delay > 0)
            usleep(delay);
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;

}

