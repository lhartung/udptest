#include <assert.h>
#include <fcntl.h>
#include <math.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <limits.h>
#include <sched.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if.h>
#include <linux/if_ether.h>

#include "rxbuff.h"
#include "tsutil.h"
#include "uthash.h"

#define PACKET_BUFFER_LEN 2048

#define DEFAULT_DCLIENT_INTERVAL    1000000
#define DEFAULT_TIME_SUFFIX         's'
#define DEFAULT_TIME_LIMIT          30

/*
 * Measurement data sent in each UDP packet.
 */
struct packet_info {
    uint32_t session;   // session ID from the sender's perspective
    uint32_t seq;       // sender sequence number
    uint32_t sent_sec;  // sender timestamp (seconds part)
    uint32_t sent_nsec; // sender timestamp (nanoseconds part)
    uint32_t key;       // private shared key
    uint32_t size;      // size (bytes) of payload
    uint32_t delay_sec; // time since previous send (seconds part)
    uint32_t delay_nsec;// time since previous send (nanoseconds part)
} __attribute__((__packed__));

const size_t MIN_PACKET_LENGTH = sizeof(struct packet_info);

struct client_info {
    struct sockaddr_storage addr;
    socklen_t addr_len;

    char addrstr[INET6_ADDRSTRLEN];
    char portstr[6];

    struct timespec timeout;

    uint32_t session;
    uint32_t next_seq;

    int sockfd;
    long packet_interval;

    UT_hash_handle hh;
};

enum {
    MODE_UP_SERVER,
    MODE_UP_CLIENT,
    MODE_DOWN_SERVER,
    MODE_DOWN_CLIENT,
    MODE_TCP_DOWN_SERVER,
    MODE_TCP_DOWN_CLIENT,
};

const char *OPTSTRING = "SCDRd:p:l:r:t:k:i:b:ch";

const struct option LONGOPTS[] = {
    {.name = "userver", .has_arg = 0, .val = 'S'},
    {.name = "uclient", .has_arg = 0, .val = 'C'},
    {.name = "dserver", .has_arg = 0, .val = 'D'},
    {.name = "dclient", .has_arg = 0, .val = 'R'},
    {.name = "dest",    .has_arg = 1, .val = 'd'},
    {.name = "port",    .has_arg = 1, .val = 'p'},
    {.name = "length",  .has_arg = 1, .val = 'l'},
    {.name = "rate",    .has_arg = 1, .val = 'r'},
    {.name = "time",    .has_arg = 1, .val = 't'},
    {.name = "key",     .has_arg = 1, .val = 'k'},
    {.name = "interval",.has_arg = 1, .val = 'i'},
    {.name = "bind",    .has_arg = 1, .val = 'b'},
    {.name = "csv",     .has_arg = 0, .val = 'c'},
    {.name = "connect-timeout", .has_arg = 1, .val = 'n'},
    {.name = "timeout", .has_arg = 1, .val = 'o'},
    {.name = "help",    .has_arg = 0, .val = 'h'},
    {.name = "tcp-dserver", .has_arg = 0, .val = MODE_TCP_DOWN_SERVER},
    {.name = "tcp-dclient", .has_arg = 0, .val = MODE_TCP_DOWN_CLIENT},
    {.name = 0,         .has_arg = 0, .val =  0},
};

/*
 * Command-line arguments that control program behavior.
 */
static int mode = -1;
static const char *server_addr = "127.0.0.1";
static int server_port = 5050;
static long packet_length = 1400;
static long sending_rate = 1000000;
static tsval_t time_limit = -1;
static unsigned access_key = 0;
static tsval_t packet_interval = -1;
static const char *bind_device = NULL;
static tsval_t connect_timeout = -1;
static tsval_t data_timeout = -1;
static int csv_output = 0;

/*
 * Parse a null-terminated string specifying a bit rate.
 *
 * The expected format is a number followed by an optional multiplier suffix,
 * G, M, or k.
 *
 * Returns a negative value on error.
 */
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

/*
 * Parses a time string with an optional suffix.
 * Returns a value in nanoseconds, negative indicates an error.
 */
tsval_t parse_time(const char *time_str)
{
    char *end;

    long time = strtol(time_str, &end, 10);
    if((errno == ERANGE && (time == LONG_MAX || time == LONG_MIN)) ||
            (errno != 0 && time == 0)) {
        perror("strtol");
        return -1;
    }

    while(end && *end) {
        if(isalpha(*end)) {
            return apply_time_suffix(time, *end);
        }
        end++;
    }

    return apply_time_suffix(time, DEFAULT_TIME_SUFFIX);
}

static void print_usage(const char *cmd)
{
    printf("udptest is a featureful UDP+TCP bandwidth testing tool.\n");
    printf("Copyright (C) 2013 Lance Hartung\n");
    printf("\n");
    printf("Usage: %s <mode> [options]\n", cmd);
    printf("\n");
    printf("Modes:\n");
    printf("  --userver     Receiving server for upload test\n");
    printf("  --uclient     Sending client for upload test\n");
    printf("  --dserver     Sending server for download test\n");
    printf("  --dclient     Receiving client for download test\n");
    printf("  --tcp-dserver Sending server for download test\n");
    printf("  --tcp-dclient Receiving client for download test\n");
    printf("\n");
    printf("Options:\n");
    printf("  --dest\n");
    printf("  --port\n");
    printf("  --length      Length of payload (bytes) in data packets\n");
    printf("  --rate        Target bit rate (optionally append a suffix k, M, or G without a space)\n");
    printf("  --time        Time limit (in seconds, zero means no limit)\n");
    printf("  --key         Authentication key (positive integer) to be used between dserver and dclient\n");
    printf("  --interval    Packet interval (seconds, overrides --rate, optionally append a suffix m, u, or n without a space)\n");
    printf("  --bind        Bind to device (super-user only)\n");
    printf("  --connect-timeout     Timeout (seconds) for establishing TCP connection\n");
    printf("  --timeout     Timeout (seconds) for receiving data\n");
    printf("  --csv         Produce output in CSV format\n");
}

/*
 * Parse the command-line arguments.
 *
 * Returns 0 on success or a negative value on failure.
 */
static int parse_args(int argc, char *argv[])
{
    const char *command = argv[0];
    int opt;

    opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL);
    while(opt > 0) {
        switch(opt) {
            case 'S':
                mode = MODE_UP_SERVER;
                break;
            case 'C':
                mode = MODE_UP_CLIENT;
                break;
            case 'D':
                mode = MODE_DOWN_SERVER;
                break;
            case 'R':
                mode = MODE_DOWN_CLIENT;
                break;
            case 'd':
                server_addr = optarg;
                break;
            case 'p':
                server_port = atoi(optarg);
                break;
            case 'l':
                packet_length = atol(optarg);
                if(packet_length < (long)MIN_PACKET_LENGTH) {
                    fprintf(stderr, "Packet length (%ld) must be at least %u\n",
                            packet_length, MIN_PACKET_LENGTH);
                    return -1;
                }
                break;
            case 'r':
                sending_rate = parse_rate(optarg);
                if(sending_rate < 0) {
                    fprintf(stderr, "Invalid rate: %s\n", optarg);
                    return -1;
                }
                break;
            case 't':
                time_limit = parse_time(optarg);
                if(time_limit < 0) {
                    fprintf(stderr, "Invalid time limit: %s\n", optarg);
                    return -1;
                }
                break;
            case 'k':
                access_key = atoi(optarg);
                break;
            case 'i':
                packet_interval = parse_time(optarg);
                if(packet_interval < 0) {
                    fprintf(stderr, "Invalid packet interval: %s\n", optarg);
                    return -1;
                }
                break;
            case 'b':
                bind_device = optarg;
                break;
            case MODE_TCP_DOWN_SERVER:
                mode = MODE_TCP_DOWN_SERVER;
                break;
            case MODE_TCP_DOWN_CLIENT:
                mode = MODE_TCP_DOWN_CLIENT;
                break;
            case 'n':
                connect_timeout = parse_time(optarg);
                break;
            case 'o':
                data_timeout = parse_time(optarg);
                break;
            case 'c':
                csv_output = 1;
                break;
            case 'h':
                print_usage(command);
                return -1;
            default:
                fprintf(stderr, "Invalid option: %c\n", opt);
                print_usage(command);
                return -1;
        }

        opt = getopt_long(argc, argv, OPTSTRING, LONGOPTS, NULL);
    }

    return 0;
}

/*
 * Compute packet spacing to achieve desired rate.
 * Rate in bits/second, length in bits, spacing in microseconds.
 */
tsval_t compute_spacing(long rate, long length)
{
    double spacing = (double)length / (double)rate;
    return (tsval_t)round(TSVAL_BASE * spacing);
}

/*
 * SET SCHED PRIORITY
 *
 * Sets the process' priority.  If priority is 0, setSchedPriority will set the
 * scheduling priority to the default used by most processes.  If priority is
 * non-zero, the result will be that this process will preempt most other
 * running processes.  priority must not be negative.
 *
 * Use ps to see the effect:
 *   ps -eo command,pid,policy,rtprio,pcpu
 */
int setSchedPriority(int priority)
{
    int rtn;
    struct sched_param param;

    if(priority < 0) {
        fprintf(stderr, "Priority cannot be negative!");
        return -1;
    }

    rtn = sched_getparam(0, &param);
    if(rtn < 0) {
        fprintf(stderr, "sched_getparam failed\n");
        return -1;
    }

    param.sched_priority = priority;
    const int policy = (priority == 0) ? SCHED_OTHER : SCHED_RR;

    rtn = sched_setscheduler(0, policy, &param);
    if(rtn < 0) {
        fprintf(stderr, "sched_setscheduler failed\n");
        return -1;
    }

    return 0;
}

int main(int argc, char *argv[])
{
    int result;

    srand(time(0));

    /* If running as root, we can set real-time priority for better accuracy
     * with inter-packet spacing. */
    if(getuid() == 0)
        setSchedPriority(1);

    result = parse_args(argc, argv);
    if(result < 0)
        exit(EXIT_FAILURE);

    if(mode < 0) {
        print_usage(argv[0]);
        return 1;
    }

    switch(mode) {
        case MODE_UP_SERVER:
            return upload_server_main();
        case MODE_UP_CLIENT:
            return upload_client_main();
        case MODE_DOWN_SERVER:
            return download_server_main();
        case MODE_DOWN_CLIENT:
            return download_client_main();
        case MODE_TCP_DOWN_SERVER:
            return tcp_download_server_main();
        case MODE_TCP_DOWN_CLIENT:
            return tcp_download_client_main();
    }

    return 0;
}

/*
 * Bind a socket to a specified network device.
 */
static int socket_bind_device(int sockfd, const char *device)
{
    assert(device);

    socklen_t option_len = strnlen(device, IFNAMSIZ);
    if(setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, device, option_len) < 0) {
        if(errno == EPERM || errno == EACCES)
            fprintf(stderr, "Error: binding to %s failed with permission denied, must be run with super user\n", device);
        else
            perror("SO_BINDTODEVICE");
        return -1;
    }

    return 0;
}

/*
 * Set the nonblocking flag on a socket.
 * Pass nonzero value to nonblocking to enable, or zero to disable.
 */
int socket_set_nonblocking(int sockfd, int nonblocking)
{
    int flags = fcntl(sockfd, F_GETFL);
    
    if(nonblocking) {
        flags |= O_NONBLOCK;
    } else {
        flags &= ~O_NONBLOCK;
    }

    int result = fcntl(sockfd, F_SETFL, flags);
    if(result < 0)
        perror("fcntl F_SETFL");

    return result;
}

/*
 * Get a timestamp for the last received packet.  Tries to use the most
 * accurate method available but falls back to another method if that fails.
 */
int recv_timestamp(int sockfd, struct timespec *ts)
{
    // Method gets incremented in the case of a failure, so that we fall back
    // to a working method without continuously retrying a failing method.
    static int method = 0;

    if(method == 0) {
        int result = ioctl(sockfd, SIOCGSTAMPNS, ts);
        if(result < 0) {
            perror("ioctl SIOCGSTAMPNS");
            method++;
        } else {
            return 0;
        }
    }

    return clock_gettime(CLOCK_REALTIME, ts);
}

/*
 * Server main function.
 */
int upload_server_main()
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
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    result = bind(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if(result < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }

    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    buffer = malloc(buffer_len);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    const char *format;
    if(csv_output) {
        printf("receiver_time,source_address,sport,session,sequence,bytes,sender_time,delay\n");
        format = "%d.%09d,%s,%s,%u,%u,%u,%d.%09d,%d.%09d\n";
    } else {
        printf("receiver_time        source_address  sport session    sequence   bytes      sender_time          delay      \n");
        format = "%10d.%09d %-15s %-5s %-10u %-10u %-10u %10d.%09d %1d.%09d\n";
    }

    while(1) {
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        result = recvfrom(sockfd, buffer, buffer_len, 0, 
                (struct sockaddr *)&from_addr, &from_addr_len);
        if(result < 0) {
            perror("recvfrom");
            return EXIT_FAILURE;
        } else {
            struct packet_info *info = (struct packet_info *)buffer;
            struct timespec received;

            recv_timestamp(sockfd, &received);

            char addrstr[INET6_ADDRSTRLEN];
            char portstr[6];

            getnameinfo((struct sockaddr *)&from_addr, from_addr_len, 
                    addrstr, sizeof(addrstr), 
                    portstr, sizeof(portstr),
                    NI_NUMERICHOST | NI_NUMERICSERV);

            printf(format,
                    received.tv_sec, received.tv_nsec,
                    addrstr, portstr,
                    ntohl(info->session), ntohl(info->seq), result,
                    ntohl(info->sent_sec), ntohl(info->sent_nsec),
                    ntohl(info->delay_sec), ntohl(info->delay_nsec));

            fflush(stdout);
        }
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

/*
 * Client main function.
 */
int upload_client_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    uint32_t next_seq = 0;
    uint32_t session = htonl(rand());

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
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    if(packet_interval < 0)
        packet_interval = compute_spacing(sending_rate, 8 * packet_length);
    
    if(time_limit < 0) {
        fprintf(stderr, "Warning: time_limit was not set, defaulting to %d seconds.\n", 
                DEFAULT_TIME_LIMIT);
        time_limit = apply_time_suffix(DEFAULT_TIME_LIMIT, 's');
    }

    struct timespec stop_time;
    clock_gettime(CLOCK_REALTIME, &stop_time);
    timespec_add(&stop_time, time_limit);
 
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);

    struct timespec delay;
    timespec_fill(packet_interval, &delay);

    while(1) {
        clock_gettime(CLOCK_REALTIME, &start);

        if(time_limit > 0 && timespec_after(&start, &stop_time))
            break;

        struct timespec actual_delay;
        timespec_sub(&start, &end, &actual_delay);

        struct packet_info *info = (struct packet_info *)buffer;
        info->session = session;
        info->seq = htonl(next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_nsec = htonl(start.tv_nsec);
        info->key = htonl(access_key);
        info->size = htonl(packet_length);
        info->delay_sec = htonl(actual_delay.tv_sec);
        info->delay_nsec = htonl(actual_delay.tv_nsec);

        result = sendto(sockfd, buffer, packet_length, 0,
                addrinfo->ai_addr, addrinfo->ai_addrlen);
        if(result < 0) {
            perror("sendto");
            return EXIT_FAILURE;
        }

        clock_gettime(CLOCK_REALTIME, &end);

        struct timespec sleep_time;
        timespec_sub(&end, &start, &sleep_time);
        timespec_sub(&delay, &sleep_time, &sleep_time);
        if(sleep_time.tv_sec >= 0)
            nanosleep(&sleep_time, NULL);
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

struct client_info *clients = NULL;

static void *dserver_send(void *arg)
{
    struct client_info *client = (struct client_info *)arg;

    char *buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }
    
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);

    struct timespec delay;
    timespec_fill(client->packet_interval, &delay);

    while(1) {
        clock_gettime(CLOCK_REALTIME, &start);
        
        struct timespec actual_delay;
        timespec_sub(&start, &end, &actual_delay);

        if(time_limit > 0 && timespec_after(&start, &client->timeout))
            goto out;

        struct packet_info *info = (struct packet_info *)buffer;
        info->session = htonl(client->session);
        info->seq = htonl(client->next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_nsec = htonl(start.tv_nsec);
        info->key = htonl(access_key);
        info->size = htonl(packet_length);
        info->delay_sec = htonl(actual_delay.tv_sec);
        info->delay_nsec = htonl(actual_delay.tv_nsec);

        int result = sendto(client->sockfd, buffer, packet_length, 0,
                (struct sockaddr *)&client->addr, client->addr_len);
        if(result < 0) {
            perror("sendto");
            goto out;
        }

        clock_gettime(CLOCK_REALTIME, &end);

        struct timespec sleep_time;
        timespec_sub(&end, &start, &sleep_time);
        timespec_sub(&delay, &sleep_time, &sleep_time);
        if(sleep_time.tv_sec >= 0)
            nanosleep(&sleep_time, NULL);
    }

out:
    free(buffer);
    
    HASH_DEL(clients, client);
    free(client);

    return NULL;
}

/*
 * Download Server main function.
 *
 * Listens for packets from clients and responds by sending a UDP packet stream
 * to the client.
 */
int download_server_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    int buffer_len = packet_length > PACKET_BUFFER_LEN ?
        packet_length : PACKET_BUFFER_LEN;
    unsigned next_session = 0;

    if(packet_interval < 0)
        packet_interval = compute_spacing(sending_rate, 8 * packet_length);

    if(time_limit == 0) {
        fprintf(stderr, "Warning: time_limit is set to zero, will send packets indefinitely.\n");
    } else if(time_limit < 0) {
        fprintf(stderr, "Warning: time_limit was not set, defaulting to %d seconds.\n", 
                DEFAULT_TIME_LIMIT);
        time_limit = apply_time_suffix(DEFAULT_TIME_LIMIT, 's');
    }

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
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    result = bind(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if(result < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    
    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    buffer = malloc(buffer_len);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    const char *format;
    if(csv_output) {
        printf("local_time,source_address,sport,session,next_seq\n");
        format = "%d.%09d,%s,%s,%u,%u";
    } else {
        printf("local_time           source_address  sport session    next_seq  \n");
        format = "%10d.%09d %-15s %-5s %-10u %-10u\n";
    }

    while(1) {
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        result = recvfrom(sockfd, buffer, buffer_len, 0,
                (struct sockaddr *)&from_addr, &from_addr_len);
        if(result < 0) {
            perror("recvfrom");
            return EXIT_FAILURE;
        } else {
            struct packet_info *info = (struct packet_info *)buffer;
            struct timespec received;
            struct sockaddr_storage key;

            if(ntohl(info->key) != access_key) {
                fprintf(stderr, "Client access key (%u) is incorrect.\n",
                        ntohl(info->key));
            } else {
                recv_timestamp(sockfd, &received);

                /* Copying the address this way ensures that the unused bytes are zero. */
                memset(&key, 0, sizeof(key));
                memcpy(&key, &from_addr, from_addr_len);

                struct client_info *client = NULL;
                HASH_FIND(hh, clients, &key, sizeof(key), client);

                if(!client) { 
                    client = malloc(sizeof(struct client_info));
                    if(!client) {
                        fprintf(stderr, "Out of memory\n");
                    } else {
                        memset(client, 0, sizeof(struct client_info));
                        memcpy(&client->addr, &from_addr, from_addr_len);
                        client->addr_len = from_addr_len;

                        getnameinfo((struct sockaddr *)&from_addr, from_addr_len, 
                                client->addrstr, sizeof(client->addrstr), 
                                client->portstr, sizeof(client->portstr),
                                NI_NUMERICHOST | NI_NUMERICSERV);

                        client->session = next_session++;
                        client->next_seq = 0;

                        client->sockfd = sockfd;
                        client->packet_interval = packet_interval;

                        HASH_ADD(hh, clients, addr, sizeof(client->addr), client);

                        pthread_t thread;
                        pthread_create(&thread, NULL, dserver_send, client);
                    }
                }

                if(client) {
                    clock_gettime(CLOCK_REALTIME, &client->timeout);
                    timespec_add(&client->timeout, time_limit);

                    printf(format,
                            received.tv_sec, received.tv_nsec, 
                            client->addrstr, client->portstr,
                            client->session, client->next_seq);

                    fflush(stdout);
                }
            }
        }
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

/*
 * Receive Client main function.
 */
int download_client_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    int buffer_len = packet_length > PACKET_BUFFER_LEN ?
        packet_length : PACKET_BUFFER_LEN;
    uint32_t next_seq = 0;
    uint32_t session = htonl(rand());

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
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    if(socket_set_nonblocking(sockfd, 1) < 0)
        return EXIT_FAILURE;
    
    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    if(packet_interval < 0)
        packet_interval = DEFAULT_DCLIENT_INTERVAL;

    struct timespec stop_time;
    clock_gettime(CLOCK_REALTIME, &stop_time);
    timespec_add(&stop_time, time_limit);
    
    const char *format;
    if(csv_output) {
        printf("receiver_time,session,sequence,bytes,sender_time,delay\n");
        format = "%d.%09d,%u,%u,%u,%d.%09d,%d.%09d\n";
    } else {
        printf("receiver_time        session    sequence   bytes      sender_time          delay      \n");
        format = "%10d.%09d %-10u %-10u %-10u %10d.%09d %1d.%09d\n";
    }

    struct timespec timeout;
    timeout.tv_sec = 0;
    timeout.tv_nsec = 0;

    struct timespec next_send;
    clock_gettime(CLOCK_REALTIME, &next_send);

    struct timespec delay;
    timespec_fill(packet_interval, &delay);

    while(1) {
        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);

        if(time_limit > 0 && timespec_after(&now, &stop_time))
            break;

        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        result = recvfrom(sockfd, buffer, buffer_len, 0, 
                (struct sockaddr *)&from_addr, &from_addr_len);
        if(result > 0) {
            struct packet_info *info = (struct packet_info *)buffer;
            struct timespec received;
            struct sockaddr_storage key;

            if(ntohl(info->key) != access_key) {
                fprintf(stderr, "Sender access key (%u) is incorrect.\n",
                        ntohl(info->key));
            } else {
                recv_timestamp(sockfd, &received);

                printf(format,
                        received.tv_sec, received.tv_nsec,
                        ntohl(info->session), ntohl(info->seq), result,
                        ntohl(info->sent_sec), ntohl(info->sent_nsec),
                        ntohl(info->delay_sec), ntohl(info->delay_nsec));

                fflush(stdout);
            }
        } else {
            if(errno != EWOULDBLOCK) {
                perror("recvfrom");
                return EXIT_FAILURE;
            }
        }

        struct timespec start;
        clock_gettime(CLOCK_REALTIME, &start);

        if(timespec_after(&start, &next_send)) {
            struct packet_info *info = (struct packet_info *)buffer;
            info->session = htonl(session);
            info->seq = htonl(next_seq++);
            info->sent_sec = htonl(start.tv_sec);
            info->sent_nsec = htonl(start.tv_nsec);
            info->key = htonl(access_key);
            info->size = htonl(packet_length);
            info->delay_sec = htonl(delay.tv_sec); // TODO: Measure the actual time since last send.
            info->delay_nsec = htonl(delay.tv_nsec);

            result = sendto(sockfd, buffer, sizeof(*info), 0,
                    addrinfo->ai_addr, addrinfo->ai_addrlen);
            if(result < 0) {
                perror("sendto");
            }

            next_send.tv_sec = start.tv_sec;
            next_send.tv_nsec = start.tv_nsec + packet_interval * NSECS_PER_USEC;

            next_send.tv_sec += next_send.tv_nsec / NSECS_PER_SEC;
            next_send.tv_nsec %= NSECS_PER_SEC;
        }

        clock_gettime(CLOCK_REALTIME, &now);

        timespec_sub(&next_send, &now, &timeout);
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

static void *tcp_dserver_send(void *arg)
{
    struct client_info *client = (struct client_info *)arg;

    char *buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }
    
    struct timespec start;
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end);

    struct timespec delay;
    timespec_fill(client->packet_interval, &delay);

    while(1) {
        clock_gettime(CLOCK_REALTIME, &start);
        
        struct timespec actual_delay;
        timespec_sub(&start, &end, &actual_delay);

        if(time_limit > 0 && timespec_after(&start, &client->timeout))
            goto out;

        struct packet_info *info = (struct packet_info *)buffer;
        info->session = htonl(client->session);
        info->seq = htonl(client->next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_nsec = htonl(start.tv_nsec);
        info->key = htonl(access_key);
        info->size = htonl(packet_length);
        info->delay_sec = htonl(actual_delay.tv_sec);
        info->delay_nsec = htonl(actual_delay.tv_nsec);

        int result = send(client->sockfd, buffer, packet_length, MSG_NOSIGNAL);
        if(result < 0) {
            perror("send");
            goto out;
        }

        clock_gettime(CLOCK_REALTIME, &end);

        struct timespec sleep_time;
        timespec_sub(&end, &start, &sleep_time);
        timespec_sub(&delay, &sleep_time, &sleep_time);
        if(sleep_time.tv_sec >= 0)
            nanosleep(&sleep_time, NULL);
    }

out:
    free(buffer);
    
    HASH_DEL(clients, client);
    close(client->sockfd);
    free(client);

    return NULL;
}

/*
 * Download Server main function.
 *
 * Listens for packets from clients and responds by sending a UDP packet stream
 * to the client.
 */
int tcp_download_server_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    char *buffer;
    int buffer_len = packet_length > PACKET_BUFFER_LEN ?
        packet_length : PACKET_BUFFER_LEN;
    unsigned next_session = 0;

    if(packet_interval < 0)
        packet_interval = compute_spacing(sending_rate, 8 * packet_length);

    if(time_limit == 0) {
        fprintf(stderr, "Warning: time_limit is set to zero, will send packets indefinitely.\n");
    } else if(time_limit < 0) {
        fprintf(stderr, "Warning: time_limit was not set, defaulting to %d seconds.\n", 
                DEFAULT_TIME_LIMIT);
        time_limit = apply_time_suffix(DEFAULT_TIME_LIMIT, 's');
    }

    snprintf(port_str, sizeof(port_str), "%d", server_port);

    const struct addrinfo hints = {
        .ai_flags = AI_PASSIVE | AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
    };

    result = getaddrinfo(NULL, port_str, &hints, &addrinfo);
    if(result < 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }

    result = bind(sockfd, addrinfo->ai_addr, addrinfo->ai_addrlen);
    if(result < 0) {
        perror("bind");
        return EXIT_FAILURE;
    }
    
    result = listen(sockfd, SOMAXCONN);
    if(result < 0) {
        perror("listen");
        return EXIT_FAILURE;
    }
    
    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    buffer = malloc(buffer_len);
    if(!buffer) {
        fprintf(stderr, "Out of memory.\n");
        return EXIT_FAILURE;
    }

    if(csv_output)
        printf("local_time,source_address,sport,session,next_seq\n");
    else
        printf("local_time           source_address  sport session    next_seq  \n");
        
    while(1) {
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        result = accept(sockfd, (struct sockaddr *)&from_addr, &from_addr_len);
        if(result > 0) {
            struct timespec received;
            struct sockaddr_storage key;

            recv_timestamp(sockfd, &received);

            /* Copying the address this way ensures that the unused bytes are zero. */
            memset(&key, 0, sizeof(key));
            memcpy(&key, &from_addr, from_addr_len);

            struct client_info *client = NULL;
            client = malloc(sizeof(struct client_info));
            if(!client) {
                fprintf(stderr, "Out of memory\n");
            } else {
                memset(client, 0, sizeof(struct client_info));
                memcpy(&client->addr, &from_addr, from_addr_len);
                client->addr_len = from_addr_len;

                getnameinfo((struct sockaddr *)&from_addr, from_addr_len, 
                        client->addrstr, sizeof(client->addrstr), 
                        client->portstr, sizeof(client->portstr),
                        NI_NUMERICHOST | NI_NUMERICSERV);

                client->session = next_session++;
                client->next_seq = 0;

                client->sockfd = result;
                client->packet_interval = packet_interval;
                
                clock_gettime(CLOCK_REALTIME, &client->timeout);
                timespec_add(&client->timeout, time_limit);

                HASH_ADD(hh, clients, addr, sizeof(client->addr), client);

                pthread_t thread;
                pthread_create(&thread, NULL, tcp_dserver_send, client);
            }
        }
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}

/*
 * If timeout is null, there is no timeout or it is the OS-implemented timeout.
 *
 * Side effect: if timeout is not null, sockfd will be set to non-blocking.
 */
int tcp_connect_timeout(int sockfd, struct sockaddr *addr, socklen_t addrlen,
        struct timespec *timeout)
{
    int result;

    if(timeout) {
        if(socket_set_nonblocking(sockfd, 1) < 0)
            return EXIT_FAILURE;
    }

    result = connect(sockfd, addr, addrlen);
    if(result < 0 && errno != EINPROGRESS) {
        perror("connect");
        return EXIT_FAILURE;
    }

    if(timeout) {
        fd_set write_set;
        FD_ZERO(&write_set);
        FD_SET(sockfd, &write_set);

        result = pselect(sockfd+1, NULL, &write_set, NULL, timeout, NULL);
        if(result < 0) {
            if(errno != EINTR)
                perror("select");
            return EXIT_FAILURE;
        } else if(result == 0) {
            // Timed out.
            return EXIT_FAILURE;
        }
    }

    return 0;
}

/*
 * Receive Client main function.
 */
int tcp_download_client_main()
{
    char port_str[16];
    int result;
    int sockfd;
    struct addrinfo *addrinfo;
    int buffer_len = packet_length > PACKET_BUFFER_LEN ?
        packet_length : PACKET_BUFFER_LEN;
    uint32_t next_seq = 0;
    uint32_t session = htonl(rand());

    snprintf(port_str, sizeof(port_str), "%d", server_port);

    const struct addrinfo hints = {
        .ai_flags = AI_NUMERICSERV,
        .ai_family = AF_UNSPEC,
        .ai_socktype = SOCK_STREAM,
        .ai_protocol = 0,
    };

    result = getaddrinfo(server_addr, port_str, &hints, &addrinfo);
    if(result < 0) {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
        return EXIT_FAILURE;
    }

    sockfd = socket(addrinfo->ai_family, addrinfo->ai_socktype, addrinfo->ai_protocol);
    if(sockfd < 0) {
        perror("socket");
        return EXIT_FAILURE;
    }
    
    if(bind_device)
        socket_bind_device(sockfd, bind_device);

    struct timespec timeout;
    struct timespec *ptimeout = NULL;

    if(connect_timeout > 0) {
        timespec_fill(connect_timeout, &timeout);
        ptimeout = &timeout;
    }

    result = tcp_connect_timeout(sockfd, addrinfo->ai_addr, 
            addrinfo->ai_addrlen, ptimeout);
    if(result == EXIT_FAILURE)
        return EXIT_FAILURE;

    if(packet_interval < 0)
        packet_interval = DEFAULT_DCLIENT_INTERVAL;

    const char *format;
    if(csv_output) {
        printf("receiver_time,session,sequence,bytes,sender_time,delay\n");
        format = "%d.%09d,%u,%u,%u,%d.%09d,%d.%09d\n";
    } else {
        printf("receiver_time        session    sequence   bytes      sender_time          delay      \n");
        format = "%10d.%09d %-10u %-10u %-10u %10d.%09d %1d.%09d\n";
    }

    struct timespec stop_time;
    clock_gettime(CLOCK_REALTIME, &stop_time);
    timespec_add(&stop_time, time_limit);

    struct rxbuff rxbuff;
    rxbuff_init(&rxbuff, buffer_len);

    ptimeout = NULL;

    while(1) {
        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        if(data_timeout > 0) {
            timespec_fill(data_timeout, &timeout);
            ptimeout = &timeout;
        }

        struct timespec now;
        clock_gettime(CLOCK_REALTIME, &now);

        if(time_limit > 0 && timespec_after(&now, &stop_time))
            break;

        result = pselect(sockfd+1, &read_set, NULL, NULL, ptimeout, NULL);
        if(result < 0) {
            perror("select");
            return EXIT_FAILURE;
        } else if(result == 0) {
            return EXIT_FAILURE;
        } else {
            result = recv(sockfd, rxbuff.write_buff, rxbuff.write_space, 0);
            if(result < 0) {
                perror("recv");
                return EXIT_FAILURE;
            }

            rxbuff_commit_write(&rxbuff, result);

            while(rxbuff.read_avail >= sizeof(struct packet_info)) {
                struct packet_info *info = (struct packet_info *)rxbuff.read_buff;
                struct timespec received;
                struct sockaddr_storage key;

                if(ntohl(info->key) != access_key) {
                    fprintf(stderr, "Sender access key (%u) is incorrect.\n",
                            ntohl(info->key));
                } else {
                    int size = ntohl(info->size);
                    if(size < sizeof(struct packet_info)) {
                        fprintf(stderr, "Bad\n");
                        return EXIT_FAILURE;
                    }

                    if(rxbuff.read_avail >= size) {
                        recv_timestamp(sockfd, &received);

                        printf(format,
                                received.tv_sec, received.tv_nsec,
                                ntohl(info->session), ntohl(info->seq), size,
                                ntohl(info->sent_sec), ntohl(info->sent_nsec),
                                ntohl(info->delay_sec), ntohl(info->delay_nsec));

                        fflush(stdout);

                        rxbuff_commit_read(&rxbuff, size);
                    } else {
                        break;
                    }
                }
            }
        }
    }

    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}


