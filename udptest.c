#include <assert.h>
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

#include "uthash.h"

#define PACKET_BUFFER_LEN 2048
#define USECS_PER_SEC 1000000

#define DEFAULT_DCLIENT_INTERVAL    1000000

/*
 * Measurement data sent in each UDP packet.
 */
struct packet_info {
    uint32_t session;
    uint32_t seq;
    uint32_t sent_sec;
    uint32_t sent_usec;
    uint32_t key;
} __attribute__((__packed__));

struct client_info {
    struct sockaddr_storage addr;
    socklen_t addr_len;

    char addrstr[INET6_ADDRSTRLEN];
    char portstr[6];

    time_t timeout;

    uint32_t session;
    uint32_t next_seq;

    int sockfd;
    long packet_interval;

    UT_hash_handle hh;
};

const char *OPTSTRING = "SCDRd:p:l:r:t:k:i:b:h";

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
    {.name = "help",    .has_arg = 0, .val = 'h'},
    {.name = 0,         .has_arg = 0, .val =  0},
};

enum {
    MODE_UP_SERVER,
    MODE_UP_CLIENT,
    MODE_DOWN_SERVER,
    MODE_DOWN_CLIENT,
};

/*
 * Command-line arguments that control program behavior.
 */
static int mode = -1;
static const char *server_addr = "127.0.0.1";
static int server_port = 5050;
static long packet_length = 1400;
static long sending_rate = 1000000;
static int time_limit = 15;
static unsigned access_key = 0;
static long packet_interval = -1;
static const char *bind_device = NULL;

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

static void print_usage(const char *cmd)
{
    printf("udptest is a powerful UDP bandwidth testing tool.\n");
    printf("Copyright (C) 2013 Lance Hartung\n");
    printf("\n");
    printf("Usage: %s <mode> [options]\n", cmd);
    printf("\n");
    printf("Modes:\n");
    printf("  --userver     Receiving server for upload test\n");
    printf("  --uclient     Sending client for upload test\n");
    printf("  --dserver     Sending server for download test\n");
    printf("  --dclient     Receiving client for download test\n");
    printf("\n");
    printf("Options:\n");
    printf("  --dest\n");
    printf("  --port\n");
    printf("  --length      Length of payload in data packets\n");
    printf("  --rate        Target bit rate (optionally append a suffix k, M, or G without a space)\n");
    printf("  --time        Time limit (in seconds)\n");
    printf("  --key         Authentication key to be used between dserver and dclient\n");
    printf("  --interval    Packet interval (overrides --rate)\n");
    printf("  --bind        Bind to device (super-user only)\n");
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
                packet_length = atoi(optarg);
                break;
            case 'r':
                sending_rate = parse_rate(optarg);
                if(sending_rate < 0) {
                    fprintf(stderr, "Invalid rate: %s\n", optarg);
                    return -1;
                }
                break;
            case 't':
                time_limit = atoi(optarg);
                break;
            case 'k':
                access_key = atoi(optarg);
                break;
            case 'i':
                packet_interval = strtol(optarg, NULL, 10);
                break;
            case 'b':
                bind_device = optarg;
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

    printf("receiver_time     source_address  sport session    sequence   bytes      sender_time\n");

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
            struct timeval received;

            gettimeofday(&received, NULL);

            char addrstr[INET6_ADDRSTRLEN];
            char portstr[6];

            getnameinfo((struct sockaddr *)&from_addr, from_addr_len, 
                    addrstr, sizeof(addrstr), 
                    portstr, sizeof(portstr),
                    NI_NUMERICHOST | NI_NUMERICSERV);

            printf("%10d.%06d %-15s %-5s %-10u %-10u %-10u %10d.%06d\n",
                    received.tv_sec, received.tv_usec,
                    addrstr, portstr,
                    ntohl(info->session), ntohl(info->seq), result,
                    ntohl(info->sent_sec), ntohl(info->sent_usec));
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
    time_t stop_sending;

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

    stop_sending = time(NULL) + time_limit;

    while(1) {
        struct timeval start;
        struct timeval end;
        long delay = packet_interval;

        if(time_limit >= 0 && time(NULL) >= stop_sending)
            break;

        gettimeofday(&start, NULL);

        struct packet_info *info = (struct packet_info *)buffer;
        info->session = session;
        info->seq = htonl(next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_usec = htonl(start.tv_usec);
        info->key = htonl(access_key);

        result = sendto(sockfd, buffer, packet_length, 0,
                addrinfo->ai_addr, addrinfo->ai_addrlen);
        if(result < 0) {
            perror("sendto");
            return EXIT_FAILURE;
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

struct client_info *clients = NULL;

static void *dserver_send(void *arg)
{
    struct client_info *client = (struct client_info *)arg;

    char *buffer = malloc(packet_length);
    if(!buffer) {
        fprintf(stderr, "Out of memory\n");
        return NULL;
    }

    while(1) {
        struct timeval start;
        struct timeval end;
        long delay = client->packet_interval;

        gettimeofday(&start, NULL);

        if(start.tv_sec > client->timeout)
            goto out;

        struct packet_info *info = (struct packet_info *)buffer;
        info->session = htonl(client->session);
        info->seq = htonl(client->next_seq++);
        info->sent_sec = htonl(start.tv_sec);
        info->sent_usec = htonl(start.tv_usec);
        info->key = htonl(access_key);

        int result = sendto(client->sockfd, buffer, packet_length, 0,
                (struct sockaddr *)&client->addr, client->addr_len);
        if(result < 0) {
            perror("sendto");
            goto out;
        }

        gettimeofday(&end, NULL);

        delay -= (end.tv_sec - start.tv_sec) * 1000000;
        delay -= (end.tv_usec - start.tv_usec);

        if(delay > 0)
            usleep(delay);
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

    if(packet_interval < 0)
        packet_interval = compute_spacing(sending_rate, 8 * packet_length);

    if(time_limit < 0) {
        fprintf(stderr, "Warning: time_limit is not set, will send packets indefinitely.\n");
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

    printf("local_time        source_address  sport session    next_seq  \n");
        
    struct timeval timeout;
    timeout.tv_sec = 1;
    timeout.tv_usec = 0;

    while(1) {
        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        result = select(sockfd + 1, &read_set, NULL, NULL, NULL);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            result = recvfrom(sockfd, buffer, buffer_len, 0, 
                    (struct sockaddr *)&from_addr, &from_addr_len);
            if(result < 0) {
                perror("recvfrom");
                return EXIT_FAILURE;
            } else {
                struct packet_info *info = (struct packet_info *)buffer;
                struct timeval received;
                struct sockaddr_storage key;

                if(ntohl(info->key) != access_key) {
                    fprintf(stderr, "Client access key (%u) is incorrect.\n",
                            ntohl(info->key));
                } else {
                    gettimeofday(&received, NULL);

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

                            /* Randomizing the session key is useful in the
                             * case where the connection is interrupted for
                             * longer than the timeout period, but the client
                             * has not realized that.  It informs the client
                             * that we have started a new session on our side. */
                            client->session = ntohl(info->session) ^ rand();
                            client->next_seq = 0;

                            client->sockfd = sockfd;
                            client->packet_interval = packet_interval;

                            HASH_ADD(hh, clients, addr, sizeof(client->addr), client);

                            pthread_t thread;
                            pthread_create(&thread, NULL, dserver_send, client);
                        }
                    }

                    if(client) {
                        client->timeout = time(NULL) + time_limit;

                        printf("%10d.%06d %-15s %-5s %-10u %-10u\n",
                                received.tv_sec, received.tv_usec, 
                                client->addrstr, client->portstr,
                                client->session, client->next_seq);
                        fflush(stdout);
                    }
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
    time_t stop_sending;

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
        packet_interval = DEFAULT_DCLIENT_INTERVAL;

    stop_sending = time(NULL) + time_limit;
    
    printf("receiver_time     session    sequence   bytes      sender_time\n");
    
    struct timeval timeout;
    timeout.tv_sec = 0;
    timeout.tv_usec = 0;

    struct timeval next_send;
    gettimeofday(&next_send, NULL);

    while(1) {
        if(time_limit >= 0 && time(NULL) >= stop_sending)
            break;

        struct sockaddr_storage from_addr;
        socklen_t from_addr_len = sizeof(from_addr);

        fd_set read_set;
        FD_ZERO(&read_set);
        FD_SET(sockfd, &read_set);

        result = select(sockfd + 1, &read_set, NULL, NULL, &timeout);
        if(result > 0 && FD_ISSET(sockfd, &read_set)) {
            result = recvfrom(sockfd, buffer, buffer_len, 0, 
                    (struct sockaddr *)&from_addr, &from_addr_len);
            if(result < 0) {
                perror("recvfrom");
                return EXIT_FAILURE;
            } else {
                struct packet_info *info = (struct packet_info *)buffer;
                struct timeval received;
                struct sockaddr_storage key;

                if(ntohl(info->key) != access_key) {
                    fprintf(stderr, "Sender access key (%u) is incorrect.\n",
                            ntohl(info->key));
                } else {
                    gettimeofday(&received, NULL);

                    printf("%10d.%06d %-10u %-10u %-10u %10d.%06d\n",
                            received.tv_sec, received.tv_usec,
                            ntohl(info->session), ntohl(info->seq), result,
                            ntohl(info->sent_sec), ntohl(info->sent_usec));
                    fflush(stdout);
                }
            }
        }

        struct timeval start;
        gettimeofday(&start, NULL);

        if(!timercmp(&start, &next_send, <)) {
            struct packet_info *info = (struct packet_info *)buffer;
            info->session = htonl(session);
            info->seq = htonl(next_seq++);
            info->sent_sec = htonl(start.tv_sec);
            info->sent_usec = htonl(start.tv_usec);
            info->key = htonl(access_key);

            result = sendto(sockfd, buffer, sizeof(*info), 0,
                    addrinfo->ai_addr, addrinfo->ai_addrlen);
            if(result < 0) {
                perror("sendto");
            }

            next_send.tv_sec = start.tv_sec;
            next_send.tv_usec = start.tv_usec + packet_interval;

            next_send.tv_sec += next_send.tv_usec / USECS_PER_SEC;
            next_send.tv_usec %= USECS_PER_SEC;
        }

        struct timeval now;
        gettimeofday(&now, NULL);

        if(timercmp(&next_send, &now, <)) {
            timersub(&next_send, &now, &timeout);
        } else {
            timeout.tv_sec = 0;
            timeout.tv_usec = 0;
        }
    }

    free(buffer);
    freeaddrinfo(addrinfo);
    close(sockfd);
    return 0;
}


