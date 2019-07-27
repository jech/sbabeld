/*
Copyright (c) 2014 by Juliusz Chroboczek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>
#include <assert.h>

#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>

#include "sbabeld.h"
#include "util.h"

/* The table of interfaces we're speaking on. */

struct interface {
    int ifindex;
    char *ifname;
    struct in6_addr address;    /* link-local address, or 0 if unknown */
    unsigned short seqno;       /* the seqno of the last Hello sent */
};

struct interface interfaces[MAXINTERFACES];
int numinterfaces = 0;

/* The table of known neighbours. */

struct neighbour {
    struct interface *interface;
    struct in6_addr address;    /* Link-local address of this neighbour. */
    unsigned short rxcost;      /* Its advertised rxcost. */
    struct timeval timeout;     /* When to discard this neighbour. */
};

struct neighbour neighbours[MAXNEIGHBOURS];
int numneighbours = 0;

/* The interval between periodic updates, in seconds. */
int update_interval = 20;

/* The time at which we last sent an update. */
struct timeval last_update = {0};

/* The interval between hellos, in seconds. */
int hello_interval = 4;

/* The time at which we last sent a hello. */
struct timeval last_hello = {0};

/* The cost of connected links. */
int link_cost = 256;

struct in6_addr babel_group;
unsigned short babel_port;

int have_prefix = 0;
unsigned char myprefix[16];
unsigned short myseqno;
unsigned char my_router_id[8];

/* The currently selected next hop. */

struct interface *selected_interface;
struct in6_addr selected_nexthop;
unsigned short selected_nexthop_metric = INFINITY;
struct timeval selected_nexthop_timeout = {0, 0};

/* Return the index of the given interface in the interface table. */
int
find_interface(int ifindex)
{
    int i;
    for(i = 0; i < numinterfaces; i++)
        if(interfaces[i].ifindex == ifindex)
            return i;

    return -1;
}

/* Delete the ith neithbour.  This invalidates all subsequent indices. */
int
delete_neighbour(int i)
{
    assert(i >= 0 && i < numneighbours);
    memmove(neighbours + i, neighbours + i + 1, numneighbours - i - 1);
    numneighbours--;
    return 1;
}

/* Return true if the ith neighbour has expired. */
int
neighbour_expired(int i, const struct timeval *now)
{
    return (timeval_compare(now, &neighbours[i].timeout) > 0);
}

/* Delete any neighbours that have expired. */
void
expire_neighbours()
{
    struct timeval now;
    int i = 0;

    gettime(&now);

    while(i < numneighbours) {
        if(neighbour_expired(i, &now) &&
           /* Don't delete the selected neighbour. */
           (selected_nexthop_metric == INFINITY ||
            neighbours[i].interface != selected_interface ||
            memcmp(&neighbours[i].address, &selected_nexthop, 16) != 0))
           delete_neighbour(i);
        else
            i++;
    }
}

/* Return the index of the given neighbour in the neighbours table.
   If none found, create a new neighbour if create is true.
   This may expire neighbours, so it potentially invalidates indices. */
int
find_neighbour(struct interface *interface, struct in6_addr *address,
               int create)
{
    int i;
    for(i = 0; i < numneighbours; i++) {
        if(neighbours[i].interface == interface &&
           memcmp(&neighbours[i].address, address, 16) == 0)
            return i;
    }

    if(!create)
        return -1;

    if(i >= MAXNEIGHBOURS)
        expire_neighbours();
    if(i >= MAXNEIGHBOURS)
        return -1;

    neighbours[i].interface = interface;
    memcpy(&neighbours[i].address, address, 16);
    neighbours[i].rxcost = INFINITY;
    memset(&neighbours[i].timeout, 0, sizeof(neighbours[i].timeout));
    numneighbours++;
    return i;
}

/* We got a Hello or IHU from a neighbour, update its entry. */
int
update_neighbour(struct in6_addr *from, struct interface *interface,
                 unsigned int ihu, unsigned short interval_or_rxcost)
{
    int i = find_neighbour(interface, from, !ihu);
    if(i < 0)
        return 0;

    if(ihu) {
        neighbours[i].rxcost = interval_or_rxcost;
    } else {
        struct timeval now;
        int interval = interval_or_rxcost;
        gettime(&now);
        /* We'll expire this neighbour if we miss 3 Hellos in a row. */
        timeval_add_msec(&neighbours[i].timeout, &now,
                         3 * interval * 10 + rand() % (interval * 5));
    }
    return 1;
}

/* Fill in a packet header and send a Babel packet. */

int
send_packet(int sock, int ifindex, struct in6_addr *to,
            unsigned char *body, unsigned char bodylen)
{
    struct sockaddr_in6 sin6;
    unsigned char header[4];

    header[0] = 42;
    header[1] = 2;
    DO_HTONS(header + 2, bodylen);

    /* Additional jitter never harms. */
    nap(10);

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    memcpy(&sin6.sin6_addr, &babel_group, 16);
    sin6.sin6_port = htons(babel_port);
    sin6.sin6_scope_id = ifindex;
    return babel_send(sock, header, 4, body, bodylen,
                      (struct sockaddr*)&sin6, sizeof(sin6));
}

/* Send a packet with a single Ack TLV. */

int
send_ack(int sock, struct interface *interface, struct in6_addr *to,
         unsigned char *nonce)
{
    unsigned char buf[4];
    buf[0] = MESSAGE_ACK;
    buf[1] = 2;
    memcpy(buf + 2, nonce, 2);
    /* Acks must be sent over unicast. */
    return send_packet(sock, interface->ifindex, to, buf, 4);
}

/* Send a Hello accompanied with a bunch of IHUs, one for each neighbour. */

int
send_hello(int sock, struct interface *interface)
{
    unsigned char buf[8 + 16 * MAXNEIGHBOURS];
    int i = 0, j;
    struct timeval now;

    /* Hello */
    buf[i] = MESSAGE_HELLO; i++; /* Type */
    buf[i] = 6; i++;            /* Length */
    DO_HTONS(buf + i, 0); i += 2;
    DO_HTONS(buf + i, interface->seqno); i += 2; /* Seqno */
    interface->seqno++;
    DO_HTONS(buf + i, hello_interval * 100); i += 2;  /* Interval */

    gettime(&now);
    for(j = 0; j < numneighbours; j++) {
        unsigned short cost;
        if(neighbours[j].interface != interface)
            continue;
        if(neighbour_expired(j, &now))
            cost = INFINITY;
        else
            cost = link_cost;

        /* IHU */
        buf[i] = MESSAGE_IHU; i++; /* Type */
        buf[i] = 14; i++;       /* Length */
        buf[i] = AE_LL; i++;    /* AE */
        buf[i] = 0; i++;
        DO_HTONS(buf + i, cost); i += 2; /* rxcost */
        DO_HTONS(buf + i, hello_interval * 100); i += 2; /* Interval */
        memcpy(buf + i, ((unsigned char *)(&neighbours[j].address)) + 8, 8);
        i += 8;                 /* Address */
    }

    assert((i - 8) % 16 == 0 && i - 8 <= 16 * numneighbours);

    return send_packet(sock, interface->ifindex, &babel_group, buf, i);
}

/* Send a single update or retraction. */
int
send_update(int sock, struct interface *interface, int retract)
{
    unsigned char buf[12 + 20];
    int i = 0;

    if(!have_prefix)
        /* Nothing to announce. */
        return 0;

    buf[i] = MESSAGE_ROUTER_ID; i++; /* Type */
    buf[i] = 10; i++;                /* Length */
    DO_HTONS(buf + i, 0); i += 2;
    memcpy(buf + i, my_router_id, 8); i += 8;

    buf[i] = MESSAGE_UPDATE; i++; /* Type */
    buf[i] = 18; i++;             /* Length */
    buf[i] = AE_IPV6; i++;        /* AE */
    buf[i] = 0; i++;              /* Flags */
    buf[i] = 64; i++;             /* Plen */
    buf[i] = 0; i++;              /* Omitted */
    DO_HTONS(buf + i, update_interval * 100); i+= 2; /* Interval */
    DO_HTONS(buf + i, myseqno); i += 2;              /* Seqno */
    DO_HTONS(buf + i, retract ? INFINITY : 0); i += 2; /* Metric */
    memcpy(buf + i, myprefix, 8); i += 8; /* Address */

    assert(i == 12 + 20);

    return send_packet(sock, interface->ifindex, &babel_group, buf, i);
}

/* Increment seqno by at most one in order to satisfy a request. */
int
increment_myseqno(unsigned short requested_seqno)
{
    unsigned short delta = (requested_seqno - myseqno) & 0xFFFF;
    if(delta == 1)
        myseqno = (myseqno + 1) & 0xFFFF;
    return myseqno;
}

/* Return true if id is the host-id of the interface's link-local address. */
int
address_match(unsigned char *id, struct interface *interface)
{
    unsigned char zeros[16] = {0};
    unsigned char ll[8] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};

    if(memcmp(&interface->address, zeros, 16) == 0)
        /* We're not performing reachability detection on this interface. */
        return 1;
    else if(memcmp(&interface->address, ll, 8) == 0 &&
            memcmp(((unsigned char*)&interface->address) + 8, id, 8) == 0)
        return 1;
    else
        return 0;
}

/* Flush the default route. */
int
flush_default_route()
{
    int rc;

    if(selected_nexthop_metric == INFINITY)
        return 0;

    rc = install_default_route(0, NULL);
    if(rc < 0) {
        perror("flush");
        /* But continue anyway -- there's not much we can do about it. */
    }

    selected_interface = NULL;
    memset(&selected_nexthop, 0, sizeof(selected_nexthop));
    selected_nexthop_metric = INFINITY;
    memset(&selected_nexthop_timeout, 0, sizeof(selected_nexthop_timeout));
    return 1;
}

/* We just got an Update for the default route. */
int
update_selected_route(struct interface *interface, struct in6_addr *nexthop,
                      short interval, int metric)
{
    struct timeval now;
    int n = find_neighbour(interface, nexthop, 0);

    if(n < 0)
        return 0;

    metric += MAX(link_cost, neighbours[n].rxcost);

    gettime(&now);

    if(selected_nexthop_metric >= INFINITY ||
       interface != selected_interface ||
       memcmp(nexthop, &selected_nexthop, sizeof(selected_nexthop)) != 0) {
        int rc;
        if(metric >= INFINITY ||
           (metric >= selected_nexthop_metric + 32 &&
            timeval_compare(&now, &selected_nexthop_timeout) < 0)) {
            /* Our currently selected route is just as good or better. */
            return 0;
        }

        rc = install_default_route(interface->ifindex, nexthop);
        if(rc < 0) {
            perror("install_default_route");
            return -1;
        }
        selected_interface = interface;
        memcpy(&selected_nexthop, nexthop, sizeof(selected_nexthop));
    }

    selected_nexthop_metric = metric;
    /* Expire this route when we lose 3 updates in a row. */
    timeval_add_msec(&selected_nexthop_timeout, &now,
                     3 * interval * 10 + rand() % (interval * 5));

    return 1;
}

/* Return 1 if found mandatory sub-TLV, -1 on error. */
int
check_tlv(const unsigned char *tlv, int l)
{
    int length = tlv[1];
    int i;

    if(length + 2 < l)
        return -1;

    i = l;
    while(i < length + 2) {
        int subl;
        if(tlv[i] == 0) {
            i++;
            continue;
        }
        subl = tlv[i + 1];
        if(i + 2 + subl > length + 2)
            return -1;
        if((tlv[i] & 0x80) != 0)
            return 1;
        i += subl + 2;
    }
    return 0;
}

/* The main function -- deal with a packet. */
int
handle_packet(int sock, unsigned char *packet, int packetlen,
              struct interface *interface, struct in6_addr *from)
{
    int bodylen, length, i;
    struct in6_addr nexthop;
    int have_nexthop = 0;

    if(!linklocal(from)) {
        fprintf(stderr, "Received non-link-local packet.\n");
        return -1;
    }

    if(packetlen < 4 || packet[0] != 42 || packet[1] != 2)
        goto fail;

    DO_NTOHS(bodylen, packet + 2);
    if(bodylen + 4 > packetlen)
        goto fail;

    i = 0;
    while(i < bodylen) {
        unsigned char *tlv = packet + 4 + i;
        unsigned int type;
        type = tlv[0];
        if(type == MESSAGE_PAD1) {
            i++;
            continue;
        }

        if(i + 1 > bodylen)
            goto fail;

        length = tlv[1];
        if(i + length > bodylen)
            goto fail;

#define CHECK(l) do { if(length + 2 < l) goto fail; } while(0)

#define CHECK_SUBTLV(l) do {                                    \
            int rc = check_tlv(tlv, l);                         \
            if(rc < 0)                                          \
                goto fail;                                      \
            else if(rc)                                         \
                goto skip;                                      \
        } while(0)

        switch(type) {
        case MESSAGE_ACK_REQ:
            CHECK_SUBTLV(8);
            send_ack(sock, interface, from, tlv + 4);
            break;
        case MESSAGE_HELLO: {
            unsigned short interval;
            CHECK_SUBTLV(8);
            DO_NTOHS(interval, tlv + 6);
            update_neighbour(from, interface, 0, interval);
            break;
        }
        case MESSAGE_IHU:
            CHECK(8);
            if(tlv[2] == AE_WILDCARD) {
                unsigned short rxcost;
                CHECK_SUBTLV(8);
                DO_NTOHS(rxcost, tlv + 4);
                update_neighbour(from, interface, 1, rxcost);
            } else if(tlv[2] == AE_LL) {
                CHECK_SUBTLV(16);
                if(address_match(tlv + 8, interface)) {
                    unsigned short rxcost;
                    DO_NTOHS(rxcost, tlv + 4);
                    update_neighbour(from, interface, 1, rxcost);
                }
            }
            break;
        case MESSAGE_NH:
            CHECK(4);
            if(tlv[2] == AE_LL) {
                unsigned char ll[8] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};
                CHECK(12);
                memcpy((unsigned char*)&nexthop, ll, 8);
                memcpy(((unsigned char*)&nexthop) + 8, tlv + 4, 8);
                have_nexthop = 1;
                CHECK_SUBTLV(12);
            } else if(tlv[2] == AE_IPV6) {
                CHECK(20);
                memcpy((unsigned char*)&nexthop, tlv + 4, 16);
                have_nexthop = 1;
                CHECK_SUBTLV(20);
            }
            break;
        case MESSAGE_UPDATE:
            CHECK(12);
            /* We're only interested in IPv6 default routes. */
            if(tlv[2] == AE_IPV6 && tlv[4] == 0) {
                unsigned short interval, metric;
                CHECK_SUBTLV(12);
                DO_NTOHS(interval, tlv + 6);
                DO_NTOHS(metric, tlv + 10);
                update_selected_route(interface,
                                      have_nexthop ? &nexthop : from,
                                      interval, metric);
            }
            break;
        case MESSAGE_REQUEST:
            CHECK(4);
            if(tlv[2] == AE_WILDCARD) {
                /* Request for a full table dump. */
                CHECK_SUBTLV(4);
                send_update(sock, interface, 0);
            } else if(tlv[2] == AE_IPV6 && tlv[3] == 64) {
                /* Request for a specific /64.  Is it ours? */
                CHECK_SUBTLV(12);
                if(have_prefix && memcmp(myprefix, tlv + 4, 8) == 0)
                    send_update(sock, interface, 0);
            }
            break;
        case MESSAGE_MH_REQUEST:
            CHECK(16);
            /* There's no such thing as a wildcard multi-hop request. */
            if(tlv[2] == AE_IPV6 && tlv[3] == 64) {
                unsigned int seqno;
                CHECK_SUBTLV(24);
                DO_NTOHS(seqno, tlv + 4);
                if(have_prefix &&
                   tlv[3] == 6 && memcmp(myprefix, tlv + 16, 8) == 0 &&
                   memcmp(tlv + 8, my_router_id, 8) == 0) {
                    increment_myseqno(seqno);
                    send_update(sock, interface, 0);
                }
            }
            break;
        default:
            /* We're ignoring all other TLVs. */
            break;
        }

    skip:
        i += length + 2;
    }
    return 1;

 fail:
    fprintf(stderr, "Received malformed packet.\n");
    return -1;
}

static int exiting = 0;

/* Our signal handler. */
void
sigexit(int signo)
{
    exiting = 1;
}

int
main(int argc, char **argv)
{
    int i, opt, rc;
    int sock;
    struct timeval now;

    gettime(&now);

    inet_pton(AF_INET6, "ff02::1:6", &babel_group);
    babel_port = 6696;

    srand(now.tv_sec ^ now.tv_usec);

    while(1) {
        opt = getopt(argc, argv, "p:u:h:c:");
        if(opt < 0)
            break;

        switch(opt) {
        case 'p':               /* prefix */
            if(have_prefix)
                goto usage;
            rc = inet_pton(AF_INET6, optarg, &myprefix);
            if(rc != 1)
                goto usage;
            have_prefix = 1;
            break;
        case 'u':               /* update interval */
            update_interval = atoi(optarg);
            if(update_interval <= 0)
                goto usage;
            break;
        case 'h':               /* hello interval */
            hello_interval = atoi(optarg);
            if(hello_interval <= 0)
                goto usage;
            break;
        case 'c':               /* link cost */
            link_cost = atoi(optarg);
            if(link_cost <= 0)
                goto usage;
            break;
        default:
            goto usage;
        }
    }

    if(!have_prefix)
        fprintf(stderr, "Warning: you didn't ask me to announce a prefix.\n");

    if(argc - optind > MAXINTERFACES) {
        fprintf(stderr, "Too many interfaces.\n");
        exit(1);
    }

    for(i = 0; i < argc - optind; i++) {
        int index;

        index = if_nametoindex(argv[optind + i]);
        if(index <= 0) {
            fprintf(stderr, "Unknown interface %s\n", argv[i]);
            exit(1);
        }
        memset(&interfaces[i], 0, sizeof(interfaces[i]));
        interfaces[i].ifindex = index;
        interfaces[i].ifname = argv[optind + i];
        rc = get_local_address(interfaces[i].ifindex, &interfaces[i].address);
        if(rc < 0) {
            perror("get_local_address");
            fprintf(stderr, "Continuing anyway -- "
                    "won't perform reachibility detection "
                    "on interface %s.\n", interfaces[i].ifname);
        }
        interfaces[i].seqno = rand() & 0xFFFF;
    }
    numinterfaces = argc - optind;

    random_eui64(my_router_id);
    myseqno = rand() & 0xFFFF;

    sock = babel_socket(babel_port);
    if(sock < 0) {
        perror("babel_socket");
        exit(1);
    }

    for(i = 0; i < numinterfaces; i++) {
        rc = join_group(sock, interfaces[i].ifindex, &babel_group);
        if(rc < 0) {
            perror("setsockopt(IPV6_JOIN_GROUP)");
            exit(1);
        }
    }

    catch_signals(sigexit);

    while(!exiting) {
        struct sockaddr_in6 sin6;
        unsigned char buf[BUF_SIZE];
        struct timeval tv, update, zerotv = {0, 0};
        fd_set readfds;
        int hello_count = 0;

        /* Compute when to wake up. */
        gettime(&now);
        timeval_add_msec(&tv, &last_hello, hello_interval * 700 + rand() % 300);
        timeval_add_msec(&update, &last_update,
                         update_interval * 700 + rand() % 300);
        timeval_min(&tv, &update);

        if(selected_nexthop_metric < INFINITY) {
            int n = find_neighbour(selected_interface, &selected_nexthop, 0);
            assert(n >= 0);
            timeval_min(&tv, &neighbours[n].timeout);
            timeval_min(&tv, &selected_nexthop_timeout);
        }

        if(timeval_compare(&tv, &now) > 0)
            timeval_minus(&tv, &tv, &now);
        else
            tv = zerotv;

        FD_ZERO(&readfds);
        FD_SET(sock, &readfds);

        rc = select(sock + 1, &readfds, NULL, NULL, &tv);
        if(rc < 0 && errno != EINTR) {
            perror("select");
            nap(1000);
            continue;
        }

        if(rc > 0) {
            /* Oh good, a packet. */
            socklen_t sin6len = sizeof(sin6);
            rc = recvfrom(sock, buf, BUF_SIZE, 0,
                          (struct sockaddr*)&sin6, &sin6len);

            if(rc < 0 || rc >= BUF_SIZE) {
                if(rc < 0 && errno != EAGAIN) {
                    perror("recv");
                    nap(100);
                }
                continue;
            }

            if(sin6.sin6_family != PF_INET6) {
                fprintf(stderr, "Received unexpected packet in family %d.\n",
                        sin6.sin6_family);
                nap(100);
                continue;
            }

            i = find_interface(sin6.sin6_scope_id);
            if(i < 0) {
                fprintf(stderr, "Received packet on unknown interface %d.\n",
                        sin6.sin6_scope_id);
                nap(100);
                continue;
            }
            handle_packet(sock, buf, rc, &interfaces[i], &sin6.sin6_addr);
        }

        gettime(&now);

        if(selected_nexthop_metric < INFINITY) {
            int n = find_neighbour(selected_interface, &selected_nexthop, 0);
            assert(n >= 0);

            if(neighbour_expired(n, &now)) {
                /* Expire neighbour. */
                flush_default_route();
                delete_neighbour(n);
            } else if(timeval_compare(&now, &selected_nexthop_timeout) > 0) {
                /* Expire route. */
                flush_default_route();
            }
            /* Send a request? */
        }

        /* Is it time to send hellos? */
        if(timeval_minus_msec(&now, &last_hello) > hello_interval * 700) {
            for(i = 0; i < numinterfaces; i++)
                send_hello(sock, &interfaces[i]);
            last_hello = now;
            hello_count++;
            /* Make an expiry pass every ten hellos. */
            if(hello_count >= 10) {
                expire_neighbours();
                hello_count = 0;
            }
        }

        /* Is it time to send an update? */
        if(timeval_minus_msec(&now, &last_update) > update_interval * 700) {
            for(i = 0; i < numinterfaces; i++)
                send_update(sock, &interfaces[i], 0);
            last_update = now;
        }
    }

    /* Send a bunch of retractions. */
    for(i = 0; i < numinterfaces; i++)
        send_update(sock, &interfaces[i], 1);

    flush_default_route();

    return 0;

 usage:
    fprintf(stderr,
            "Usage: sbabeld "
            "[-p prefix] [-u interval] [-h interval] [-c cost] interface...\n");
    return 1;
}
