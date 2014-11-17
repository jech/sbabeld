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
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/time.h>
#include <arpa/inet.h>

#include "util.h"

/* Like gettimeofday, but returns monotonic time.  If POSIX clocks are not
   available, falls back to gettimeofday but enforces monotonicity. */

int
gettime(struct timeval *tv)
{
    int rc;
    static time_t offset = 0, previous = 0;

#if defined(_POSIX_TIMERS) && _POSIX_TIMERS > 0 && defined(CLOCK_MONOTONIC)
    static int have_posix_clocks = -1;

    if(have_posix_clocks < 0) {
        struct timespec ts;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0) {
            have_posix_clocks = 0;
        } else {
            have_posix_clocks = 1;
        }
    }

    if(have_posix_clocks) {
        struct timespec ts;
        int rc;
        rc = clock_gettime(CLOCK_MONOTONIC, &ts);
        if(rc < 0)
            return rc;
        tv->tv_sec = ts.tv_sec;
        tv->tv_usec = ts.tv_nsec / 1000;
        return rc;
    }
#endif

    rc = gettimeofday(tv, NULL);
    if(rc < 0)
        return rc;
    tv->tv_sec += offset;
    if(previous > tv->tv_sec) {
        offset += previous - tv->tv_sec;
        tv->tv_sec = previous;
    }
    previous = tv->tv_sec;
    return rc;
}

/* Compare two timevals. */

int
timeval_compare(const struct timeval *s1, const struct timeval *s2)
{
    if(s1->tv_sec < s2->tv_sec)
        return -1;
    else if(s1->tv_sec > s2->tv_sec)
        return 1;
    else if(s1->tv_usec < s2->tv_usec)
        return -1;
    else if(s1->tv_usec > s2->tv_usec)
        return 1;
    else
        return 0;
}

/* Subtract two timevals. */

void
timeval_minus(struct timeval *d,
              const struct timeval *s1, const struct timeval *s2)
{
    if(s1->tv_usec >= s2->tv_usec) {
        d->tv_usec = s1->tv_usec - s2->tv_usec;
        d->tv_sec = s1->tv_sec - s2->tv_sec;
    } else {
        d->tv_usec = s1->tv_usec + 1000000 - s2->tv_usec;
        d->tv_sec = s1->tv_sec - s2->tv_sec - 1;
    }
}

/* Return s1 - s2, in ms, saturates at 0. */

unsigned
timeval_minus_msec(const struct timeval *s1, const struct timeval *s2)
{
    if(s1->tv_sec < s2->tv_sec)
        return 0;

    /* Avoid overflow. */
    if(s1->tv_sec - s2->tv_sec > 2000000)
        return 2000000000;

    if(s1->tv_sec > s2->tv_sec)
        return
            (unsigned)((unsigned)(s1->tv_sec - s2->tv_sec) * 1000 +
                       ((int)s1->tv_usec - s2->tv_usec) / 1000);

    if(s1->tv_usec <= s2->tv_usec)
        return 0;

    return (unsigned)(s1->tv_usec - s2->tv_usec) / 1000u;
}

/* Set d to s + msecs */

void
timeval_add_msec(struct timeval *d, const struct timeval *s, int msecs)
{
    int usecs;
    d->tv_sec = s->tv_sec + msecs / 1000;
    usecs = s->tv_usec + (msecs % 1000) * 1000;
    if(usecs < 1000000) {
        d->tv_usec = usecs;
    } else {
        d->tv_usec = usecs - 1000000;
        d->tv_sec++;
    }
}

/* Smaller of two timevals.  {0, 0} represents infinity */
void
timeval_min(struct timeval *d, const struct timeval *s)
{
    if(s->tv_sec == 0)
        return;

    if(d->tv_sec == 0 || timeval_compare(d, s) > 0) {
        *d = *s;
    }
}

/* Sleep for roughly the given time, in ms. */

void
nap(int ms)
{
    int usec = ms * 1000;
    if(usec <= 1)
        usec = 1;
    else
        usec = usec / 2 + rand() % usec;
    /* On some systems, usleep is limited to 1s. */
    if(usec >= 10000000)
        usec = 990000 + rand() % 10000;
    usleep(usec);
}

/* Return true if addr is a link-local IPv6 address. */

int
linklocal(const struct in6_addr *addr)
{
    unsigned char ll[8] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0};
    return(memcmp(addr, ll, 8) == 0);
}

/* Find out the link-local address of an interface.
   Please certify that you're a consenting adult before reading this code. */

int
get_local_address(const char *ifname, struct in6_addr *addr)
{
    char buf[100];
    int n, rc;
    FILE *pip;
    char *p;

    rc = snprintf(buf, 100,
                  "ip -6 addr show dev %s | "
                  "sed -n '/^ *inet6 \\([^ ]\\+\\)\\/64 scope link/s//\\1/p'",
                  ifname);
    if(rc < 0 || rc >= 100)
        return -1;

    pip = popen(buf, "r");
    if(pip == NULL)
        return -1;

    n = 0;
    while(n < 99) {
        rc = fread(buf + n, 1, 100 - n, pip);
        if(rc <= 0)
            break;
        n += rc;
    }
    buf[n] = '\0';
    pclose(pip);

    p = strchr(buf, ' ');
    if(p)
        *p = '\0';
    p = strchr(buf, '\n');
    if(p)
        *p = '\0';

    rc = inet_pton(AF_INET6, buf, addr);
    if(rc != 1)
        return -1;

    return 1;
}

/* Draw a random id, in modified EUI-64 format. */
void
random_eui64(unsigned char *eui64)
{
    int i;
    for(i = 0; i < 8; i++)
        eui64[i] = rand() & 0xFF;
    eui64[0] &= ~3;
}

/* Install or flush a default route. */

int
install_default_route(char *ifname, struct in6_addr *nexthop)
{
    char nh[INET6_ADDRSTRLEN], buf[100];
    int rc;

    if(nexthop) {
        if(inet_ntop(AF_INET6, nexthop, nh, 100) == NULL)
            return -1;

        rc = snprintf(buf, 100, "ip -6 route add default via %s dev %s",
                      nh, ifname);
        if(rc < 0 || rc >= 100)
            return -1;
    } else {
        rc = snprintf(buf, 100, "ip -6 route del default");
        if(rc < 0 || rc >= 100)
            return -1;
    }
    rc = system(buf);
    if(rc != 0)
        return -1;

    return 1;
}

/* Create a listening socket. */

int
babel_socket(int port)
{
    struct sockaddr_in6 sin6;
    int s, rc;
    int saved_errno;
    int one = 1, zero = 0;
    const int ds = 0xc0;        /* CS6 - Network Control */

    s = socket(PF_INET6, SOCK_DGRAM, 0);
    if(s < 0)
        return -1;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_LOOP,
                    &zero, sizeof(zero));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_UNICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

    rc = setsockopt(s, IPPROTO_IPV6, IPV6_MULTICAST_HOPS,
                    &one, sizeof(one));
    if(rc < 0)
        goto fail;

#ifdef IPV6_TCLASS
    rc = setsockopt(s, IPPROTO_IPV6, IPV6_TCLASS, &ds, sizeof(ds));
#else
    rc = -1;
    errno = ENOSYS;
#endif
    if(rc < 0)
        perror("Couldn't set traffic class");

    rc = fcntl(s, F_GETFL, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFL, (rc | O_NONBLOCK));
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_GETFD, 0);
    if(rc < 0)
        goto fail;

    rc = fcntl(s, F_SETFD, rc | FD_CLOEXEC);
    if(rc < 0)
        goto fail;

    memset(&sin6, 0, sizeof(sin6));
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    rc = bind(s, (struct sockaddr*)&sin6, sizeof(sin6));
    if(rc < 0)
        goto fail;

    return s;

 fail:
    saved_errno = errno;
    close(s);
    errno = saved_errno;
    return -1;
}

/* Receive a packet. */

int
babel_recv(int s, void *buf, int buflen, struct sockaddr *sin, int slen)
{
    struct iovec iovec;
    struct msghdr msg;
    int rc;

    memset(&msg, 0, sizeof(msg));
    iovec.iov_base = buf;
    iovec.iov_len = buflen;
    msg.msg_name = sin;
    msg.msg_namelen = slen;
    msg.msg_iov = &iovec;
    msg.msg_iovlen = 1;

    rc = recvmsg(s, &msg, 0);
    return rc;
}

/* Send a packet with the concatenation of buf1 and buf2. */

int
babel_send(int s,
           const void *buf1, int buflen1, const void *buf2, int buflen2,
           const struct sockaddr *sin, int slen)
{
    struct iovec iovec[2];
    struct msghdr msg;
    int rc;

    iovec[0].iov_base = (void*)buf1;
    iovec[0].iov_len = buflen1;
    iovec[1].iov_base = (void*)buf2;
    iovec[1].iov_len = buflen2;
    memset(&msg, 0, sizeof(msg));
    msg.msg_name = (struct sockaddr*)sin;
    msg.msg_namelen = slen;
    msg.msg_iov = iovec;
    msg.msg_iovlen = 2;

 again:
    rc = sendmsg(s, &msg, 0);
    if(rc < 0) {
        if(errno == EINTR)
            goto again;
        else if(errno == EAGAIN) {
            nap(10);
            rc = sendmsg(s, &msg, 0);
        }
    }
    return rc;
}

int
join_group(int sock, int ifindex, struct in6_addr *group)
{
    struct ipv6_mreq mreq;
    memset(&mreq, 0, sizeof(mreq));
    memcpy(&mreq.ipv6mr_multiaddr, group, 16);
    mreq.ipv6mr_interface = ifindex;
    return setsockopt(sock, IPPROTO_IPV6, IPV6_JOIN_GROUP,
                      (char*)&mreq, sizeof(mreq));
}

int
catch_signals(void (*handler)(int))
{
    struct sigaction sa;
    sigset_t ss;

    sigemptyset(&ss);
    sa.sa_handler = handler;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGTERM, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = handler;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGHUP, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = handler;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    sigemptyset(&ss);
    sa.sa_handler = SIG_IGN;
    sa.sa_mask = ss;
    sa.sa_flags = 0;
    sigaction(SIGPIPE, &sa, NULL);

    return 1;
}
