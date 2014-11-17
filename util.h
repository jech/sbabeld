#define MIN(x, y) ((x) <= (y) ? x : y)
#define MAX(x, y) ((x) < (y) ? y : x)

#define DO_NTOHS(_d, _s)                        \
    do { short _dd; \
         memcpy(&(_dd), (_s), 2); \
         _d = ntohs(_dd); } while(0)
#define DO_HTONS(_d, _s) \
    do { unsigned short _dd; \
         _dd = htons(_s); \
         memcpy((_d), &(_dd), 2); } while(0)

int gettime(struct timeval *tv);
int timeval_compare(const struct timeval *s1, const struct timeval *s2);
void timeval_minus(struct timeval *d,
                   const struct timeval *s1, const struct timeval *s2);
void timeval_add_msec(struct timeval *d, const struct timeval *s, int msecs);
unsigned timeval_minus_msec(const struct timeval *s1, const struct timeval *s2);
void timeval_min(struct timeval *d, const struct timeval *s);
void nap(int ms);
int babel_socket(int port);
int linklocal(const struct in6_addr *addr);
int get_local_address(const char *ifname, struct in6_addr *addr);
void random_eui64(unsigned char *eui64);
int install_default_route(char *ifname, struct in6_addr *nexthop);
int babel_recv(int s, void *buf, int buflen, struct sockaddr *sin, int slen);
int babel_send(int s,
               const void *buf1, int buflen1, const void *buf2, int buflen2,
               const struct sockaddr *sin, int slen);
int join_group(int sock, int ifindex, struct in6_addr *group);
int catch_signals(void (*handler)(int));
