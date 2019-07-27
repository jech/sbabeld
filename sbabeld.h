#define BUF_SIZE 4096

#define MAXINTERFACES 5
/* This must be chosen so that (48 + 12 + 16 * MAXNEIGHBOURS) is less than
   the smallest MTU. */
#define MAXNEIGHBOURS 10

#define MESSAGE_PAD1 0
#define MESSAGE_PADN 1
#define MESSAGE_ACK_REQ 2
#define MESSAGE_ACK 3
#define MESSAGE_HELLO 4
#define MESSAGE_IHU 5
#define MESSAGE_ROUTER_ID 6
#define MESSAGE_NH 7
#define MESSAGE_UPDATE 8

#define MESSAGE_REQUEST 9
#define MESSAGE_MH_REQUEST 10

#define AE_WILDCARD 0
#define AE_IPV4 1
#define AE_IPV6 2
#define AE_LL 3

#define INFINITY 0xFFFF

