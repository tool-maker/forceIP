
#if 0
---------------------------------------------------------------------------

To build:

mkdir ~/forceIP
pushd ~/forceIP
# upload source for forceIP.c
gcc -nostartfiles -fpic -shared forceIP.c -o forceIP.so -ldl
ls -la
popd

Environment variables (all optional):

  fIP_TRACE        - trace all calls (set to anything)
  fIP_BINDADDR     - IPv4 address to force as source address for calls to "bind"
  fIP_BINDADDR6    - IPv6 address to force as source address for calls to "bind"
                     bind to localhost, 127.0.0.0, ::1 is left alone
  fIP_BINDLOCAL    - force bind source address for localhost too (set to anything)
  fIP_LISTENADDR   - IPv4 address to force as source address for calls to "listen"
  fIP_LISTENADDR6  - IPv6 address to force as source address for calls to "listen"
                     listen on localhost, 127.0.0.0, ::1 is left alone
  fIP_LISTENLOCAL  - force listen source address for localhost too (set to anything)
  fIP_CONNECTADDR  - IPv4 address to force as source address for calls to "connect", "sendto" and "sendmsg"
  fIP_CONNECTADDR6 - IPv6 address to force as source address for calls to "connect", "sendto" and "sendmsg"
                     connect to destination localhost, 127.0.0.0, ::1 is left alone
  fIP_DNSSKIP      - do not modify UDP packets with detination port 53 (DNS) (set to anything)

NOTE:

Since CONNECTADDR will not be the IP address of the default gateway
interface, you will need to set up source address routing.
For example:

/sbin/ip rule add from $CONNECTADDR table 19891
/sbin/ip route add default via $CONNECTGATEWAY table 19891

To test:

export LD_PRELOAD=~/forceIP/forceIP.so
export fIP_TRACE=yes
export fIP_BINDADDR=127.0.0.67
export fIP_BINDADDR6=::1
env | grep fIP_
netcat -l -p 32500
netcat -6 -l -p 32500

export LD_PRELOAD=~/forceIP/forceIP.so
export fIP_TRACE=yes
export fIP_CONNECTADDR=127.0.0.1
export fIP_CONNECTADDR6=::1
env | grep fIP_
ss -lutp | grep netcat
echo hello | netcat 127.0.0.67 32500
echo hello | netcat -6 ::1 32500

export LD_PRELOAD=~/forceIP/forceIP.so
export fIP_TRACE=yes
unset fIP_CONNECTADDR
unset fIP_CONNECTADDR6
env | grep fIP_
echo hello | netcat google.com 80
echo hello | netcat -6 google.com 80

---------------------------------------------------------------------------
#endif

#define _GNU_SOURCE

//#include <errno.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <resolv.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <ctype.h>

#define SHOW_LINE fprintf(stderr, "forceIP: at line %d\n", __LINE__);

#define ENTERED(name) fprintf(stderr, "forceIP: %s entered\n", #name);

#define error_case(e) case e: return #e;

int (*real_getaddrinfo)(
                const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res);
int (*real_bind)(int socket, const struct sockaddr *address, socklen_t address_len);
int (*real_listen)(int sockfd, int backlog);
int (*real_connect)(int socket, const struct sockaddr *address, socklen_t address_len);
int (*real_socket)(int domain, int type, int protocol);
ssize_t (*real_sendto)(int socket, const void *message, size_t length,
               int flags, const struct sockaddr *address, socklen_t address_len);
ssize_t (*real_sendmsg)(int socket, const struct msghdr *message, int flags);

__attribute__ ((constructor)) void forceIP_init(void) {

  const char *err;

  //ENTERED(forceIP_init)
  
  #define real_save(name) \
    real_##name = dlsym(RTLD_NEXT, #name); \
    if ((err = dlerror()) != NULL) { \
      fprintf(stderr, "forceIP_init: dlsym failed: %s\n", err); \
    }
  real_save(getaddrinfo)
  real_save(bind)
  real_save(listen)
  real_save(connect)
  real_save(socket)
  real_save(sendto)
  real_save(sendmsg)
  //SHOW_LINE

  //#define env_save(name)
}

__attribute__ ((destructor)) void forceIP_fini(void) {

  const char *err;

  //ENTERED(forceIP_fini)
}

int getaddrinfo(const char *node, const char *service,
                const struct addrinfo *hints,
                struct addrinfo **res) {
  const char *trace_all;
  //ENTERED(getaddrinfo)
  trace_all = getenv("fIP_TRACE");
  if (trace_all && trace_all[0] != '\0') {
    int ret;
    //SHOW_LINE
    fprintf(stderr, "forceIP: getaddrinfo entered for %s %s\n", node, service);
    //SHOW_LINE
    ret = real_getaddrinfo(node, service, hints, res);
    //SHOW_LINE
    fprintf(stderr, "forceIP: getaddrinfo exited for %s %s\n", node, service);
    //SHOW_LINE
    return ret;
  }
  //SHOW_LINE
  return real_getaddrinfo(node, service, hints, res);
}

#if 0 // left for posterity
int clearenv(void) {
  //ENTERED(clearenv)
  // do not clear environment when asked to
  return 0;
}
#endif // 0 - left for posterity
 
// return "family" code from socket address for socket (i.e. type of socket)
static sa_family_t getsockname_family(int socket) {

  int ret;
  sa_family_t sa_family;
  struct sockaddr *address;
  socklen_t address_len;

  // get length needed
  address = NULL;
  address_len = 0;
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    return AF_UNSPEC;
  }

  // get address
  address = malloc(address_len);
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    free(address);
    return AF_UNSPEC;
  }
  sa_family = address->sa_family;
  free(address);
  return sa_family;
}

#if 0 // https://man7.org/linux/man-pages/man2/socket.2.html

       The domain argument specifies a communication domain; this
       selects the protocol family which will be used for communication.
       These families are defined in <sys/socket.h>.  The formats
       currently understood by the Linux kernel include:

       Name         Purpose                                    Man page
       AF_UNIX      Local communication                        unix(7)
       AF_LOCAL     Synonym for AF_UNIX
       AF_INET      IPv4 Internet protocols                    ip(7)
       AF_AX25      Amateur radio AX.25 protocol               ax25(4)
       AF_IPX       IPX - Novell protocols
       AF_APPLETALK AppleTalk                                  ddp(7)
       AF_X25       ITU-T X.25 / ISO-8208 protocol             x25(7)
       AF_INET6     IPv6 Internet protocols                    ipv6(7)
       AF_DECnet    DECet protocol sockets
       AF_KEY       Key management protocol, originally
                    developed for usage with IPsec
       AF_NETLINK   Kernel user interface device               netlink(7)
       AF_PACKET    Low-level packet interface                 packet(7)
       AF_RDS       Reliable Datagram Sockets (RDS) protocol   rds(7)
                                                               rds-rdma(7)
       AF_PPPOX     Generic PPP transport layer, for setting
                    up L2 tunnels (L2TP and PPPoE)
       AF_LLC       Logical link control (IEEE 802.2 LLC)
                    protocol
       AF_IB        InfiniBand native addressing
       AF_MPLS      Multiprotocol Label Switching
       AF_CAN       Controller Area Network automotive bus
                    protocol
       AF_TIPC      TIPC, "cluster domain sockets" protocol
       AF_BLUETOOTH Bluetooth low-level socket protocol
       AF_ALG       Interface to kernel crypto API
       AF_VSOCK     VSOCK (originally "VMWare VSockets")       vsock(7)
                    protocol for hypervisor-guest
                    communication
       AF_KCM       KCM (kernel connection multiplexer)
                    interface
       AF_XDP       XDP (express data path) interface

#endif // https://man7.org/linux/man-pages/man2/socket.2.html

#if 0 // from /usr/include/x86_64-linux-gnu/bits/socket.h

/* Address families.  */
#define AF_UNSPEC       PF_UNSPEC
#define AF_LOCAL        PF_LOCAL
#define AF_UNIX         PF_UNIX
#define AF_FILE         PF_FILE
#define AF_INET         PF_INET
#define AF_AX25         PF_AX25
#define AF_IPX          PF_IPX
#define AF_APPLETALK    PF_APPLETALK
#define AF_NETROM       PF_NETROM
#define AF_BRIDGE       PF_BRIDGE
#define AF_ATMPVC       PF_ATMPVC
#define AF_X25          PF_X25
#define AF_INET6        PF_INET6
#define AF_ROSE         PF_ROSE
#define AF_DECnet       PF_DECnet
#define AF_NETBEUI      PF_NETBEUI
#define AF_SECURITY     PF_SECURITY
#define AF_KEY          PF_KEY
#define AF_NETLINK      PF_NETLINK
#define AF_ROUTE        PF_ROUTE
#define AF_PACKET       PF_PACKET
#define AF_ASH          PF_ASH
#define AF_ECONET       PF_ECONET
#define AF_ATMSVC       PF_ATMSVC
#define AF_RDS          PF_RDS
#define AF_SNA          PF_SNA
#define AF_IRDA         PF_IRDA
#define AF_PPPOX        PF_PPPOX
#define AF_WANPIPE      PF_WANPIPE
#define AF_LLC          PF_LLC
#define AF_IB           PF_IB
#define AF_MPLS         PF_MPLS
#define AF_CAN          PF_CAN
#define AF_TIPC         PF_TIPC
#define AF_BLUETOOTH    PF_BLUETOOTH
#define AF_IUCV         PF_IUCV
#define AF_RXRPC        PF_RXRPC
#define AF_ISDN         PF_ISDN
#define AF_PHONET       PF_PHONET
#define AF_IEEE802154   PF_IEEE802154
#define AF_CAIF         PF_CAIF
#define AF_ALG          PF_ALG
#define AF_NFC          PF_NFC
#define AF_VSOCK        PF_VSOCK
#define AF_KCM          PF_KCM
#define AF_QIPCRTR      PF_QIPCRTR
#define AF_SMC          PF_SMC
#define AF_XDP          PF_XDP
#define AF_MAX          PF_MAX

#endif // from /usr/include/x86_64-linux-gnu/bits/socket.h

static const char *family_str(sa_family_t family) {
  switch(family) {
    default: return "unknown";
    #define family_str_case(f) case f: return #f;
    family_str_case(AF_UNSPEC)
    //family_str_case(AF_LOCAL) // same as AF_UNIX
    family_str_case(AF_UNIX)
    //family_str_case(AF_FILE) // same as AF_UNIX
    family_str_case(AF_INET)
    family_str_case(AF_AX25)
    family_str_case(AF_IPX)
    family_str_case(AF_APPLETALK)
    family_str_case(AF_NETROM)
    family_str_case(AF_BRIDGE)
    family_str_case(AF_ATMPVC)
    family_str_case(AF_X25)
    family_str_case(AF_INET6)
    family_str_case(AF_ROSE)
    family_str_case(AF_DECnet)
    family_str_case(AF_NETBEUI)
    family_str_case(AF_SECURITY)
    family_str_case(AF_KEY)
    //family_str_case(AF_NETLINK) //same as AF_ROUTE
    family_str_case(AF_ROUTE)
    family_str_case(AF_PACKET)
    family_str_case(AF_ASH)
    family_str_case(AF_ECONET)
    family_str_case(AF_ATMSVC)
    family_str_case(AF_RDS)
    family_str_case(AF_SNA)
    family_str_case(AF_IRDA)
    family_str_case(AF_PPPOX)
    family_str_case(AF_WANPIPE)
    family_str_case(AF_LLC)
    family_str_case(AF_CAN)
    family_str_case(AF_TIPC)
    family_str_case(AF_BLUETOOTH)
    family_str_case(AF_IUCV)
    family_str_case(AF_RXRPC)
    family_str_case(AF_ISDN)
    family_str_case(AF_PHONET)
    family_str_case(AF_IEEE802154)
    family_str_case(AF_CAIF)
    family_str_case(AF_ALG)
    family_str_case(AF_NFC)
    family_str_case(AF_VSOCK)
    family_str_case(AF_MAX)
  }    
}

static const char *getnameinfo_error(int err) {
  switch(err) {
    default: return "unknown";
    error_case(EAI_AGAIN)
    error_case(EAI_BADFLAGS)
    error_case(EAI_FAIL)
    error_case(EAI_FAMILY)
    error_case(EAI_MEMORY)
    error_case(EAI_NONAME)
    error_case(EAI_OVERFLOW)
    error_case(EAI_SYSTEM)
  }    
}

#if 0 // https://man7.org/linux/man-pages/man2/socket.2.html

       The socket has the indicated type, which specifies the
       communication semantics.  Currently defined types are:

       SOCK_STREAM
              Provides sequenced, reliable, two-way, connection-based
              byte streams.  An out-of-band data transmission mechanism
              may be supported.

       SOCK_DGRAM
              Supports datagrams (connectionless, unreliable messages of
              a fixed maximum length).

       SOCK_SEQPACKET
              Provides a sequenced, reliable, two-way connection-based
              data transmission path for datagrams of fixed maximum
              length; a consumer is required to read an entire packet
              with each input system call.

       SOCK_RAW
              Provides raw network protocol access.

       SOCK_RDM
              Provides a reliable datagram layer that does not guarantee
              ordering.

       SOCK_PACKET
              Obsolete and should not be used in new programs; see
              packet(7).

#endif // https://man7.org/linux/man-pages/man2/socket.2.html

#if 0 // from /usr/include/x86_64-linux-gnu/bits/socket_type.h

/* Types of sockets.  */
enum __socket_type
{
  SOCK_STREAM = 1,              /* Sequenced, reliable, connection-based
                                   byte streams.  */
#define SOCK_STREAM SOCK_STREAM
  SOCK_DGRAM = 2,               /* Connectionless, unreliable datagrams
                                   of fixed maximum length.  */
#define SOCK_DGRAM SOCK_DGRAM
  SOCK_RAW = 3,                 /* Raw protocol interface.  */
#define SOCK_RAW SOCK_RAW
  SOCK_RDM = 4,                 /* Reliably-delivered messages.  */
#define SOCK_RDM SOCK_RDM
  SOCK_SEQPACKET = 5,           /* Sequenced, reliable, connection-based,
                                   datagrams of fixed maximum length.  */
#define SOCK_SEQPACKET SOCK_SEQPACKET
  SOCK_DCCP = 6,                /* Datagram Congestion Control Protocol.  */
#define SOCK_DCCP SOCK_DCCP
  SOCK_PACKET = 10,             /* Linux specific way of getting packets
                                   at the dev level.  For writing rarp and
                                   other similar things on the user level. */
#define SOCK_PACKET SOCK_PACKET

  /* Flags to be ORed into the type parameter of socket and socketpair and
     used for the flags parameter of paccept.  */

  SOCK_CLOEXEC = 02000000,      /* Atomically set close-on-exec flag for the
                                   new descriptor(s).  */
#define SOCK_CLOEXEC SOCK_CLOEXEC
  SOCK_NONBLOCK = 00004000      /* Atomically mark descriptor(s) as
                                   non-blocking.  */
#define SOCK_NONBLOCK SOCK_NONBLOCK
};

#endif // from /usr/include/x86_64-linux-gnu/bits/socket_type.h

// return "type" option of socket (i.e. type of socket)
static int getsockopt_type(int socket) {

  int ret;
  int type;
  socklen_t optlen;

  //int getsockopt(int sockfd, int level, int optname,
  //               void *optval, socklen_t *optlen);
                      
  // get type
  optlen = sizeof type;
  ret = getsockopt(socket, SOL_SOCKET, SO_TYPE, &type, &optlen);
  if (ret) {
    fprintf(stderr, "forceIP: getsockopt_type: getsockopt failed: bad return code\n");
    return 0;
  }
  if (optlen != sizeof type) {
    fprintf(stderr, "forceIP: getsockopt_type: getsockopt failed: bad buffer length\n");
    return 0;
  }

  return type;
}

static const char *type_str(int type) {
  switch(type) {
    default: return "unknown";
    #define type_str_case(f) case f: return #f;
    type_str_case(SOCK_STREAM)
    type_str_case(SOCK_DGRAM)
    type_str_case(SOCK_RAW)
    type_str_case(SOCK_RDM)
    type_str_case(SOCK_SEQPACKET)
    type_str_case(SOCK_DCCP)
    type_str_case(SOCK_PACKET)
    type_str_case(SOCK_CLOEXEC)
    type_str_case(SOCK_NONBLOCK)
  }    
}

// return string with address socket is bound to
static char *getsockname_str(int socket) {

  int ret;
  struct sockaddr *address;
  socklen_t address_len;
  char node[240];
  char service[20];

  // get length needed
  address = NULL;
  address_len = 0;
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    if (errno == EINVAL) return strdup("shut down");
    return strdup("could not get length");
  }

  // get address
  address = malloc(address_len);
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    free(address);
    return strdup("could not get address");
  }

  // get address and port as strings
  node[0] = 0;
  service[0] = 0;
  ret = getnameinfo(
          address, address_len, node, sizeof node, service, sizeof service,
          NI_NUMERICHOST | NI_NUMERICSERV);
  free(address);
  if (ret) {
    fprintf(stderr, "forceIP: getsockname_str: getnameinfo failed: %s %s\n", getnameinfo_error(ret), gai_strerror(ret));
    return strdup(getnameinfo_error(ret));
  }

  // append port to address and return
  if (service[0] != 0 && isprint(service[0])) {
    strncat(node, ":", sizeof node - 1 - strlen(node));
    strncat(node, service, sizeof node - 1 - strlen(node));
  }
  
  return strdup(node);
}

// return string with port socket is bound to
static char *getsockname_port_str(int socket) {

  int ret;
  struct sockaddr *address;
  socklen_t address_len;
  char service[20];

  // get length needed
  address = NULL;
  address_len = 0;
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    if (errno == EINVAL) return strdup("shut down");
    return strdup("could not get length");
  }

  // get address
  address = malloc(address_len);
  ret = getsockname(socket, address, &address_len);
  if (ret) {
    free(address);
    return strdup("could not get address");
  }

  // get port as string
  service[0] = 0;
  ret = getnameinfo(
          address, address_len, NULL, 0, service, sizeof service,
          NI_NUMERICSERV);
  free(address);
  if (ret) {
    fprintf(stderr, "forceIP: getsockname_port_str: getnameinfo failed: %s %s\n", getnameinfo_error(ret), gai_strerror(ret));
    return strdup(getnameinfo_error(ret));
  }

  return strdup(service);
}

// return address as string for socket address
static char *sockaddr_addr_str(const struct sockaddr *address, socklen_t address_len) {

  int ret;
  char node[240];

  //ENTERED(sockaddr_addr_str)

  node[0] = 0;
  //SHOW_LINE
  ret = getnameinfo(
          address, address_len, node, sizeof node, NULL, 0, NI_NUMERICHOST);
  //SHOW_LINE
  if (ret) {
    fprintf(stderr, "forceIP: sockaddr_addr_str: getnameinfo failed: %s %s %s %d\n",
            getnameinfo_error(ret), gai_strerror(ret), family_str(address->sa_family), (int)address_len);
    return strdup(getnameinfo_error(ret));
  }

  //fprintf(stderr, "forceIP: sockaddr_addr_str: getnameinfo succeeded\n");
  //fprintf(stderr, "forceIP: sockaddr_addr_str: finished\n");
  return strdup(node);
}

// return port for socket address
static char *sockaddr_port_str(const struct sockaddr *address, socklen_t address_len) {

  int ret;
  char node[240];

  //ENTERED(sockaddr_port_str)

  node[0] = 0;
  //SHOW_LINE
  ret = getnameinfo(
          address, address_len, NULL, 0, node, sizeof node, NI_NUMERICSERV);
  //SHOW_LINE
  if (ret) {
    fprintf(stderr, "forceIP: sockaddr_port_str: getnameinfo failed: %s %s %s %d\n",
            getnameinfo_error(ret), gai_strerror(ret), family_str(address->sa_family), (int)address_len);
    return strdup(getnameinfo_error(ret));
  }

  //fprintf(stderr, "forceIP: sockaddr_port_str: getnameinfo succeeded\n");
  //fprintf(stderr, "forceIP: sockaddr_port_str: finished\n");
  return strdup(node);
}

static const char *bind_error(int err) {
  switch(err) {
    default: return "unknown";
    error_case(EADDRINUSE)
    error_case(EADDRNOTAVAIL)
    error_case(EAFNOSUPPORT)
    error_case(EBADF)
    error_case(EINVAL)
    error_case(ENOTSOCK)
    error_case(EOPNOTSUPP)
    error_case(EACCES)
    error_case(EDESTADDRREQ)
    error_case(EISDIR)
    error_case(EIO)
    error_case(ELOOP)
    error_case(ENAMETOOLONG)
    error_case(ENOENT)
    error_case(ENOTDIR)
    error_case(EROFS)
    error_case(EISCONN)
  }    
}

#if 0 // left for posterity
int socket(int domain, int type, int protocol) {

  //ENTERED(socket)

  return real_socket(domain, type, protocol);
}
#endif // 0 - left for posterity

static const char *getaddrinfo_error(int err) {
  switch(err) {
    default: return "unknown";
    error_case(EAI_ADDRFAMILY)
    error_case(EAI_AGAIN)
    error_case(EAI_BADFLAGS)
    error_case(EAI_FAIL)
    error_case(EAI_FAMILY)
    error_case(EAI_MEMORY)
    error_case(EAI_NODATA)
    error_case(EAI_NONAME)
    error_case(EAI_SERVICE)
    error_case(EAI_SOCKTYPE)
    error_case(EAI_SYSTEM)
  }    
}

int bind(int socket, const struct sockaddr *address, socklen_t address_len) {

  int ret;
  char *arg_addr;
  char *arg_port;
  const char *trace_all;
  const char *bindaddr;
  sa_family_t family_socket;
  sa_family_t family_addr;

  //ENTERED(bind)

  family_socket = getsockname_family(socket);
  if (!address) family_addr = AF_UNSPEC;
  else family_addr = address->sa_family;
  //fprintf(stderr, "forceIP: bind called for family: %s\n", family_str(family_socket));

  // do not block/override for unsupported
  if (family_socket == AF_ROUTE) {
    return real_bind(socket, address, address_len);
  }

  #if 1
  // do not block/override for unsupported
  if (family_addr != AF_INET && family_addr != AF_INET6) {
    return real_bind(socket, address, address_len);
  }
  #endif

  if (family_addr != AF_INET && family_addr != AF_INET6) {
    arg_addr = strdup("non_INET");
    arg_port = strdup("0");
  }
  else {
    arg_addr = sockaddr_addr_str(address, address_len);
    arg_port = sockaddr_port_str(address, address_len);
  }

  trace_all = getenv("fIP_TRACE");
  if (trace_all && trace_all[0] != '\0') {
    fprintf(stderr, "forceIP: bind called for %s:%s %s %s %s\n",
            arg_addr, arg_port, family_str(family_socket), family_str(family_addr), type_str(getsockopt_type(socket)));
  }

  // do not block/override for unsupported
  if (0 == strncmp(arg_addr, "EAI_FAMILY", strlen("EAI_FAMILY"))) {
    fprintf(stderr, "forceIP: bind not blocking for unsupported family: %s %s\n",
            family_str(family_socket), family_str(family_addr));
    free(arg_addr);
    free(arg_port);
    return real_bind(socket, address, address_len);
  }

  if (family_socket == AF_INET6) {
    bindaddr = getenv("fIP_BINDADDR6");
  }
  else if (family_socket == AF_INET){
    bindaddr = getenv("fIP_BINDADDR");
  }
  
  if (bindaddr && bindaddr[0] != '\0') {

    int ret;
    int err;
    struct addrinfo *res;
  
    // don't override if the address is the same as ours
    if (0 == strncmp(arg_addr, bindaddr, strlen(bindaddr))) {
      free(arg_addr);
      free(arg_port);
      return real_bind(socket, address, address_len);
    }

    // do not block/override bind to localhost
    if ( 0
         || (0 == strncmp(arg_addr, "localhost", strlen("localhost")))
         || (0 == strncmp(arg_addr, "127.0.0.1", strlen("127.0.0.1")))
         || (0 == strncmp(arg_addr, "::1", strlen("::1")))
       ) {
      const char *bindlocal;
      bindlocal = getenv("fIP_BINDLOCAL");
      if (!bindlocal || bindlocal[0] == '\0') {
        fprintf(stderr, "forceIP: bind hook skipped for BINDADDR=%s with PORT=%s: original address was %s\n", bindaddr, arg_port, arg_addr);
        free(arg_addr);
        free(arg_port);
        return real_bind(socket, address, address_len);
      }
    }

    //SHOW_LINE
    ret = real_getaddrinfo(bindaddr, arg_port, NULL, &res);
    //SHOW_LINE
    if (ret) {
      fprintf(stderr, "forceIP: bind hook for BINDADDR=%s with PORT=%s: getaddrinfo failed: %s %s\n",
              bindaddr, arg_port, getaddrinfo_error(ret), gai_strerror(ret));
      free(arg_addr);
      free(arg_port);
      return real_bind(socket, address, address_len);
    }
    //SHOW_LINE
    ret = real_bind(socket, res->ai_addr, res->ai_addrlen);
    //SHOW_LINE
    err = errno;
    //SHOW_LINE
    if (ret) {
      if (err != EINVAL) {
        fprintf(stderr, "forceIP: bind hook for BINDADDR=%s with PORT=%s: bind failed: %s - %s\n", bindaddr, arg_port, bind_error(err), strerror(err));
      }
      else {
        char *socket_addr;
        char *info_addr;
        //SHOW_LINE
        socket_addr = getsockname_str(socket);
        //SHOW_LINE
        info_addr = sockaddr_addr_str(res->ai_addr, res->ai_addrlen);
        //SHOW_LINE
        if (strncmp(socket_addr, info_addr, strlen(info_addr))) {
          fprintf(stderr, "forceIP: bind hook for BINDADDR=%s with PORT=%s: bind failed: %s - %s\n", bindaddr, arg_port, bind_error(err), strerror(err));
          fprintf(stderr, "forceIP: bind hook: already bound address: %s does not match %s\n", socket_addr, info_addr);
        }
        //SHOW_LINE
        free(socket_addr);
        //SHOW_LINE
        free(info_addr);
        //SHOW_LINE
      }
      //SHOW_LINE
      freeaddrinfo(res);
      free(arg_addr);
      free(arg_port);
      return real_bind(socket, address, address_len);
    }
    fprintf(stderr, "forceIP: bind hook done for BINDADDR=%s with PORT=%s: original address was %s\n", bindaddr, arg_port, arg_addr);
    freeaddrinfo(res);
    free(arg_addr);
    free(arg_port);
    return ret;
  }
  
  return real_bind(socket, address, address_len);
}

// no point? must already be bound to specify port?
int listen(int socket, int backlog) {

  int ret;
  const char *trace_all;
  const char *listenaddr;
  sa_family_t family_socket;
  char *socket_addr;
  char *socket_port;

  //ENTERED(listen)

  family_socket = getsockname_family(socket);
  //fprintf(stderr, "forceIP: listen called for family: %s\n", family_str(family_socket));

  // do not block/override for unsupported
  if (family_socket == AF_ROUTE) {
    return real_listen(socket, backlog);
  }

  socket_addr = getsockname_str(socket);
  socket_port = getsockname_port_str(socket);

  trace_all = getenv("fIP_TRACE");
  if (trace_all && trace_all[0] != '\0') {
    fprintf(stderr, "forceIP: listen called for %s %s %s\n",
            socket_addr, family_str(family_socket), type_str(getsockopt_type(socket)));
  }

  // do not block/override for unsupported
  if (0 == strncmp(socket_addr, "EAI_FAMILY", strlen("EAI_FAMILY"))) {
    fprintf(stderr, "forceIP: listen not blocking for unsupported family: %s\n",
            family_str(family_socket));
    free(socket_addr);
    free(socket_port);
    return real_listen(socket, backlog);
  }

  if (family_socket == AF_INET6) {
    listenaddr = getenv("fIP_LISTENADDR6");
  }
  else if (family_socket == AF_INET) {
    listenaddr = getenv("fIP_LISTENADDR");
  }
  
  if (listenaddr && listenaddr[0] != '\0') {

    int ret;
    int err;
    struct addrinfo *res;
  
    // don't override if the bind address is the same as ours
    if (0 == strncmp(socket_addr, listenaddr, strlen(listenaddr))) {
      free(socket_addr);
      free(socket_port);
      return real_listen(socket, backlog);
    }
    
    // do not block/override listen to localhost
    if ( 0
         || (0 == strncmp(socket_addr, "localhost", strlen("localhost")))
         || (0 == strncmp(socket_addr, "127.0.0.1", strlen("127.0.0.1")))
         || (0 == strncmp(socket_addr, "::1", strlen("::1")))
       ) {
      const char *listenlocal;
      listenlocal = getenv("fIP_LISTENLOCAL");
      if (!listenlocal || listenlocal[0] == '\0') {
        fprintf(stderr, "forceIP: listen hook skipped for LISTENADDR=%s with PORT=%s: original address was %s\n", listenaddr, socket_port, socket_addr);
        free(socket_addr);
        free(socket_port);
        return real_listen(socket, backlog);
      }
    }
       
    //SHOW_LINE
    ret = real_getaddrinfo(listenaddr, socket_port, NULL, &res);
    //SHOW_LINE
    if (ret) {
      fprintf(stderr, "forceIP: listen hook for LISTENADDR=%s with PORT=%s: getaddrinfo failed: %s %s\n",
              listenaddr, socket_port, getaddrinfo_error(ret), gai_strerror(ret));
      free(socket_addr);
      free(socket_port);
      return real_listen(socket, backlog);
    }
    //SHOW_LINE
    ret = real_bind(socket, res->ai_addr, res->ai_addrlen);
    //SHOW_LINE
    err = errno;
    //SHOW_LINE
    if (ret) {
      if (err != EINVAL) {
        fprintf(stderr, "forceIP: listen hook for LISTENADDR=%s with PORT=%s: bind failed: %s - %s\n", listenaddr, socket_port, bind_error(err), strerror(err));
      }
      else {
        char *socket_addr;
        char *info_addr;
        //SHOW_LINE
        socket_addr = getsockname_str(socket);
        //SHOW_LINE
        info_addr = sockaddr_addr_str(res->ai_addr, res->ai_addrlen);
        //SHOW_LINE
        if (strncmp(socket_addr, info_addr, strlen(info_addr))) {
          fprintf(stderr, "forceIP: listen hook for LISTENADDR=%s with PORT=%s: bind failed: %s - %s\n", listenaddr, socket_port, bind_error(err), strerror(err));
          fprintf(stderr, "forceIP: listen hook: already bound address: %s does not match %s\n", socket_addr, info_addr);
        }
        //SHOW_LINE
        free(socket_addr);
        //SHOW_LINE
        free(info_addr);
        //SHOW_LINE
      }
      //SHOW_LINE
      freeaddrinfo(res);
      free(socket_addr);
      free(socket_port);
      return real_listen(socket, backlog);
    }
    fprintf(stderr, "forceIP: listen hook done for LISTENADDR=%s with PORT=%s: original address was %s\n", listenaddr, socket_port, socket_addr);
    freeaddrinfo(res);
    free(socket_addr);
    free(socket_port);
    return ret;
  }

  return real_listen(socket, backlog);
}

typedef enum{
  hcc_OK,
  hcc_failed,
  hcc_block
} hook_cc_t;
static hook_cc_t my_connect_hook(int socket, const struct sockaddr *address, socklen_t address_len, const char *context) {

  hook_cc_t my_ret = hcc_OK;
  int ret;
  int err;
  const char *trace_all;
  const char *DNS_skip;
  const char *connectaddr;
  struct addrinfo *res;
  char *arg_addr;
  char *arg_port;
  char *socket_addr;
  char *socket_port;
  sa_family_t family_socket;
  sa_family_t family_addr;

  //ENTERED(my_connect_hook)
  
  //fprintf(stderr, "forceIP: my_connect_hook entered from %s\n", context);

  family_socket = getsockname_family(socket);
  if (!address) family_addr = AF_UNSPEC;
  else family_addr = address->sa_family;
  //fprintf(stderr, "forceIP: my_connect_hook called for family: %s\n", family_str(family_socket));
  
  // do not block/override for unsupported
  if (family_socket == AF_ROUTE) {
    return hcc_OK;
  }
  //SHOW_LINE

  #if 1
  // do not block/override for unsupported
  if (family_addr != AF_INET && family_addr != AF_INET6) {
    return hcc_OK;
  }
  #endif

  if (family_addr != AF_INET && family_addr != AF_INET6) {
    arg_addr = strdup("non_INET");
    arg_port = strdup("0");
  }
  else {
    arg_addr = sockaddr_addr_str(address, address_len);
    arg_port = sockaddr_port_str(address, address_len);
  }
  socket_addr = getsockname_str(socket);
  socket_port = getsockname_port_str(socket);
  //fprintf(stderr, "forceIP: my_connect_hook getsockname done from %s\n", context);
  //SHOW_LINE

  trace_all = getenv("fIP_TRACE");
  if (trace_all && trace_all[0] != '\0') {
    fprintf(stderr, "forceIP: my_connect_hook: called from %s with %s for destination %s:%s %s %s %s\n",
            context, socket_addr, arg_addr, arg_port,
            family_str(family_socket), family_str(family_addr), type_str(getsockopt_type(socket)));
  }
  //SHOW_LINE

  // do not block/override for unsupported
  if (0 == strncmp(socket_addr, "EAI_FAMILY", strlen("EAI_FAMILY"))) {
    fprintf(stderr, "forceIP: my_connect_hook not blocking for unsupported family: %s\n", family_str(family_socket));
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }
  //SHOW_LINE

  DNS_skip = getenv("fIP_DNSSKIP");
  if (DNS_skip && DNS_skip[0] != '\0'
      && (0 == strcmp(arg_port, "53"))
      && (SOCK_DGRAM == getsockopt_type(socket))
     ) {
    // do not block/override for DNS UDP packets on port 53
    if (trace_all && trace_all[0] != '\0') {
      fprintf(stderr, "forceIP: my_connect_hook: skipped for UDP port 53 for destination %s\n", arg_addr);
    }
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }
  //SHOW_LINE

  // do not block/override for localhost
  if ( 0
       || (0 == strncmp(socket_addr, "localhost", strlen("localhost")))
       || (0 == strncmp(socket_addr, "127.0.0.1", strlen("127.0.0.1")))
       || (0 == strncmp(socket_addr, "::1", strlen("::1")))
     ) {
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }
  //SHOW_LINE

  // do not block/override for connect to localhost
  if ( 0
       || (0 == strncmp(arg_addr, "127.0.0.1", strlen("127.0.0.1")))
       || (0 == strncmp(arg_addr, "::1", strlen("::1")))
     ) {
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }
  //SHOW_LINE

  if (family_socket == AF_INET6) {
    connectaddr = getenv("fIP_CONNECTADDR6");
  }
  else if (family_socket == AF_INET) {
    connectaddr = getenv("fIP_CONNECTADDR");
  }
  if (!connectaddr || connectaddr[0] == '\0') {
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }
  //SHOW_LINE

  // don't override if the bind address is the same as ours
  if (0 == strncmp(socket_addr, connectaddr, strlen(connectaddr))) {
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_OK;
  }

  ret = real_getaddrinfo(connectaddr, socket_port, NULL, &res);
  if (ret) {
    fprintf(stderr, "forceIP: connect hook from %s for CONNECTADDR=%s with PORT=%s: getaddrinfo failed: %s %s\n",
            context, connectaddr, socket_port, getaddrinfo_error(ret), gai_strerror(ret));
    free(socket_addr);
    free(socket_port);
    free(arg_addr);
    free(arg_port);
    return hcc_failed;
  }
  //SHOW_LINE
  //fprintf(stderr, "forceIP: my_connect_hook getaddrinfo done from %s\n", context);
  ret = real_bind(socket, res->ai_addr, res->ai_addrlen);
  err = errno;
  //fprintf(stderr, "forceIP: my_connect_hook real_bind done from %s\n", context);
  if (ret) {
    //SHOW_LINE
    if (err != EINVAL) {
      my_ret = hcc_failed;
      fprintf(stderr, "forceIP: connect hook from %s=%s: bind failed: %s - %s\n", context, connectaddr, bind_error(err), strerror(err));
    }
    else {
      char *info_addr;
      //fprintf(stderr, "forceIP: my_connect_hook checking address from %s\n", context);
      info_addr = sockaddr_addr_str(res->ai_addr, res->ai_addrlen);
      //fprintf(stderr, "forceIP: my_connect_hook sockaddr_addr_str done from %s\n", context);
      if (strncmp(socket_addr, info_addr, strlen(info_addr))) {
        my_ret = hcc_block;
        fprintf(stderr, "forceIP: connect hook from %s=%s: bind failed: %s - %s\n", context, connectaddr, bind_error(err), strerror(err));
        fprintf(stderr, "forceIP: connect hook: blocked: already bound address: %s does not match %s\n", socket_addr, info_addr);
      }
      free(info_addr);
    }
    //SHOW_LINE
  }
  else {
    fprintf(stderr, "forceIP: connect hook done for CONNECTADDR=%s with destination %s:%s: original bind address was %s\n", connectaddr, arg_addr, arg_port, socket_addr);
  }
  //SHOW_LINE
  freeaddrinfo(res);
  free(socket_addr);
  free(socket_port);
  free(arg_addr);
  free(arg_port);
  //SHOW_LINE
  return my_ret;
}

int connect(int socket, const struct sockaddr *address, socklen_t address_len) {
  
  hook_cc_t ret;

  //ENTERED(connect)

  ret = my_connect_hook(socket, address, address_len, "connect");
  if (ret == hcc_OK) return real_connect(socket, address, address_len);
  if (ret == hcc_block) {
    // block
    //errno = EHOSTUNREACH;
    errno = ENETUNREACH;
  }
  else {
    // failed
    errno = EINVAL;
  }
  //SHOW_LINE
  return -1;
}

ssize_t sendto(int socket, const void *message, size_t length,
               int flags, const struct sockaddr *address, socklen_t address_len) {

  hook_cc_t ret;

  //ENTERED(sendto)

  // only do hook when socket type is SOCK_DGRAM?
  // must already be connected for SOCK_STREAM, SOCK_SEQPACKET

  ret = my_connect_hook(socket, address, address_len, "sendto");
  //ret = my_connect_hook(socket, "sendto", "fIP_SENDADDR");
  if (ret == hcc_OK) return real_sendto(socket, message, length, flags, address, address_len);
  if (ret == hcc_block) {
    // block
    //errno = EHOSTUNREACH;
    errno = ENETUNREACH;
  }
  else {
    // failed
    errno = EINVAL;
  }
  return -1;
}

// no point? this will call sendto?
ssize_t sendmsg(int socket, const struct msghdr *message, int flags) {

  hook_cc_t ret;

  //ENTERED(sendmsg)

  // only do hook when socket type is SOCK_DGRAM?
  // must already be connected for SOCK_STREAM, SOCK_SEQPACKET

  ret = my_connect_hook(socket, message->msg_name, message->msg_namelen, "sendmsg");
  //ret = my_connect_hook(socket, "sendmsg", "fIP_SENDADDR");
  if (ret == hcc_OK) return real_sendmsg(socket, message, flags);
  if (ret == hcc_block) {
    // block
    //errno = EHOSTUNREACH;
    errno = ENETUNREACH;
  }
  else {
    // failed
    errno = EINVAL;
  }
  return -1;
}
