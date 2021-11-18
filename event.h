/*
 * Copyright(c) 2021 ADLINK Technology Limited and others
 *
 * This program and the accompanying materials are made available under the
 * terms of the Eclipse Public License v. 2.0 which is available at
 * http://www.eclipse.org/legal/epl-2.0, or the Eclipse Distribution License
 * v. 1.0 which is available at
 * http://www.eclipse.org/org/documents/edl-v10.php.
 *
 * SPDX-License-Identifier: EPL-2.0 OR BSD-3-Clause
 */
#include <stdint.h>

#if _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include "compat/wepoll.h"
#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>

typedef SOCKET socket_t;
#else
# if __APPLE__ || __FreeBSD__
#include <sys/event.h>
# elif __linux__
#include <sys/epoll.h>
# endif
#include <netinet/in.h>
#include <arpa/inet.h>

typedef int socket_t;
#endif

#define READ (1u<<0)
#define WRITE (1u<<1)
#define IPV4_ADDED (1u<<2)
#define IPV4_DELETED (1u<<3)
#define IPV6_ADDED (1u<<4)
#define IPV6_DELETED (1u<<5)
#define LINK_UP (1u<<6)
#define LINK_DOWN (1u<<7)

/* types are not opaque to allow for static allocation */

typedef struct loop loop_t;
struct loop;

typedef struct event event_t;
struct event {
  enum {
    SOCKET_EVENT,
    IPCHANGE_EVENT
    /* more event sources to follow, e.g. TIMER_EVENT, SIGNAL_EVENT */
  } source; /**< source of event */
  uint32_t flags;
  const loop_t *loop; /**< pointer to loop with which event is registered */
  void *user_data;
};

void destroy_event(void *);

typedef struct socket_event socket_event_t;
typedef int32_t(*socket_callback_t)(const socket_event_t *, uint32_t, void *);
struct socket_event {
  event_t event;
  socket_callback_t callback;
  socket_t socketfd;
};

int create_socket_event(socket_event_t *, socket_t, socket_callback_t, uint32_t, void *);
void destroy_socket_event(socket_event_t *);

typedef struct ipchange_message ipchange_message_t;
struct ipchange_message;

typedef struct ipchange_event ipchange_event_t;
struct ipchange_event;
typedef int32_t(*ipchange_callback_t)(const ipchange_event_t *, ipchange_message_t *, uint32_t, void *);

/* an abstract notion of an interface identifier is required because of
   differences between operating systems. previously the interface name was
   used, but that caused problems on (at least) Windows because the name
   cannot be retreived if the interface is down. of course, getifaddrs must
   be updated to provide the same information */
typedef struct interface interface_t;
struct interface {
#if _WIN32
  NET_LUID luid;
  NET_IFINDEX index;
#elif __APPLE__
  uint32_t unit; // FIXME: rename to index
#elif __FreeBSD__
  unsigned short index;
#elif __linux__
  unsigned int index;
#endif
};

struct ipchange_message {
  const interface_t *interface;
  const struct sockaddr *socket_address; /**< socket address (if applicable) */
};

/* requires use of NotifyIpInterfaceChange and NotifyUnicastIpAddressChange.
   use self-pipe to receive asynchronous notifications in the same fashion on
   Unix and Windows */
struct ipchange_event {
  event_t event;
  ipchange_callback_t callback;
#if _WIN32
  HANDLE address_handle; /**< NotifyUnicastIpAddressChange handle */
  HANDLE interface_handle; /**< NotifyIpInterfaceChange handle */
  socket_t pipefds[2];
#else // __APPLE__ || __FreeBSD__ || __linux__
  socket_t socketfd;
#endif
};

int create_ipchange_event(ipchange_event_t *, ipchange_callback_t, uint32_t, void *);

typedef struct { uint32_t v; } atomic_uint32_t;

inline uint32_t atomic_ld32(const volatile atomic_uint32_t *a) { return a->v; }
inline void atomic_st32(volatile atomic_uint32_t *a, uint32_t v) { a->v = v; }
#if _MSC_VER
inline uint32_t atomic_inc32(volatile atomic_uint32_t *a) { return InterlockedIncrement(&a->v); }
inline uint32_t atomic_dec32(volatile atomic_uint32_t *a) { return InterlockedDecrement(&a->v); }
#else
inline uint32_t atomic_inc32(volatile atomic_uint32_t *a) { return __sync_add_and_fetch(&a->v, 1); }
inline uint32_t atomic_dec32(volatile atomic_uint32_t *a) { return __sync_sub_and_fetch(&a->v, 1); }
#endif

struct loop { /* size must be known for static allocation */
  socket_t pipefds[2]; /**< self-pipe used for triggering */
#if _WIN32 || __linux__
  atomic_uint32_t shutdown; // FIXME: perhaps make this a tri-state?!
  //SRWLOCK lock; // FIXME: do we need a lock in case of epoll?!
  socket_t epollfd;
#elif __APPLE__ || __FreeBSD__
  int kqueuefd;
#endif
  atomic_uint32_t events;
};

#define EVENTLIST_DELTA (8)

/* eventlist must be treated as an opaque structure. by removing the context
   from the loop structure, no additional locks are required to add or delete
   events */
typedef struct eventlist eventlist_t;
struct eventlist {
#if _WIN32 || __linux__ // << based on whether or not epoll is available
	                //    .. in this case we simply know windows and linux use it
  union {
    struct epoll_event fixed[EVENTLIST_DELTA];
    struct epoll_event *dynamic;
  } events;
#elif __APPLE__ || __FreeBSD__
  union {
    struct kevent fixed[EVENTLIST_DELTA];
    struct kevent *dynamic;
  } events;
#endif
  size_t length;
};

int create_loop(loop_t *);
void destroy_loop(loop_t *);
int add_event(loop_t *, event_t *);
int delete_event(loop_t *, event_t *);
int notify(loop_t *);
int run(loop_t *, eventlist_t *);
