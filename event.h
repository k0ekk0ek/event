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

// prototype implementation for Microsoft Windows
//
// Windows offers three (four?) flavours of event handling mechanisms.
//  1. select (or WSAPoll)
//  2. WSAWaitForMultipleEvents (WaitForMultipleObjects)
//  3. I/O Completion Ports
//  4. Windows Registered I/O
//
// select is notoriously slow on Windows, which is not a big problem if used
// for two udp sockets (discovery+data), but is a problem if tcp connections
// are used. WSAPoll is broken (1) up to Windows 10 version 2004 (2), which was
// released in May of 2020. WSAWaitForMultipleEvents is more performant, which
// is why it is used for Windows CE already, but only allows for
// WSA_MAXIMUM_WAIT_EVENTS (MAXIMUM_WAIT_OBJECTS, or 64) sockets to be polled
// simultaneously, which again may be a problem if tcp connections are used.
// select is also limited to 64 sockets unless FD_SETSIZE is defined to a
// higher number before including winsock2.h (3). For high-performance I/O
// on Windows, OVERLAPPED sockets in combination with I/O Completion Ports is
// recommended, but the interface is completely different from interfaces like
// epoll and kqueue (4). Zero byte receives can of course be used (5,6,7), but
// it seems suboptimal to do so(?) Asynchronous I/O, which is offered by the
// likes of I/O Completion Ports and io_uring, seems worthwile, but the
// changes seem a bit to substantial at this point.
//
// OPTION #5: wepoll, epoll for windows (8)
//
// wepoll implements the epoll API for Windows using the Ancillart Function
// Driver, i.e. Winsock. wepoll was developed by one of the libuv authors (9)
// and is used by libevent (10,11) and ZeroMQ (12).
//
// 1: https://daniel.haxx.se/blog/2012/10/10/wsapoll-is-broken/
// 2: https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsapoll
// 3: https://docs.microsoft.com/en-us/windows/win32/winsock/maximum-number-of-sockets-supported-2
// 4: https://sudonull.com/post/14582-epoll-and-Windows-IO-Completion-Ports-The-Practical-Difference
// 5: https://stackoverflow.com/questions/49970454/zero-byte-receives-purpose-clarification
// 6: https://stackoverflow.com/questions/10635976/iocp-notifications-without-bytes-copy
// 7: https://stackoverflow.com/questions/24434289/select-equivalence-in-i-o-completion-ports
// 8: https://github.com/piscisaureus/wepoll
// 9: https://news.ycombinator.com/item?id=15978372
// 10: https://github.com/libevent/libevent/pull/1006
// 11: https://libev.schmorp.narkive.com/tXCCS0na/better-windows-backend-using-wepoll
// 12: https://github.com/zeromq/libzmq/pull/3127

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>

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

typedef SOCKET socket_t;

typedef struct socket_event socket_event_t;
typedef int32_t(*socket_callback_t)(const socket_event_t *, uint32_t, void *);
struct socket_event {
  event_t event;
  socket_callback_t callback;
  socket_t socketfd;
};

int create_socket_event(socket_event_t *, socket_t, socket_callback_t, uint32_t, void *);

typedef struct ipchange_message ipchange_message_t;
struct ipchange_message;

typedef struct ipchange_event ipchange_event_t;
struct ipchange_event;
typedef int32_t(*ipchange_callback_t)(const ipchange_event_t *, ipchange_message_t *, uint32_t, void *);

struct ipchange_message {
  const char *interface; /**< interface name (NULL if interface is removed?) */
  const SOCKADDR *address; /**< socket address (on EV_IPV(4|6)_(ADD|DELETE), not EV_LINK_(UP|DOWN)) */
};

/* requires use of NotifyIpInterfaceChange and NotifyUnicastIpAddressChange.
   use self-pipe to receive asynchronous notifications in the same fashion on
   Unix and Windows */
struct ipchange_event {
  event_t event;
  ipchange_callback_t callback;
  HANDLE address_handle; /**< NotifyUnicastIpAddressChange handle */
  HANDLE interface_handle; /**< NotifyIpInterfaceChange handle */
  socket_t pipefds[2];
};

int create_ipchange_event(ipchange_event_t *, ipchange_callback_t, uint32_t, void *);

typedef struct { uint32_t v; } atomic_uint32_t;

inline uint32_t atomic_ld32(const volatile atomic_uint32_t *a) { return a->v; }
inline void atomic_st32(volatile atomic_uint32_t *a, uint32_t v) { a->v = v; }

typedef struct loop loop_t;
struct loop { /* size must be known for static allocation */
  SOCKET pipefds[2];
  atomic_uint32_t shutdown; // FIXME: perhaps make this a tri-state?!
  //SRWLOCK lock; // FIXME: do we need a lock in case of epoll?!
  HANDLE epollfd;
};

int create_loop(loop_t *);
void destroy_loop(loop_t *);
int add_event(loop_t *, event_t *);
int delete_event(loop_t *, event_t *);
int notify(loop_t *);
int run(loop_t *);
