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

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdio.h>

#include "compat/wepoll.h"

#include "event.h"
#include <Windows.h.>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ws2ipdef.h>
#include <iphlpapi.h>

int
create_socket_event(
  socket_event_t *event,
  socket_t socketfd,
  socket_callback_t callback,
  uint32_t flags,
  void *user_data)
{
  assert(event);
  assert(flags & (READ|WRITE));
  assert(callback);

  memset(event, 0, sizeof(*event));
  event->event.source = SOCKET_EVENT;
  event->event.flags = flags & (READ|WRITE);
  event->event.user_data = user_data;
  event->socketfd = socketfd;
  event->callback = callback;
  return 0;
}

static void
destroy_socket_event(socket_event_t *event)
{
  memset(event, 0, sizeof(*event));
}

/* use same structure for every ipchange event for convenience */
struct ipchange {
  uint32_t event;
  NET_LUID luid;
  NET_IFINDEX index;
  ADDRESS_FAMILY family;
  SOCKADDR_INET socket_address; /* zeroed out on NotifyIpInterfaceChange */
};

static inline int
read_ipchange(const ipchange_event_t *event, struct ipchange *change)
{
  int cnt, off = 0, len = sizeof(*change);
  uint8_t *buf = (uint8_t *)change;

  do {
    cnt = recv(event->pipefds[0], buf + off, len - off, 0);
    if (cnt == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
      continue;
    if (cnt == SOCKET_ERROR)
      return -1;
    assert(cnt >= 0);
    off += cnt;
  } while (off < len);

  assert(off == len);
  return 0;
}

static inline int
write_ipchange(ipchange_event_t *event, const struct ipchange *change)
{
  int cnt, off = 0, len = sizeof(*change);
  uint8_t *buf = (void *)change;

  do {
    cnt = send(event->pipefds[1], buf + (size_t)off, len, 0);
    if (cnt == SOCKET_ERROR && WSAGetLastError() == WSAEINTR)
      continue;
    if (cnt == SOCKET_ERROR)
      return -1;
    assert(cnt >= 0);
    off += cnt;
  } while (off < len);

  assert(off == len);
  return 0;
}

/* registered as callback with NotifyUnicastIpAddressChange */
static void
do_address_change(
  void *caller_context,
  MIB_UNICASTIPADDRESS_ROW *row,
  MIB_NOTIFICATION_TYPE notification_type)
{
  uint32_t event;
  struct ipchange change;

  assert(caller_context);

  if (!row) /* initial notification, unused */
    return;
  assert(notification_type != MibInitialNotification);
  if (notification_type == MibParameterNotification)
    return;

  if (row->Address.si_family == AF_INET6)
    event = notification_type == MibAddInstance ? IPV6_ADDED : IPV6_DELETED;
  else
    event = notification_type == MibAddInstance ? IPV4_ADDED : IPV4_DELETED;
  change.event = event;
  change.luid = row->InterfaceLuid;
  change.index = row->InterfaceIndex;
  change.family = row->Address.si_family;
  change.socket_address = row->Address;

  write_ipchange(caller_context, &change);
}

/* registered as callback with NotifyIpInterfaceChange */
static void
do_interface_change(
  void *caller_context,
  MIB_IPINTERFACE_ROW *row,
  MIB_NOTIFICATION_TYPE notification_type)
{
  struct ipchange change;

  assert(caller_context);

  if (!row) /* initial notification, unused */
    return;
  assert(notification_type != MibInitialNotification);
  if (notification_type == MibParameterNotification)
    return;

  change.event =
    notification_type == MibAddInstance ? LINK_UP : LINK_DOWN;
  change.luid = row->InterfaceLuid;
  change.index = row->InterfaceIndex;
  change.family = row->Family;
  memset(&change.socket_address, 0, sizeof(change.socket_address));

  write_ipchange(caller_context, &change);
}

int32_t
create_ipchange_event(
  ipchange_event_t *event,
  ipchange_callback_t callback,
  uint32_t flags,
  void *user_data)
{
  if (!event)
    return -1;

  /* callbacks registered when added because self-pipe is required */
  memset(event, 0, sizeof(*event));
  event->callback = callback;
  event->event.source = IPCHANGE_EVENT;
  event->event.flags = flags;
  event->event.user_data = user_data;
  return 0;
}

static void
destroy_ipchange_event(ipchange_event_t *event)
{
  if (!event)
    return;
}

static int
forward_ipchange_event(loop_t *loop, const ipchange_event_t *event)
{
  struct ipchange change;

  if (read_ipchange(event, &change) != 0)
    abort(); /* never happens, presumably */

  int ret;
  struct interface nic;
  struct ipchange_message msg = { &nic, NULL };

  nic.luid.Value = change.luid.Value;
  nic.index = change.index;
  if (change.event & (LINK_UP|LINK_DOWN)) {
    return event->callback(event, &msg, change.event, event->event.user_data);
  } else {
    assert(change.event & (IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED));
    msg.socket_address = (SOCKADDR *)&change.socket_address.Ipv4;
    return event->callback(event, &msg, change.event, event->event.user_data);
  }
}

void destroy_event(void *event)
{
  if (!event)
    return;

  switch (((event_t *)event)->source) {
    case IPCHANGE_EVENT:
      destroy_ipchange_event(event);
      break;
    default:
      assert(((event_t *)event)->source == SOCKET_EVENT);
      destroy_socket_event(event);
      break;
  }
}

static int make_pipe(socket_t pipefd[2])
{
  struct sockaddr_in addr;
  socklen_t asize = sizeof(addr);
  socket_t listener = socket(AF_INET, SOCK_STREAM, 0);
  socket_t s1 = socket(AF_INET, SOCK_STREAM, 0);
  socket_t s2 = INVALID_SOCKET;

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl (INADDR_LOOPBACK);
  addr.sin_port = 0;
  if (bind (listener, (struct sockaddr *)&addr, sizeof (addr)) == -1)
    goto fail;
  if (getsockname (listener, (struct sockaddr *)&addr, &asize) == -1)
    goto fail;
  if (listen (listener, 1) == -1)
    goto fail;
  if (connect (s1, (struct sockaddr *)&addr, sizeof (addr)) == -1)
    goto fail;
  if ((s2 = accept (listener, 0, 0)) == -1)
    goto fail;
  closesocket (listener);
  /* equivalent to FD_CLOEXEC */
  SetHandleInformation ((HANDLE) s1, HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation ((HANDLE) s2, HANDLE_FLAG_INHERIT, 0);
  pipefd[0] = s1;
  pipefd[1] = s2;
  return 0;

fail:
  closesocket (listener);
  closesocket (s1);
  closesocket (s2);
  return -1;
}

static void close_pipe(socket_t pipefd[2])
{
  closesocket(pipefd[0]);
  closesocket(pipefd[1]);
}

static inline int
add_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  socket_t fds[2];
  struct epoll_event ev = { .events = EPOLLIN, { .ptr = event } };
  HANDLE addr_hdl = NULL, iface_hdl = NULL;

  /* loop must be locked */

  assert(!event->address_handle);
  assert(!event->interface_handle);

  /* register callbacks that send a notification over a self-pipe */
  if (event->event.flags & (LINK_UP|LINK_DOWN)) {
    if (NO_ERROR != NotifyIpInterfaceChange(
      AF_UNSPEC, &do_interface_change, event, false, &iface_hdl))
      goto err_iface;
  }

  if (event->event.flags & (IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED)) {
    bool ip4 = (event->event.flags & (IPV4_ADDED|IPV4_DELETED)) != 0;
    bool ip6 = (event->event.flags & (IPV6_ADDED|IPV6_DELETED)) != 0;
    ADDRESS_FAMILY af = (ip4 && ip6) ? AF_UNSPEC : (ip6 ? AF_INET6 : AF_INET);
    if (NO_ERROR != NotifyUnicastIpAddressChange(
      af, &do_address_change, event, false, &addr_hdl))
      goto err_addr;
  }

  if (make_pipe(fds) == -1)
    goto err_pipe;
  if (epoll_ctl(loop->epollfd, EPOLL_CTL_ADD, fds[0], &ev) == -1)
    goto err_epoll;

  event->pipefds[0] = fds[0];
  event->pipefds[1] = fds[1];
  event->address_handle = addr_hdl;
  event->interface_handle = iface_hdl;
  event->event.loop = loop;
  return 0;
err_epoll:
  close_pipe(fds);
err_pipe:
  if (addr_hdl)
    CancelMibChangeNotify2(addr_hdl);
err_addr:
  if (iface_hdl)
    CancelMibChangeNotify2(iface_hdl);
err_iface:
  return -1;
}

static inline int
delete_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  /* cancel notifications */
  if (event->address_handle)
    CancelMibChangeNotify2(event->address_handle);
  event->address_handle = NULL;
  if (event->interface_handle)
    CancelMibChangeNotify2(event->interface_handle);
  event->interface_handle = NULL;
  epoll_ctl(loop->epollfd, EPOLL_CTL_DEL, event->pipefds[0], NULL);
  close_pipe(event->pipefds);
  event->pipefds[0] = INVALID_SOCKET;
  event->pipefds[1] = INVALID_SOCKET;
  event->event.loop = NULL;
  return 0;
}

static inline int
add_socket_event(loop_t *loop, socket_event_t *event)
{
  struct epoll_event ev = { .events = EPOLLIN, { .ptr = event } };

  if (epoll_ctl(loop->epollfd, EPOLL_CTL_ADD, event->socketfd, &ev) == -1)
    return -1;
  event->event.loop = loop;
  return 0;
}

static inline int
delete_socket_event(loop_t *loop, socket_event_t *event)
{
  epoll_ctl(loop->epollfd, EPOLL_CTL_DEL, event->socketfd, NULL);
  event->event.loop = NULL;
  return 0;
}

int add_event(loop_t *loop, event_t *event)
{
  int ret = 0;

  assert(loop);
  assert(event);

  if (event->loop)
    return event->loop == loop ? 0 : -1;

  //lock(loop);
  assert(loop->epollfd != NULL);

  switch (event->source) {
    case IPCHANGE_EVENT:
      ret = add_ipchange_event(loop, (ipchange_event_t *)event);
      break;
    default:
      assert(event->source == SOCKET_EVENT);
      ret = add_socket_event(loop, (socket_event_t *)event);
      break;
  }

  //unlock(loop);

  return ret;
}

int delete_event(loop_t *loop, event_t *event)
{
  int ret = 0;

  assert(loop);
  assert(event);

  if (event->loop != loop)
    return -1;

  //lock(loop);
  assert(loop->epollfd != NULL);

  switch (event->source) {
    case IPCHANGE_EVENT:
      delete_ipchange_event(loop, (ipchange_event_t *)event);
      break;
    default:
      assert(event->source == SOCKET_EVENT);
      delete_socket_event(loop, (socket_event_t *)event);
      break;
  }

  //unlock(loop);

  return ret;
}

int create_loop(loop_t *loop)
{
  SOCKET pipefds[2];
  HANDLE epollfd = NULL;
  struct epoll_event ev;

  assert(loop);

  if (make_pipe(pipefds) == -1)
    goto err_pipe;
  epollfd = epoll_create1(0); /* no supported flags on Windows */
  if (!epollfd)
    goto err_epollfd;
  ev.events = EPOLLIN;
  ev.data.ptr = loop;
  if (epoll_ctl(epollfd, EPOLL_CTL_ADD, pipefds[0], &ev) == -1)
    goto err_epoll_ctl;
  memset(loop, 0, sizeof(*loop));
  loop->pipefds[0] = pipefds[0];
  loop->pipefds[1] = pipefds[1];
  loop->epollfd = epollfd;
  //InitializeSRWLock(&loop->lock);
  return 0;
err_epoll_ctl:
  epoll_close(epollfd);
err_epollfd:
  close_pipe(pipefds);
err_pipe:
  return -1;
}

void destroy_loop(loop_t *loop)
{
  if (!loop)
    return;
  close_pipe(loop->pipefds);
  loop->pipefds[0] = INVALID_SOCKET;
  loop->pipefds[1] = INVALID_SOCKET;
  epoll_close(loop->epollfd);
  loop->epollfd = NULL;
  //memset(&loop->lock, 0, sizeof(loop->lock));
}

int notify(loop_t *loop)
{
  char buf[] = { '\0' }; // FIXME: could send different bytes to trigger
                         //        different operations
  return send(loop->pipefds[1], buf, sizeof(buf), 0) == 1 ? 0 : -1;
}

#define MAX_EVENTS (10)
int run(loop_t *loop)
{
  int cnt, err = 0;
  struct epoll_event events[MAX_EVENTS];

  for (; !err && !atomic_ld32(&loop->shutdown);) {
    int ready = epoll_wait(loop->epollfd, events, MAX_EVENTS, -1);
    if (ready == -1) {
      return cnt; // error...
    }
    for (int i=0; i < ready; i++) {
      if (events[i].data.ptr == (void*)loop) {
        char buf[1];
        cnt = recv(loop->pipefds[0], buf, sizeof(buf), 0);
        assert(cnt == 1);
        // level-triggered, so pending event will show up again
        break;
      } else {
        event_t *event = events[i].data.ptr;
        switch (event->source) {
          case IPCHANGE_EVENT:
            err = forward_ipchange_event(loop, (ipchange_event_t *)event);
            break;
          default: {
            uint32_t flags = 0;
            assert(event->source == SOCKET_EVENT);
            if (events[i].events & EPOLLIN)
              flags |= READ;
            if (events[i].events & EPOLLOUT)
              flags |= WRITE;
            socket_event_t *socket_event = (socket_event_t *)event;
            err = socket_event->callback(socket_event, flags, event->user_data);
          } break;
        }
      }
    }
  }

  return err;
}
