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

#if _WIN32
//#include "compat/wepoll.h"
//#include <Windows.h.>
//#include <winsock2.h>
//#include <ws2tcpip.h>
//#include <ws2ipdef.h>
//#include <iphlpapi.h>
#else
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <net/route.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <sys/epoll.h>
#include <net/if.h>

#define epoll_close(x) close(x)

#endif

#include "event.h"

#if _WIN32
// use same structure for every ipchange event for convenience
struct ipchange {
  uint32_t event;
  NET_LUID luid;
  NET_IFINDEX index;
  ADDRESS_FAMILY family;
  SOCKADDR_INET socket_address; // zeroed out on NotifyIpInterfaceChange
};

static inline int
read_ipchange(SOCKET fd, struct ipchange *change)
{
  int cnt, off = 0, len = sizeof(*change);
  uint8_t *buf = (uint8_t *)change;

  do {
    cnt = recv(fd, buf + off, len - off, 0);
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
write_ipchange(SOCKET fd, const struct ipchange *change)
{
  int cnt, off = 0, len = sizeof(*change);
  uint8_t *buf = (void *)change;

  do {
    cnt = send(fd, buf + (size_t)off, len, 0);
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

// registered as callback with NotifyUnicastIpAddressChange
static void
do_address_change(
  void *caller_context,
  MIB_UNICASTIPADDRESS_ROW *row,
  MIB_NOTIFICATION_TYPE notification_type)
{
  uint32_t event;
  struct ipchange change;

  assert(caller_context);

  if (!row) // initial notification, unused
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

  write_ipchange((SOCKET)caller_context, &change);
}

// registered as callback with NotifyIpInterfaceChange
static void
do_interface_change(
  void *caller_context,
  MIB_IPINTERFACE_ROW *row,
  MIB_NOTIFICATION_TYPE notification_type)
{
  struct ipchange change;

  assert(caller_context);

  if (!row) // initial notification, unused
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

  write_ipchange((SOCKET)caller_context, &change);
}

// use a SOCK_DGRAM socket pair to deal with partial writes
static int make_dgram_pipe(SOCKET pipefds[2])
{
  struct sockaddr_in addr;
  socklen_t addrlen = sizeof(addr);
  SOCKET fds[2] = { INVALID_SOCKET, INVALID_SOCKET };

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
  addr.sin_port = 0;
  if ((fds[0] = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
    goto err_socket_fd0;
  if (bind(fds[0], (struct sockaddr *)&addr, addrlen) == SOCKET_ERROR)
    goto err_bind;
  if (getsockname(fds[0], (struct sockaddr *)&addr, &addrlen) == SOCKET_ERROR)
    goto err_bind;
  if ((fds[1] = socket(AF_INET, SOCK_DGRAM, 0)) == INVALID_SOCKET)
    goto err_socket_fd1;
  if (connect(fds[1], (struct sockaddr *)&addr, addrlen) == -1)
    goto err_connect;
  // equivalent to FD_CLOEXEC
  SetHandleInformation((HANDLE) fds[0], HANDLE_FLAG_INHERIT, 0);
  SetHandleInformation((HANDLE) fds[1], HANDLE_FLAG_INHERIT, 0);
  pipefds[0] = fds[0];
  pipefds[1] = fds[1];
  return 0;
err_connect:
  closesocket(fds[1]);
err_socket_fd1:
err_bind:
  closesocket(fds[0]);
err_socket_fd0:
  return -1;
}

static void close_pipe(socket_t pipefd[2])
{
  closesocket(pipefd[0]);
  closesocket(pipefd[1]);
}

int create_ipchange_event(
  ipchange_event_t *event,
  ipchange_callback_t callback,
  uint32_t flags,
  void *user_data)
{
  SOCKET fds[2];
  HANDLE addr_hdl = NULL, iface_hdl = NULL;

  assert(event);

  // make self-pipe required by callbacks
  if (make_dgram_pipe(fds) == -1)
    goto err_pipe;

  // register callbacks that send a notifications over the self-pipe
  if (flags & (LINK_UP|LINK_DOWN)) {
    if (NO_ERROR != NotifyIpInterfaceChange(
      AF_UNSPEC, &do_interface_change, (void*)fds[1], false, &iface_hdl))
      goto err_iface;
  }

  if (flags & (IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED)) {
    bool ip4 = (flags & (IPV4_ADDED|IPV4_DELETED)) != 0;
    bool ip6 = (flags & (IPV6_ADDED|IPV6_DELETED)) != 0;
    ADDRESS_FAMILY af = (ip4 && ip6) ? AF_UNSPEC : (ip6 ? AF_INET6 : AF_INET);
    if (NO_ERROR != NotifyUnicastIpAddressChange(
      af, &do_address_change, (void*)fds[1], false, &addr_hdl))
      goto err_addr;
  }

  memset(event, 0, sizeof(*event));
  event->pipefds[0] = fds[0];
  event->pipefds[1] = fds[1];
  event->address_handle = addr_hdl;
  event->interface_handle = iface_hdl;
  event->callback = callback;
  event->event.source = IPCHANGE_EVENT;
  event->event.flags = flags;
  event->event.user_data = user_data;
  return 0;
err_addr:
  CancelMibChangeNotify2(addr_hdl);
err_iface:
  close_pipe(fds);
err_pipe:
  return -1;
}

static void destroy_ipchange_event(ipchange_event_t *event)
{
  if (!event)
    return;
  // cancel notifications
  if (event->address_handle)
    CancelMibChangeNotify2(event->address_handle);
  event->address_handle = NULL;
  if (event->interface_handle)
    CancelMibChangeNotify2(event->interface_handle);
  event->interface_handle = NULL;
  close_pipe(event->pipefds);
  event->pipefds[0] = INVALID_SOCKET;
  event->pipefds[1] = INVALID_SOCKET;
}

static int
proxy_ipchange_event(loop_t *loop, const ipchange_event_t *event)
{
  struct ipchange change;

  if (read_ipchange(event->pipefds[0], &change) != 0)
    abort(); // never happens, presumably

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

static SOCKET filedesc(ipchange_event_t *event)
{
  return event->pipefds[0];
}
#elif __linux__
// https://stackoverflow.com/questions/36347807/how-to-monitor-ip-address-change-using-rtnetlink-socket-in-go-language
// https://www.cs.cmu.edu/~srini/15-441/F01.full/www/assignments/P2/htmlsim_split/node20.html
// https://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch18lev1sec3.html
// https://www.masterraghu.com/subjects/np/introduction/unix_network_programming_v1.3/ch18.html

int create_ipchange_event(
  ipchange_event_t *event,
  ipchange_callback_t callback,
  uint32_t flags,
  void *user_data)
{
  int fd = -1;
  struct sockaddr_nl sa;

  assert(event);

  if ((fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE)) == -1)
    goto err_socket;
  memset(&sa, 0, sizeof(sa));
  sa.nl_family = AF_NETLINK;
  if (flags & (LINK_UP|LINK_DOWN))
    sa.nl_groups |= RTMGRP_LINK;
  if (flags & (IPV4_ADDED|IPV4_DELETED))
    sa.nl_groups |= RTMGRP_IPV4_IFADDR;
  if (flags & (IPV6_ADDED|IPV6_DELETED))
    sa.nl_groups |= RTMGRP_IPV6_IFADDR;
  if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    goto err_bind;
  memset(event, 0, sizeof(*event));
  event->socketfd = fd;
  event->callback = callback;
  event->event.source = IPCHANGE_EVENT;
  event->event.flags = flags;
  event->event.user_data = user_data;
  return 0;
err_bind:
  close(fd);
err_socket:
  return -1;
}

static void destroy_ipchange_event(ipchange_event_t *event)
{
  if (!event)
    return;
  close(event->socketfd);
}

// inspired by get_rtaddrs and parse_rtaddrs
static void
get_rtattrs(
  const struct rtattr *attrs,
  unsigned int len,
  const struct rtattr *rta_info[],
  unsigned int max)
{
  memset(rta_info, 0, sizeof(*attrs) * max);
  for (const struct rtattr *attr = attrs; RTA_OK(attr, len); attr = RTA_NEXT(attr, len)) {
    assert(attr->rta_type <= max);
    rta_info[attr->rta_type] = attr;
  }
}

static int
proxy_ipchange_event(loop_t *loop, const ipchange_event_t *event)
{
  int len, ret = 0;
  struct nlmsghdr buf[8192/sizeof(struct nlmsghdr)];
  struct iovec iov = { buf, sizeof(buf) };
  struct sockaddr_nl sa;
  struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
  len = recvmsg(event->socketfd, &msg, 0);

  for (struct nlmsghdr *nh = buf; ret == 0 && NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
    // end of multipart message
    if (nh->nlmsg_type == NLMSG_DONE)
      break;

    struct ifinfomsg *ifimsg = NLMSG_DATA(nh);

    switch (nh->nlmsg_type) {
      case RTM_NEWADDR:
      case RTM_DELADDR: {
        interface_t nic = { ifimsg->ifi_index };
        uint32_t flags = 0u;
        struct ifaddrmsg *ifamsg = NLMSG_DATA(nh);
        struct rtattr *rta_info[IFA_MAX + 1];
        get_rtattrs(IFA_RTA(ifamsg), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifamsg)), rta_info, IFA_MAX);
        struct sockaddr_storage saddr;
        void *rta_data = RTA_DATA(rta_info[IFA_ADDRESS]);
        if (ifamsg->ifa_family == AF_INET) {
          struct sockaddr_in *saddr_in = (struct sockaddr_in *)&saddr;
          flags = (nh->nlmsg_type == RTM_NEWADDR) ? IPV4_ADDED : IPV4_DELETED;
          saddr_in->sin_family = AF_INET;
          saddr_in->sin_port = 0;
          memcpy(&saddr_in->sin_addr, rta_data, sizeof(saddr_in->sin_addr));
        } else {
          struct sockaddr_in6 *saddr_in6 = (struct sockaddr_in6 *)&saddr;
          flags = (nh->nlmsg_type == RTM_NEWADDR) ? IPV6_ADDED : IPV6_DELETED;
          saddr_in6->sin6_family = AF_INET6;
          saddr_in6->sin6_port = 0;
          memcpy(&saddr_in6->sin6_addr, rta_data, sizeof(saddr_in6->sin6_addr));
        }

        ipchange_message_t msg = { &nic, &saddr };
        ret = event->callback(event, &msg, flags, event->event.user_data);
      } break;
      case RTM_NEWLINK:
      case RTM_DELLINK: {
        interface_t nic = { ifimsg->ifi_index };
        uint32_t flags = (ifimsg->ifi_flags & IFF_UP) ? LINK_UP : LINK_DOWN;

        ipchange_message_t msg = { &nic, NULL };
        ret = event->callback(event, &msg, flags, event->event.user_data);
      } break;
      default:
        break;
    }
  }

  return ret;
}

static int filedesc(ipchange_event_t *event)
{
  return event->socketfd;
}

static void close_pipe(int pipefds[2])
{
  close(pipefds[0]);
  close(pipefds[1]);
}
#endif

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

#if _WIN32
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
#elif __linux__
static int make_pipe(socket_t pipefds[2])
{
  return pipe(pipefds);
}
#endif

static inline int
add_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  struct epoll_event ev = { .events = EPOLLIN, { .ptr = event } };

  assert(loop);
  assert(event);
  if (epoll_ctl(loop->epollfd, EPOLL_CTL_ADD, filedesc(event), &ev) == -1)
    return -1;
  event->event.loop = loop;
  return 0;
}

static inline int
delete_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  epoll_ctl(loop->epollfd, EPOLL_CTL_DEL, filedesc(event), NULL);
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

  switch (event->source) {
    case IPCHANGE_EVENT:
      ret = add_ipchange_event(loop, (ipchange_event_t *)event);
      break;
    default:
      assert(event->source == SOCKET_EVENT);
      ret = add_socket_event(loop, (socket_event_t *)event);
      break;
  }

  atomic_inc32(&loop->events);
  return ret;
}

int delete_event(loop_t *loop, event_t *event)
{
  int ret = 0;

  assert(loop);
  assert(event);

  if (event->loop != loop)
    return -1;

  switch (event->source) {
    case IPCHANGE_EVENT:
      delete_ipchange_event(loop, (ipchange_event_t *)event);
      break;
    default:
      assert(event->source == SOCKET_EVENT);
      delete_socket_event(loop, (socket_event_t *)event);
      break;
  }

  atomic_dec32(&loop->events);
  return ret;
}

int create_loop(loop_t *loop)
{
  socket_t pipefds[2];
  socket_t epollfd;
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
  epoll_close(loop->epollfd);
}

int notify(loop_t *loop)
{
  char buf[] = { '\0' }; // FIXME: could send different bytes to trigger
                         //        different operations
  return send(loop->pipefds[1], buf, sizeof(buf), 0) == 1 ? 0 : -1;
}

int run(loop_t *loop, eventlist_t *list)
{
  int ret = 0;
  uint32_t blk = sizeof(list->events.fixed) / sizeof(list->events.fixed[0]);
  uint32_t cnt = atomic_ld32(&loop->events), len = 0;
  struct epoll_event *evs = NULL;

  if (list->length <= blk) /* eventlist has a fixed number of minimum slots */
    list->length = blk;

  if (cnt <= list->length) {
    len = list->length;
    evs = list->length <= blk ? list->events.fixed : list->events.dynamic;
  } else {
    len = (list->length / blk) + 1;
    if (!(evs = malloc(blk * sizeof(*list->events.dynamic))))
      return -1;
    if (list->length > blk)
      free(list->events.dynamic);
    list->events.dynamic = evs;
    list->length = len;
  }

  assert(evs);

  for (; ret == 0;) {
    int ready = epoll_wait(loop->epollfd, evs, list->length, -1);
    if (ready == -1) {
      return cnt; // error...
    }
    for (int i=0; i < ready; i++) {
      if (evs[i].data.ptr == (void*)loop) {
        char buf[1];
        cnt = recv(loop->pipefds[0], buf, sizeof(buf), 0);
        assert(cnt == 1);
        // level-triggered, so pending event will show up again
        break;
      } else {
        event_t *event = evs[i].data.ptr;
        switch (event->source) {
          case IPCHANGE_EVENT:
            ret = proxy_ipchange_event(loop, (ipchange_event_t *)event);
            break;
          default: {
            uint32_t flags = 0;
            assert(event->source == SOCKET_EVENT);
            if (evs[i].events & EPOLLIN)
              flags |= READ;
            if (evs[i].events & EPOLLOUT)
              flags |= WRITE;
            socket_event_t *socket_event = (socket_event_t *)event;
            ret = socket_event->callback(socket_event, flags, event->user_data);
          } break;
        }
      }
    }
  }

  return ret;
}
