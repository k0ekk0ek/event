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

// prototype implementation for Apple macOS
//
// macOS offers a bunch of mechanisms for notification on address changes
//  1. System Configuration framework
//  2. IOKit
//  3. PF_ROUTE socket
//  4. PF_SYSTEM socket
//
// the System Configuration framework allows the user to create notification
// ports (not a mach_port_t), but a CFRunLoop is required and therefore seems
// primarily intented to be used in Cocoa applications. IOKit allows for
// creation of an IONotificationPortRef from which a mach_port_t can be
// retrieved and which can be monitored by kqueue with EVFILTER_MACH, but no
// notifications were received on IP address changes in tests. PF_ROUTE
// sockets are frequently used on BSD systems to monitor for changes to the
// routing database, but notifications were kind of a hit and miss in tests.
// PF_SYSTEM (1) sockets are provide exactly what is required.
//
// 1: http://newosxbook.com/bonus/vol1ch16.html

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#if __FreeBSD__
#include <sys/param.h>
#endif
#include <net/route.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <unistd.h>
#include <sys/event.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <fcntl.h>

#if __APPLE__
#include <sys/kern_event.h>
#include <netinet/in_var.h> // struct kev_in_data
#include <netinet6/in6_var.h> // struct kev_in6_data
#include <net/if_var.h> // struct net_event_data
#elif __FreeBSD__
#include <net/if.h>
#include <net/if_var.h>
#endif

#include "event.h"

int create_socket_event(
  socket_event_t *event,
  socket_t socket,
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
  event->socketfd = socket;
  event->callback = callback;
  return 0;
}

static void
destroy_socket_event(socket_event_t *event)
{
  memset(event, 0, sizeof(*event));
  event->socketfd = -1;
}

int create_ipchange_event(
  ipchange_event_t *event,
  ipchange_callback_t callback,
  uint32_t flags,
  void *user_data)
{
  int fd;

  assert(event);

#if __APPLE__
  struct kev_request req;
  if ((fd = socket(PF_SYSTEM, SOCK_RAW, SYSPROTO_EVENT)) == -1)
    goto err_socket;
  req.vendor_code = KEV_VENDOR_APPLE;
  req.kev_class = KEV_NETWORK_CLASS;
  req.kev_subclass = KEV_ANY_SUBCLASS;
  if (ioctl(fd, SIOCSKEVFILT, &req) == -1)
    goto err_ioctl;
#elif __FreeBSD__
  if ((fd = socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC)) == -1)
    goto err_socket;
#else
#error "Unsupported operating system"
#endif
  memset(event, 0, sizeof(*event));
  event->socketfd = fd;
  event->callback = callback;
  event->event.source = IPCHANGE_EVENT;
  event->event.flags = flags;
  event->event.user_data = user_data;
  return 0;
err_ioctl:
  (void)close(fd);
err_socket:
  return -1;
}

static void destroy_ipchange_event(ipchange_event_t *event)
{
  assert(event);
  close(event->socketfd);
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

int add_event(loop_t *loop, event_t *event)
{
  int fd = -1;
  struct kevent kev;
  unsigned short flags;

  assert(loop);
  assert(event);

  if (event->loop)
    return event->loop == loop ? 0 : -1;

  assert(loop->kqueuefd != -1);

  switch (event->source) {
    case IPCHANGE_EVENT:
      fd = ((ipchange_event_t *)event)->socketfd;
      flags = EVFILT_READ;
      break;
    default:
      assert(SOCKET_EVENT);
      fd = ((socket_event_t *)event)->socketfd;
      if (event->flags & READ)
        flags |= EVFILT_READ;
      if (event->flags & WRITE)
        flags |= EVFILT_WRITE;
      break;
  }

  EV_SET(&kev, fd, flags, EV_ADD, 0, 0, event);
  if (kevent(loop->kqueuefd, &kev, 1, NULL, 0, NULL) == -1)
    return -1;

  atomic_inc32(&loop->events);
  event->loop = loop;
  return 0;
}

int delete_event(loop_t *loop, event_t *event)
{
  int fd = -1;
  struct kevent kev;

  assert(loop);
  assert(event);

  if (event->loop != loop)
    return -1;

  assert(loop->kqueuefd != -1);

  switch (event->source) {
    case IPCHANGE_EVENT:
      fd = ((ipchange_event_t *)event)->socketfd;
      break;
    default:
      assert(event->source == SOCKET_EVENT);
      fd = ((socket_event_t *)event)->socketfd;
      break;
  }

  assert(fd != -1);
  EV_SET(&kev, fd, 0, EV_DELETE, 0, 0, NULL);
  if (kevent(loop->kqueuefd, &kev, 1, NULL, 0, NULL) == -1)
    return -1;

  atomic_dec32(&loop->events);
  event->loop = NULL;
  return 0;
}

int create_loop(loop_t *loop)
{
  int pipefds[2] = { -1, -1 };
  int kqueuefd = -1;
  struct kevent kev;

  assert(loop);

  if (pipe(pipefds) == -1)
    goto err_pipe;
  if ((kqueuefd = kqueue()) == -1)
    goto err_kqueue;
  if (fcntl(kqueuefd, F_SETFD, fcntl(kqueuefd, F_GETFD)|FD_CLOEXEC) == -1)
    goto err_fcntl;
  if (fcntl(pipefds[0], F_SETFD, fcntl(pipefds[0], F_GETFD)|FD_CLOEXEC) == -1)
    goto err_fcntl;
  if (fcntl(pipefds[1], F_SETFD, fcntl(pipefds[1], F_GETFD)|FD_CLOEXEC) == -1)
    goto err_fcntl;
  EV_SET(&kev, pipefds[0], EVFILT_READ, EV_ADD, 0, 0, loop);
  if (kevent(kqueuefd, &kev, 1, NULL, 0, NULL) == -1)
    goto err_kevent;

  loop->pipefds[0] = pipefds[0];
  loop->pipefds[1] = pipefds[1];
  loop->kqueuefd = kqueuefd;
  return 0;
err_events:
err_kevent:
err_fcntl:
  close(kqueuefd);
err_kqueue:
  close(pipefds[0]);
  close(pipefds[1]);
err_pipe:
  return -1;
}

void destroy_loop(loop_t *loop)
{
  if (!loop)
    return;
  close(loop->kqueuefd);
  close(loop->pipefds[1]);
  close(loop->pipefds[0]);
}

int notify(loop_t *loop)
{
  char buf[1] = { '\0' };
  return write(loop->pipefds[1], buf, sizeof(buf)) == 1 ? 0 : -1;
}

#if __APPLE__
static inline int inet_event(
  loop_t *loop,
  ipchange_event_t *event,
  const struct kern_event_msg *kev,
  uint32_t flags)
{
  struct kev_in_data *in_data = (struct kev_in_data *)kev->event_data;
  interface_t nic;
  struct sockaddr_in sin;
  ipchange_message_t msg;

  nic.unit = in_data->link_data.if_unit;
  sin.sin_family = AF_INET;
  assert(sizeof(sin.sin_addr) == sizeof(in_data->ia_addr));
  memcpy(&sin.sin_addr, &in_data->ia_addr, sizeof(sin.sin_addr));
  sin.sin_port = 0;
  msg.interface = &nic;
  msg.socket_address = (const struct sockaddr *)&sin;
  return event->callback(event, &msg, flags, event->event.user_data);
}

static inline int inet6_event(
  loop_t *loop,
  ipchange_event_t *event,
  const struct kern_event_msg *kev,
  uint32_t flags)
{
  struct kev_in6_data *in6_data = (struct kev_in6_data *)kev->event_data;
  struct interface nic;
  struct sockaddr_in6 sin6;
  ipchange_message_t msg;

  nic.unit = in6_data->link_data.if_unit;
  sin6.sin6_family = AF_INET6;
  assert(sizeof(sin6.sin6_addr) == sizeof(in6_data->ia_addr));
  memcpy(&sin6.sin6_addr, &in6_data->ia_addr, sizeof(sin6.sin6_addr));
  sin6.sin6_port = 0;
  msg.interface = &nic;
  msg.socket_address = (const struct sockaddr *)&sin6;
  return event->callback(event, &msg, flags, event->event.user_data);
}

static inline int dl_event(
  loop_t *loop,
  ipchange_event_t *event,
  const struct kern_event_msg *kev,
  uint32_t flags)
{
  const struct net_event_data *net_data =
    (const struct net_event_data *)kev->event_data;
  struct interface nic;
  ipchange_message_t msg;

  nic.unit = net_data->if_unit;
  msg.interface = &nic;
  msg.socket_address = NULL;
  return event->callback(event, &msg, flags, event->event.user_data);
}

static int proxy_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  unsigned char buf[1024]; // FIXME: determine max message size
  ssize_t cnt;
  ipchange_message_t msg;

  for (;;) {
    cnt = read(event->socketfd, buf, sizeof(buf));
    if (cnt == -1) {
      if (errno != EINTR)
        return -1;
    } else {
      uint32_t flags = 0;
      const struct kern_event_msg *kev = (const struct kern_event_msg *)buf;
      /* ignore non-networking events */
      if (kev->kev_class != KEV_NETWORK_CLASS) {
        break;
      } else if (kev->kev_subclass == KEV_INET_SUBCLASS) {
        if (kev->event_code == KEV_INET_NEW_ADDR)
          flags = IPV4_ADDED;
        else if (kev->event_code == KEV_INET_ADDR_DELETED)
          flags = IPV4_DELETED;
        if ((event->event.flags & flags))
          return inet_event(loop, event, kev, flags);
      } else if (kev->kev_subclass == KEV_INET6_SUBCLASS) {
        if (kev->event_code == KEV_INET6_NEW_USER_ADDR)
          flags = IPV6_ADDED;
        else if (kev->event_code == KEV_INET6_ADDR_DELETED)
          flags = IPV6_DELETED;
        if ((event->event.flags & flags))
          return inet6_event(loop, event, kev, flags);
      } else if (kev->kev_subclass == KEV_DL_SUBCLASS) {
        if (kev->event_code == KEV_DL_PROTO_ATTACHED)
          flags = LINK_UP;
        else if (kev->event_code == KEV_DL_PROTO_DETACHED)
          flags = LINK_DOWN;
        if ((event->event.flags & flags))
          return dl_event(loop, event, kev, flags);
      }
      break;
    }
  }

  return 0;
}

#elif __FreeBSD__
/*
 * Round up 'a' to next multiple of 'size', which must be a power of 2
 */
#define ROUNDUP(a, size) (((a) & ((size)-1)) ? (1 + ((a) | ((size)-1))) : (a))

/*
 * Step to next socket address structure;
 * if sa_len is 0, assume it is sizeof(u_long).
 */
#define NEXT_SA(ap) ap = (struct sockaddr *) \
     ((caddr_t) ap + (ap->sa_len ? ROUNDUP(ap->sa_len, sizeof (u_long)) : \
                                        sizeof(u_long)))

static void get_rtaddrs(int addrs, const struct sockaddr *sa, const struct sockaddr **rti_info)
{
  for (int i = 0; i < RTAX_MAX; i++) {
    if (addrs & (1 << i)) {
      rti_info[i] = sa;
      NEXT_SA(sa);
    } else {
      rti_info[i] = NULL;
    }
  }
}

static int proxy_ipchange_event(loop_t *loop, ipchange_event_t *event)
{
  unsigned char buf[512];
  ssize_t msglen;

  do {
    msglen = read(event->socketfd, buf, sizeof(buf));
    if (msglen == -1 && errno != EINTR)
      return -1;
  } while (msglen == -1);

  const struct {
    unsigned short rtm_msglen;
    unsigned char rtm_version;
    unsigned char rtm_type;
  } *msghdr = (void *)buf;

  assert((size_t)msghdr->rtm_msglen == (size_t)msglen);
  switch (msghdr->rtm_type) {
    case RTM_NEWADDR: /* address being added to iface */
    case RTM_DELADDR: { /* address being remove from iface */
      const struct ifa_msghdr *ifa_msghdr = (void *)buf;
      const interface_t iface = { ifa_msghdr->ifam_index };
      const struct sockaddr *saddr = NULL, *rti_info[RTAX_MAX];
      ipchange_message_t msg = { &iface, NULL };
      uint32_t flags = 0;
      /* retrieve socket addresses */
      saddr = (const struct sockaddr *)(ifa_msghdr + 1);
      get_rtaddrs(ifa_msghdr->ifam_addrs, saddr, rti_info);
      msg.socket_address = saddr = rti_info[RTAX_IFA];
      if (saddr->sa_family == AF_INET)
        flags = msghdr->rtm_type == RTM_NEWADDR ? IPV4_ADDED : IPV4_DELETED;
      else
        flags = msghdr->rtm_type == RTM_DELADDR ? IPV6_ADDED : IPV6_DELETED;
      return event->callback(event, &msg, flags, event->event.user_data);
    }
    case RTM_IFINFO: { /* iface going up/down etc. */
      const struct if_msghdr *if_msghdr = (void *)buf;
      const interface_t iface = { if_msghdr->ifm_index };
      ipchange_message_t msg = { &iface, NULL };
      uint32_t flags = (if_msghdr->ifm_flags & IFF_UP) ? LINK_UP : LINK_DOWN;
      return event->callback(event, &msg, flags, event->event.user_data);
    }
    default: /* discard unsupported messages */
      return 0;
  }
}
#endif

int run(loop_t *loop, eventlist_t *list)
{
  uint32_t blk = sizeof(list->events.fixed) / sizeof(list->events.fixed[0]);
  uint32_t cnt = atomic_ld32(&loop->events), len = 0;
  struct kevent *kevs = NULL;

  if (list->length <= blk) /* eventlist has a fixed number of minimum slots */
    list->length = blk;

  if (cnt <= list->length) {
    len = list->length;
    kevs = list->length <= blk ? list->events.fixed : list->events.dynamic;
  } else {
    len = (list->length / blk) + 1;
    if (!(kevs = malloc(blk * sizeof(*list->events.dynamic))))
      return -1;
    if (list->length > blk)
      free(list->events.dynamic);
    list->events.dynamic = kevs;
    list->length = len;
  }

  assert(kevs);

  for (int n;;) {
    if ((n = kevent(loop->kqueuefd, NULL, 0, kevs, len, NULL)) == -1) {
      if (errno != EINTR)
        return -1;
      continue;
    } else {
      for (int i=0; i < n; i++) {
        /* skip self-pipe triggers */
        if ((uintptr_t)kevs[i].udata == (uintptr_t)loop) {
          char buf[1];
          read(loop->pipefds[0], buf, sizeof(buf));
        } else {
          uint32_t flags = 0;
          event_t *event = kevs[i].udata;
          switch (event->source) {
            case IPCHANGE_EVENT:
              if (proxy_ipchange_event(loop, (ipchange_event_t *)event) == -1)
                return -1;
              break;
            default:
              assert(event->source == SOCKET_EVENT);
              if (kevs[i].fflags & EVFILT_READ)
                flags |= READ;
              if (kevs[i].fflags & EVFILT_WRITE)
                flags |= WRITE;
              socket_event_t *socket_event = (socket_event_t *)event;
              if (socket_event->callback(socket_event, flags, event->user_data) == -1)
                return -1;
              break;
          }
        }
      }
    }
  }
}
