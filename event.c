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
#include <assert.h>
#include <string.h>

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

void destroy_socket_event(socket_event_t *event)
{
  memset(event, 0, sizeof(*event));
  event->socketfd = -1;
}

extern inline uint32_t atomic_ld32(const volatile atomic_uint32_t *a);
extern inline void atomic_st32(volatile atomic_uint32_t *a, uint32_t v);
extern inline uint32_t atomic_inc32(volatile atomic_uint32_t *a);
extern inline uint32_t atomic_dec32(volatile atomic_uint32_t *a);
