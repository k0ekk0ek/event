#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event.h"

int32_t callback(const ipchange_event_t *event, ipchange_message_t *message, uint32_t flags, void *user_data)
{
  uint32_t ip_flags = IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED;
  char addrstr[INET6_ADDRSTRLEN] = { 0 };

  if (flags & (IPV4_ADDED|IPV4_DELETED))
    inet_ntop(AF_INET, &((struct sockaddr_in *)message->socket_address)->sin_addr, addrstr, sizeof(addrstr));
  else if (flags & (IPV6_ADDED|IPV6_DELETED))
    inet_ntop(AF_INET6, &((struct sockaddr_in6 *)message->socket_address)->sin6_addr, addrstr, sizeof(addrstr));

  if (flags & (IPV4_ADDED|IPV6_ADDED))
    fprintf(stderr, "got ip added event: %s\n", addrstr);
  else if (flags & (IPV4_DELETED|IPV6_DELETED))
    fprintf(stderr, "got ip deleted event: %s\n", addrstr);
  else if (flags & LINK_UP)
    fprintf(stderr, "got link up event\n");
  else if (flags & LINK_DOWN)
    fprintf(stderr, "got link down event\n");
  else
    fprintf(stderr, "got unknown event\n");
  return 0;
}

int main(int argc, char *argv[])
{
  loop_t loop;
  ipchange_event_t event;
  uint32_t flags = LINK_UP|LINK_DOWN|IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED;
  char buf[] = "hello world!\n";
  eventlist_t eventlist;

  memset(&eventlist, 0, sizeof(eventlist));
#if _WIN32
  WSADATA wsa_data;
  if (WSAStartup(MAKEWORD(2,0), &wsa_data) != 0)
    return 1;
#endif
  if (create_ipchange_event(&event, &callback, flags, buf) != 0)
    return 1;
  if (create_loop(&loop) != 0)
    return 1;
  if (add_event(&loop, &event) != 0)
    return 1;
  run(&loop, &eventlist);
  return 0;
}
