#include <stdio.h>

#include "event.h"

int32_t callback(const ipchange_event_t *event, ipchange_message_t *message, uint32_t flags, void *user_data)
{
  uint32_t ip_flags = IPV4_ADDED|IPV4_DELETED|IPV6_ADDED|IPV6_DELETED;
  char addrstr[INET6_ADDRSTRLEN] = { 0 };

  if (flags & (IPV4_ADDED|IPV4_DELETED))
    inet_ntop(AF_INET, &((SOCKADDR_IN *)message->address)->sin_addr, addrstr, sizeof(addrstr));
  else if (flags & (IPV6_ADDED|IPV6_DELETED))
    inet_ntop(AF_INET6, &((SOCKADDR_IN6 *)message->address)->sin6_addr, addrstr, sizeof(addrstr));

  if (flags & (IPV4_ADDED|IPV6_ADDED))
    fprintf(stderr, "got ip added event: %s\n", addrstr);
  else if (flags & (IPV4_DELETED|IPV6_DELETED))
    fprintf(stderr, "got ip deleted event: %s\n", addrstr);
  else if (flags & LINK_UP)
    fprintf(stderr, "got link up event: %s\n", message->interface);
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
  WSADATA wsa_data;

  if (WSAStartup(MAKEWORD(2,0), &wsa_data) != 0)
    return 1;
  if (create_ipchange_event(&event, &callback, flags, buf) != 0)
    return 1;
  if (create_loop(&loop) != 0)
    return 1;
  if (add_event(&loop, &event) != 0)
    return 1;
  run(&loop);
  return 0;
}
