cmake_minimum_required(VERSION 3.10)
project(event LANGUAGES C VERSION 0.1.0)

set(sources main.c event.c)

if(CMAKE_SYSTEM_NAME STREQUAL "Windows")
  list(APPEND sources compat/wepoll.c epoll.c)
elseif(CMAKE_SYSTEM_NAME STREQUAL "Linux")
  list(APPEND sources epoll.c)
elseif(UNIX)
  list(APPEND sources kqueue.c)
endif()

add_executable(event ${sources})

if(WIN32)
  target_link_libraries(event PRIVATE ws2_32 iphlpapi bcrypt)
endif()
