cmake_minimum_required(VERSION 3.10)
project(event LANGUAGES C VERSION 0.1.0)

set(sources main.c event.c)

if(WIN32)
  list(APPEND sources compat/wepoll.c windows.c)
elseif(APPLE)
  list(APPEND sources darwin.c)
endif()

add_executable(event ${sources})

if(WIN32)
  target_link_libraries(event PRIVATE ws2_32 iphlpapi bcrypt)
endif()
