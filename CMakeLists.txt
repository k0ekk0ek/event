cmake_minimum_required(VERSION 3.10)
project(event LANGUAGES C VERSION 0.1.0)

set(sources compat/wepoll.c event.c main.c)

add_executable(event ${sources})
target_link_libraries(event PRIVATE ws2_32 iphlpapi bcrypt)
