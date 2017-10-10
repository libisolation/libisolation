cmake_minimum_required(VERSION 2.4)

project(hypervisor)

include_directories(include)

include(${CMAKE_SYSTEM_NAME}.cmake)

set(CMAKE_C_FLAGS_RELEASE "-Wall -O0")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

enable_testing()
add_subdirectory(test)
