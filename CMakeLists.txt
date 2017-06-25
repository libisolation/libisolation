cmake_minimum_required(VERSION 2.4)

project(hypervisor)

set(CMAKE_BUILD_TYPE Release)

include_directories(include)

include(${CMAKE_SYSTEM_NAME}.cmake)

enable_testing()
add_subdirectory(test)
