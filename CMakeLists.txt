cmake_minimum_required(VERSION 2.8)

project(libisolation C CXX)

include(GNUInstallDirs)
enable_testing()

set(CMAKE_CXX_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_CXX_FLAGS_DEBUG "-g3 -O0")

add_subdirectory(lib/libhypervisor)

include_directories(include lib/libhypervisor/include)

set(SOURCES
  src/isolation.cxx)

set(HEADERS
  include/isolation.h)

add_library(isolation SHARED ${SOURCES})

target_link_libraries(isolation hypervisor)

install(TARGETS isolation DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

add_subdirectory(test)
