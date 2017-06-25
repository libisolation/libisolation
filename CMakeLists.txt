cmake_minimum_required(VERSION 2.8)

project(libisolation)

include(GNUInstallDirs)

add_subdirectory(lib/libhypervisor)

include_directories(include lib/libhypervisor/include)

set(SOURCES
  src/isolation.c)

set(HEADERS
  include/isolation.h)

add_library(isolation SHARED ${SOURCES})

target_link_libraries(isolation hypervisor)

install(TARGETS isolation DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

enable_testing()
add_subdirectory(test)
