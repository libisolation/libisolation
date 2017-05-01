cmake_minimum_required(VERSION 3.8)

project(libisolation)

include(GNUInstallDirs)

include_directories(include)

set(SOURCES
  src/isolation.c)

set(HEADERS
  include/isolation.h)

add_library(isolation SHARED ${SOURCES})

install(TARGETS isolation DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(FILES ${HEADERS} DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
