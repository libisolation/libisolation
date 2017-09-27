add_executable(test1 test.c)
target_link_libraries(test1 isolation)

add_test(NAME simple_test
  COMMAND sg kvm -c $<TARGET_FILE:test1>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
