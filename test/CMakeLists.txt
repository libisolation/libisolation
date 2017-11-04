add_executable(simple_isl_call_c simple_isl_call_test_c.c)
target_link_libraries(simple_isl_call_c isolation)

add_executable(simple_isl_call_asm simple_isl_call_test_asm.c)
target_link_libraries(simple_isl_call_asm isolation)

add_test(NAME simple_isl_call_test_asm
  COMMAND sg kvm -c $<TARGET_FILE:simple_isl_call_asm>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

add_test(NAME simple_isl_call_test_c
  COMMAND sg kvm -c $<TARGET_FILE:simple_isl_call_c>
  WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
