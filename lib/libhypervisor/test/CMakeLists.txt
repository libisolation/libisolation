add_executable(main main.c)
target_link_libraries(main hypervisor)

add_executable(main_longmode main_longmode.c)
target_link_libraries(main_longmode hypervisor)

add_test(NAME test_main COMMAND $<TARGET_FILE:main>)
add_test(NAME test_main_longmode COMMAND $<TARGET_FILE:main_longmode>)
