add_executable(main main.c)
target_link_libraries(main hypervisor)

add_test(NAME test_main COMMAND $<TARGET_FILE:main>)
