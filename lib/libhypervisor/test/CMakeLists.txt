add_executable(main main.c)
target_link_libraries(main vmm)

add_test(NAME test_main COMMAND $<TARGET_FILE:main>)
