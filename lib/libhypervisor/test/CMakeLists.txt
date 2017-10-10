add_executable(boot_realmode boot_realmode.c)
target_link_libraries(boot_realmode hypervisor)

add_executable(boot_longmode boot_longmode.c)
target_link_libraries(boot_longmode hypervisor)

add_test(NAME test_boot_realmode COMMAND $<TARGET_FILE:boot_realmode>)
add_test(NAME test_boot_longmode COMMAND $<TARGET_FILE:boot_longmode>)


