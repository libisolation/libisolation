set(CMAKE_MACOSX_RPATH 1)

set(CMAKE_C_FLAGS_RELEASE "-Wall -O2")
set(CMAKE_C_FLAGS_DEBUG "-g -O0")

add_library(vmm SHARED src/vmm_ahf.c)

target_link_libraries(vmm "-framework Hypervisor")
