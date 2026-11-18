cmake_minimum_required(VERSION 3.18)
project(rdr2shell C)

# The shell APK contains no game code. It exists so the Android side (window,
# Vulkan surface, storage, input) can be built and tested on its own, and so
# that a device can report the Vulkan capabilities the game will get.
add_library(rdr2shell SHARED shell.c)
target_compile_options(rdr2shell PRIVATE -Wall -Wextra -O2)
target_link_libraries(rdr2shell PRIVATE android log vulkan)

# Full builds add the recompiled game objects. gen/ is derived from the user's
# own copy of the game and is never committed (see README, "Legal").
if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../gen/CMakeLists.txt")
    message(STATUS "gen/ present: building the full APK")
    add_subdirectory("${CMAKE_CURRENT_SOURCE_DIR}/../../gen" gen)
else()
    message(STATUS "gen/ absent: building the shell APK (no game code)")
endif()
