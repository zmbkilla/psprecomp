# psprecomp — a static-recompilation toolkit for PlayStation Portable games.
#
# This file builds two things:
#   1. the `psprecomp` runtime static library — what recompiled game code links
#      against (CPU state, memory map, semantic helpers)
#   2. `allegrexrecomp` — the tool that turns a PSP module into C
#
# A game repo consumes this repo as a git submodule and does:
#     add_subdirectory(psprecomp)
#     add_subdirectory(games/<game>)
# and links its host against the `psprecomp` target.
#
# The core has no external dependencies on purpose. SDL2 and friends only ever
# appear behind an opt-in option, so a fresh clone builds with nothing installed.

cmake_minimum_required(VERSION 3.16)
project(psprecomp C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

if(MSVC)
    add_compile_options(/W3)
    # The generated C is millions of lines; MSVC's default object format
    # cannot hold that many sections.
    add_compile_options(/bigobj)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
else()
    add_compile_options(-Wall -Wextra -Wno-unused-parameter)
endif()

# --- the runtime library ------------------------------------------------------

add_library(psprecomp STATIC
    src/cpu.c
    src/mem.c
    src/dispatch.c
    src/ctors.c
    src/render.c
    src/vfpu.c
    src/hle/hle.c
    src/hle/sysmem.c
    src/hle/threadman.c
    src/hle/display.c
    src/hle/ge.c
    src/hle/gpu.c
    src/hle/ge_vertex.c
    src/hle/sascore.c
    src/hle/iofilemgr.c
    src/hle/misc.c
    src/hle/system.c
    src/hle/modules.c
    src/hle/atrac.c
    src/hle/mpeg.c
    src/hle/utility.c
    src/hle/font.c
    src/hle/net.c
    src/hle/net_sock.c
    src/hle/http.c
    src/hle/np.c
    src/hle/np2.c
    src/hle/p2p.c
    src/hle/adhoc.c
    src/hle/adhoc_mesh.c
    src/hle/adhoc_matching.c
    src/hle/adhoc_server.c
)

target_include_directories(psprecomp PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

# Networking HLE (src/hle/net.c) uses the host's sockets and adapter list.
if(WIN32)
    target_link_libraries(psprecomp PUBLIC ws2_32 iphlpapi)
endif()

# --- the modern ad hoc server on its own (tools/modern_server) --------------------
# The server the game runs with modern_server=host, as a program for a machine
# players can reach (a VPS, a PC with an open port). Builds anywhere the runtime does.

add_executable(modern_server tools/modern_server/main.c)
target_link_libraries(modern_server PRIVATE psprecomp)
if(NOT WIN32)
    find_package(Threads REQUIRED)
    target_link_libraries(modern_server PRIVATE Threads::Threads)
endif()

# --- the recompiler -----------------------------------------------------------

add_subdirectory(tools/allegrexrecomp)

# --- tests (only when psprecomp is the top-level project, not a submodule) -----

if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    enable_testing()
    add_subdirectory(tests)
endif()
