# Tests are self-contained: no game data, no ROMs, no disc images. Every input
# is either a hand-written instruction encoding or a synthetic buffer built in
# the test itself.

add_executable(test_decode test_decode.c)
target_link_libraries(test_decode PRIVATE allegrex_core)
add_test(NAME decode COMMAND test_decode)

add_executable(test_runtime test_runtime.c)
target_link_libraries(test_runtime PRIVATE psprecomp)
add_test(NAME runtime COMMAND test_runtime)

add_executable(test_container test_container.c)
target_link_libraries(test_container PRIVATE allegrex_core)
add_test(NAME container COMMAND test_container)

# Published standard vectors only (FIPS-197, SP 800-38A, RFC 4493) — no PSP
# key material, no game data.
add_executable(test_crypto test_crypto.c)
target_link_libraries(test_crypto PRIVATE allegrex_core)
add_test(NAME crypto COMMAND test_crypto)

add_executable(test_kirk test_kirk.c)
target_link_libraries(test_kirk PRIVATE allegrex_core)
add_test(NAME kirk COMMAND test_kirk)

add_executable(test_emit test_emit.c)
target_link_libraries(test_emit PRIVATE allegrex_core)
add_test(NAME emit COMMAND test_emit)

add_executable(test_p2p test_p2p.c)
target_link_libraries(test_p2p PRIVATE psprecomp allegrex_core)
target_include_directories(test_p2p PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/hle)
add_test(NAME p2p COMMAND test_p2p)

add_executable(test_adhoc test_adhoc.c)
target_link_libraries(test_adhoc PRIVATE psprecomp allegrex_core)
target_include_directories(test_adhoc PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/../src/hle)
add_test(NAME adhoc COMMAND test_adhoc)

add_executable(test_hle test_hle.c)
target_link_libraries(test_hle PRIVATE psprecomp allegrex_core)
add_test(NAME hle COMMAND test_hle)

add_executable(test_vfpu test_vfpu.c)
target_link_libraries(test_vfpu PRIVATE psprecomp)
add_test(NAME vfpu COMMAND test_vfpu)

add_executable(test_ctors test_ctors.c)
target_link_libraries(test_ctors PRIVATE psprecomp)
add_test(NAME ctors COMMAND test_ctors)

add_executable(test_raster test_raster.c)
target_link_libraries(test_raster PRIVATE psprecomp)
add_test(NAME raster COMMAND test_raster)

# PGF font parsing. Synthetic data only; set PSPRECOMP_FONT_DIR to a directory
# holding the PSP's own font files to run the extra real-font checks.
add_executable(test_font test_font.c)
target_link_libraries(test_font PRIVATE psprecomp)
add_test(NAME font COMMAND test_font)

add_executable(test_ge_vertex test_ge_vertex.c)
target_link_libraries(test_ge_vertex PRIVATE psprecomp)
add_test(NAME ge_vertex COMMAND test_ge_vertex)
