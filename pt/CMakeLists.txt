cmake_minimum_required(VERSION 2.8.12)
project(ptfuzzer)


add_compile_options("-Wall")
add_compile_options("-I /usr/src/linux-headers-4.15.0-91/include/")

IF (BUILD_TYPE MATCHES "Debug")
    message( "build type is Debug." )
    set ( CMAKE_C_FLAGS "-std=c11 -O0 -D_FILE_OFFSET_BITS=64 -g -DDEBUG ")
    set ( CMAKE_CXX_FLAGS "-std=c++11 -O0 -D_FILE_OFFSET_BITS=64 -g -DDEBUG")
ELSE()
    message( "build type is Release." )
    set ( CMAKE_C_FLAGS "-std=c11 -O3 -lpthread -D_FILE_OFFSET_BITS=64 -g ")
    set ( CMAKE_CXX_FLAGS "-std=c++11 -O3 -lpthread -D_FILE_OFFSET_BITS=64 -g ")

ENDIF()
set(PT_SRC pt.cpp pt_fuzzer.cpp pt_decoder.cpp disassembler.cpp tnt_cache.cpp)

add_library(pt STATIC ${PT_SRC})
add_executable(run_pt run_pt.cpp)
target_link_libraries(run_pt pt msr capstone pthread)

add_executable(test_disassemble test_disassemble.cpp)
target_link_libraries(test_disassemble pt capstone )

install(TARGETS pt run_pt test_disassemble
		RUNTIME DESTINATION bin
		ARCHIVE DESTINATION bin
)

