cmake_minimum_required(VERSION 3.14)
project(ibe_direct_demo)

# GmSSL
find_library(GMSSL_LIBRARY gmssl)
find_path(GMSSL_INCLUDE_DIR gmssl/sm9.h)
if(NOT GMSSL_LIBRARY)
    message(FATAL_ERROR "GmSSL library not found")
endif()

# Note: ibe_core library is already built by parent CMakeLists.txt
# This demo just links against it

# Include directories for source files
get_filename_component(IBE_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories(${IBE_BASE_DIR}/lib/ibe_core)
include_directories(${IBE_BASE_DIR}/lib/ibe_core/include)

# Executables
add_executable(ibe_server server.cpp)
add_executable(ibe_client client.cpp)

target_link_libraries(ibe_server ibe_core ${GMSSL_LIBRARY})
target_link_libraries(ibe_client ibe_core ${GMSSL_LIBRARY})

# Note: Keys are generated at runtime, no need to copy
