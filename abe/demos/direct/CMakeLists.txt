cmake_minimum_required(VERSION 3.14)
project(abe_direct_demo)

# CMAKE_PREFIX_PATH for gRPC/Protobuf
list(APPEND CMAKE_PREFIX_PATH "/root/.local")
list(APPEND CMAKE_MODULE_PATH "/root/.local/lib/cmake")

# Find Protobuf and gRPC
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Note: abe_core library is already built by parent CMakeLists.txt
# This demo just links against it

# Executables
add_executable(abe_server server.cpp)
add_executable(abe_client client.cpp)

target_link_libraries(abe_server abe_core)
target_link_libraries(abe_client abe_core)

# Copy a.param to build directory
get_filename_component(ABE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
configure_file(${ABE_DIR}/a.param ${CMAKE_CURRENT_BINARY_DIR}/a.param COPYONLY)
