cmake_minimum_required(VERSION 3.14)
project(abe_all)

# ABE Module - Modular Structure
#
# lib/abe_core/     - Core ABE library (direct interface)
# demos/direct/     - Direct interface demo (server + client)
# demos/grpc/       - gRPC demo (remote PKG)

# Build options
option(BUILD_DIRECT_DEMO "Build direct interface demo" ON)
option(BUILD_GRPC_DEMO "Build gRPC demo" ON)

# Build core library
add_subdirectory(lib/abe_core)

# Build demos
if(BUILD_DIRECT_DEMO)
    message(STATUS "Building ABE direct interface demo")
    add_subdirectory(demos/direct)
endif()

if(BUILD_GRPC_DEMO)
    message(STATUS "Building ABE gRPC demo")
    add_subdirectory(demos/grpc)
endif()

message(STATUS "ABE module configured successfully")
