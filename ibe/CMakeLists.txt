cmake_minimum_required(VERSION 3.14)
project(ibe_all)

# IBE Module - Modular Structure
#
# lib/ibe_core/     - Core IBE library (direct interface)
# demos/direct/     - Direct interface demo (server + client)
# demos/grpc/       - gRPC demo (remote PKG)

# Build options
option(BUILD_DIRECT_DEMO "Build direct interface demo" ON)
option(BUILD_GRPC_DEMO "Build gRPC demo" ON)

# Build core library
add_subdirectory(lib/ibe_core)

# Build demos
if(BUILD_DIRECT_DEMO)
    message(STATUS "Building IBE direct interface demo")
    add_subdirectory(demos/direct)
endif()

if(BUILD_GRPC_DEMO)
    message(STATUS "Building IBE gRPC demo")
    add_subdirectory(demos/grpc)
endif()

message(STATUS "IBE module configured successfully")
