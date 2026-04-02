cmake_minimum_required(VERSION 3.14)
project(ibe_grpc_demo)

# CMAKE_PREFIX_PATH for gRPC/Protobuf
list(APPEND CMAKE_PREFIX_PATH "/root/.local")
list(APPEND CMAKE_MODULE_PATH "/root/.local/lib/cmake")

# Find Protobuf and gRPC
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# GmSSL
find_library(GMSSL_LIBRARY gmssl)
find_path(GMSSL_INCLUDE_DIR gmssl/sm9.h)

# Proto file - use absolute paths
get_filename_component(IBE_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(PROTO_FILE "${IBE_BASE_DIR}/ibe.proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
set(PROTO_HDR "${PROTO_OUT_DIR}/ibe.pb.h")
set(PROTO_SRC "${PROTO_OUT_DIR}/ibe.pb.cc")
set(GRPC_HDR "${PROTO_OUT_DIR}/ibe.grpc.pb.h")
set(GRPC_SRC "${PROTO_OUT_DIR}/ibe.grpc.pb.cc")

# Generate proto files
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

add_custom_command(
    OUTPUT ${PROTO_SRC} ${PROTO_HDR} ${GRPC_SRC} ${GRPC_HDR}
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --cpp_out ${PROTO_OUT_DIR}
         --grpc_out ${PROTO_OUT_DIR}
         --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN_EXECUTABLE}
         -I ${IBE_BASE_DIR}
         ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "Generating IBE protobuf C++ sources"
    VERBATIM
)

add_custom_target(ibe_proto_gen ALL DEPENDS ${PROTO_SRC} ${PROTO_HDR} ${GRPC_SRC} ${GRPC_HDR})

# Note: ibe_core library is already built by parent CMakeLists.txt
# This demo just links against it

# Include directories
get_filename_component(IBE_BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
include_directories(${IBE_BASE_DIR}/lib/ibe_core)
include_directories(${IBE_BASE_DIR}/lib/ibe_core/include)
include_directories(${PROTO_OUT_DIR})

# Executables
add_executable(ibe_grpc_server server.cpp ${PROTO_SRC} ${GRPC_SRC})
add_executable(ibe_grpc_client client.cpp ${PROTO_SRC} ${GRPC_SRC})

add_dependencies(ibe_grpc_server ibe_proto_gen)
add_dependencies(ibe_grpc_client ibe_proto_gen)

target_link_libraries(ibe_grpc_server
    ibe_core
    gRPC::grpc++
    protobuf::libprotobuf
    ${GMSSL_LIBRARY}
)

target_link_libraries(ibe_grpc_client
    ibe_core
    gRPC::grpc++
    protobuf::libprotobuf
    ${GMSSL_LIBRARY}
)

# Note: Keys are generated at runtime, no need to copy
