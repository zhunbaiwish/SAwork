cmake_minimum_required(VERSION 3.14)
project(abe_grpc_demo)

# CMAKE_PREFIX_PATH for gRPC/Protobuf
list(APPEND CMAKE_PREFIX_PATH "/root/.local")
list(APPEND CMAKE_MODULE_PATH "/root/.local/lib/cmake")

# Find Protobuf and gRPC
find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

# Proto file - use absolute path
get_filename_component(ABE_PROTO_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../.." ABSOLUTE)
set(PROTO_FILE "${ABE_PROTO_DIR}/serverInteraction.proto")
set(PROTO_OUT_DIR "${CMAKE_CURRENT_BINARY_DIR}")
set(PROTO_HDR "${PROTO_OUT_DIR}/serverInteraction.pb.h")
set(PROTO_SRC "${PROTO_OUT_DIR}/serverInteraction.pb.cc")
set(GRPC_HDR "${PROTO_OUT_DIR}/serverInteraction.grpc.pb.h")
set(GRPC_SRC "${PROTO_OUT_DIR}/serverInteraction.grpc.pb.cc")

# Generate proto files
set(_PROTOBUF_PROTOC $<TARGET_FILE:protobuf::protoc>)
set(_GRPC_CPP_PLUGIN_EXECUTABLE $<TARGET_FILE:gRPC::grpc_cpp_plugin>)

add_custom_command(
    OUTPUT ${PROTO_SRC} ${PROTO_HDR} ${GRPC_SRC} ${GRPC_HDR}
    COMMAND ${_PROTOBUF_PROTOC}
    ARGS --cpp_out ${PROTO_OUT_DIR}
         --grpc_out ${PROTO_OUT_DIR}
         --plugin=protoc-gen-grpc=${_GRPC_CPP_PLUGIN_EXECUTABLE}
         -I ${ABE_PROTO_DIR}
         ${PROTO_FILE}
    DEPENDS ${PROTO_FILE}
    COMMENT "Generating ABE protobuf C++ sources"
    VERBATIM
)

add_custom_target(abe_proto_gen ALL DEPENDS ${PROTO_SRC} ${PROTO_HDR} ${GRPC_SRC} ${GRPC_HDR})

# Note: abe_core library is already built by parent CMakeLists.txt
# This demo just links against it

# Include directories (for proto generated files)
include_directories(${PROTO_OUT_DIR})

# Executables
add_executable(abe_grpc_server server.cpp ${PROTO_SRC} ${GRPC_SRC})
add_executable(abe_grpc_client client.cpp ${PROTO_SRC} ${GRPC_SRC})

add_dependencies(abe_grpc_server abe_proto_gen)
add_dependencies(abe_grpc_client abe_proto_gen)

target_link_libraries(abe_grpc_server
    abe_core
    gRPC::grpc++
    protobuf::libprotobuf
)

target_link_libraries(abe_grpc_client
    abe_core
    gRPC::grpc++
    protobuf::libprotobuf
)

# Copy a.param to build directory
configure_file(${ABE_PROTO_DIR}/a.param ${CMAKE_CURRENT_BINARY_DIR}/a.param COPYONLY)
