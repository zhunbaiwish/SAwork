cmake_minimum_required(VERSION 3.14)
project(ibe_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# GmSSL library
find_library(GMSSL_LIBRARY gmssl)
find_path(GMSSL_INCLUDE_DIR gmssl/sm9.h)
if(NOT GMSSL_LIBRARY)
    message(FATAL_ERROR "GmSSL library not found")
endif()

# Source files for IBE core
set(IBE_CORE_SOURCES
    sm9_ibe.cpp
    sm9_ibs.cpp
    pkg_service.cpp
)

# Create static library
add_library(ibe_core STATIC ${IBE_CORE_SOURCES})

# Include directories
target_include_directories(ibe_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
    ${GMSSL_INCLUDE_DIR}
)

# Link dependencies
target_link_libraries(ibe_core PUBLIC
    ${GMSSL_LIBRARY}
)

# Installation
install(TARGETS ibe_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
)
