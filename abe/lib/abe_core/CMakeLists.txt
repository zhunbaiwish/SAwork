cmake_minimum_required(VERSION 3.14)
project(abe_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# PBC library
find_library(PBC_LIBRARY pbc)
find_path(PBC_INCLUDE_DIR pbc/pbc.h)
if(NOT PBC_LIBRARY)
    message(FATAL_ERROR "PBC library not found")
endif()

# GMP library
find_library(GMP_LIBRARY gmp)
if(NOT GMP_LIBRARY)
    message(FATAL_ERROR "GMP library not found")
endif()

# Source files for ABE core
set(ABE_CORE_SOURCES
    CPABE_types.cpp
    CPABE_utils.cpp
    CPABE_access.cpp
    CPABE_core.cpp
    CPABE_serialize.cpp
    parse.cpp
    authority.cpp
)

# Create static library
add_library(abe_core STATIC ${ABE_CORE_SOURCES})

# Include directories
target_include_directories(abe_core PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

# Link dependencies
target_link_libraries(abe_core PUBLIC
    ${PBC_LIBRARY}
    ${GMP_LIBRARY}
)

# Installation
install(TARGETS abe_core
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
)

install(DIRECTORY include/
    DESTINATION include
)
