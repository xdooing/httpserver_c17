cmake_minimum_required(VERSION 3.5)

set(CMAKE_CXX_STANDARD 17)

project(http17)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Debug)
endif()

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_RELEASE "${CMAKE_SOURCE_DIR}/output/release")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY_DEBUG "${CMAKE_SOURCE_DIR}/output/debug")

find_package(fmt REQUIRED)

file(GLOB sources *.cpp)
add_executable(http17 ${sources})
target_link_libraries(http17 PRIVATE fmt::fmt pthread)
