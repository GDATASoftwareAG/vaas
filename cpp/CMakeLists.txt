cmake_minimum_required(VERSION 3.10)
project(vaas_example)

set(CMAKE_CXX_STANDARD 17)

# Find and link libraries
find_package(CURL REQUIRED)
find_package(jsoncpp CONFIG REQUIRED)
find_package(doctest CONFIG REQUIRED)

# vaas_example
add_executable(vaas_example main.cpp)

target_link_libraries(vaas_example PRIVATE CURL::libcurl JsonCpp::JsonCpp)

# test
add_executable(vaas_test vaas_test.cpp)

target_link_libraries(vaas_test PRIVATE CURL::libcurl JsonCpp::JsonCpp)
