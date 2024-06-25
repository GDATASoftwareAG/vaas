cmake_minimum_required(VERSION 3.10)
project(OIDCClientExample)

set(CMAKE_CXX_STANDARD 17)

# Find and link libraries
find_package(CURL REQUIRED)
find_package(jsoncpp CONFIG REQUIRED)

add_executable(OIDCClientExample main.cpp)

target_link_libraries(OIDCClientExample PRIVATE CURL::libcurl JsonCpp::JsonCpp)
