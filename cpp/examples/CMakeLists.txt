cmake_minimum_required(VERSION 3.22)
project(vaas_cxx)

set(CMAKE_CXX_STANDARD 17)

set(CARGO_MANIFEST ${CMAKE_SOURCE_DIR}/../Cargo.toml)
set(CARGO_TARGET_DIR ${CMAKE_SOURCE_DIR}/../target)

set(VAAS_SOURCE_FILE ${CMAKE_SOURCE_DIR}/../src/vaas.rs)
set(VAAS_BRIDGE_CPP ${CARGO_TARGET_DIR}/cxxbridge/vaas-cxx/src/vaas.rs.cc)
set(VAAS_LIB ${CARGO_TARGET_DIR}/debug/libvaas_cxx${CMAKE_STATIC_LIBRARY_SUFFIX})

# Add a custom command that builds the rust crate and generates C++ bridge code
add_custom_command(
        OUTPUT ${VAAS_BRIDGE_CPP} ${VAAS_LIB}
        COMMAND cargo build --manifest-path ${CARGO_MANIFEST}
        DEPENDS ${VAAS_SOURCE_FILE}
        USES_TERMINAL
        COMMENT "Running cargo..."
)

add_executable(vaas_cxx src/main.cpp ${VAAS_BRIDGE_CPP})

target_include_directories(
        vaas_cxx
        PRIVATE
        include/
        ${CARGO_TARGET_DIR}/cxxbridge/vaas-cxx/src/
        ${CARGO_TARGET_DIR}/cxxbridge/rust/
)

target_link_libraries(vaas_cxx ${VAAS_LIB} "crypto" "ssl")

set_target_properties(
        vaas_cxx
        PROPERTIES ADDITIONAL_CLEAN_FILES ${CARGO_TARGET_DIR}
)
