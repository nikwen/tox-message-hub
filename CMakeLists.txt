project(tox-message-hub)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

add_subdirectory(meta)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
)

set(ARCH amd64)
set(ARCH_DIR_NAME ${ARCH})
set(DATA_DIR_PREFIX "/var/lib/apps/${PROJECT_NAME}.nikwen")
set(VERSION_NUMBER "0.0.1")
set(DATA_DIR "${DATA_DIR_PREFIX}/${VERSION_NUMBER}/")

target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so)

# Configure and include config.h.in
configure_file(config.h.in ${CMAKE_BINARY_DIR}/config.h)
include_directories(${CMAKE_BINARY_DIR})

configure_file(${CMAKE_CURRENT_SOURCE_DIR}/meta/package.yaml.in ${CMAKE_CURRENT_BINARY_DIR}/package.yaml)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/meta/run.sh.in ${CMAKE_CURRENT_BINARY_DIR}/run.sh)

# Install executable
install(TARGETS ${PROJECT_NAME} RUNTIME DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap)

# Install toxcore library
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so.0 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so.0.0.0 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)

# Install libsodium library
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libsodium.so DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libsodium.so.13 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libsodium.so.13.0.2 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/lib)

# Install meta files
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/package.yaml DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/meta)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/meta/readme.md DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap/meta)

# Install run script
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/run.sh DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/snap PERMISSIONS OWNER_READ OWNER_WRITE OWNER_EXECUTE)

# Use C++11
include(CheckCXXCompilerFlag)
CHECK_CXX_COMPILER_FLAG("-std=c++11" COMPILER_SUPPORTS_CXX11)
if(COMPILER_SUPPORTS_CXX11)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11")
else()
    message(FATAL_ERROR "Please use a different compiler with C++11 support.")
endif()
