project(tox-redirection-server)
cmake_minimum_required(VERSION 2.8)
aux_source_directory(. SRC_LIST)
add_executable(${PROJECT_NAME} ${SRC_LIST})

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}/include/
)

set(ARCH_DIR_NAME amd64)

target_link_libraries(${PROJECT_NAME} ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so)

# Install toxcore library
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so.0 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
install(FILES ${CMAKE_CURRENT_SOURCE_DIR}/libs/${ARCH_DIR_NAME}/libtoxcore.so.0.0.0 DESTINATION ${CMAKE_CURRENT_BINARY_DIR}/)
