cmake_minimum_required(VERSION 3.25)
project(libpreopen)

set(CMAKE_C_STANDARD 17)

include(GNUInstallDirs)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/modules")

option(ENABLE_PO_DEBUG "Enable debug logging (PO_DEBUG)" OFF)

include_directories(include)

add_subdirectory(doc)
add_subdirectory(include)
add_subdirectory(lib)
add_subdirectory(test)

set(PKG_CONFIG_DEST "libdata/pkgconfig")

configure_file("libpreopen.pc.in" "${CMAKE_BINARY_DIR}/libpreopen.pc" @ONLY)
install(FILES "${CMAKE_BINARY_DIR}/libpreopen.pc" DESTINATION "${PKG_CONFIG_DEST}")
