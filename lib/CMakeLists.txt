set(LIBRARY_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

add_library(libpreopen SHARED libpreopen.c)
install(TARGETS libpreopen DESTINATION lib)
