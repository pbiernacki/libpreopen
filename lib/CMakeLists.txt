set(LIBRARY_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

add_library(libpreopen SHARED libpreopen.c)
set_property(TARGET libpreopen PROPERTY OUTPUT_NAME preopen)
install(TARGETS libpreopen LIBRARY)
