set(LIBRARY_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

add_library(preopen SHARED libpreopen.c)
install(TARGETS preopen DESTINATION lib)
