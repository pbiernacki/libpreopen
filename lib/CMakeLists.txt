set(LIBRARY_BUILD_DIR ${CMAKE_CURRENT_BINARY_DIR} PARENT_SCOPE)

add_library(libpreopen SHARED libpreopen.c)
set_property(TARGET libpreopen PROPERTY OUTPUT_NAME preopen)

if(ENABLE_PO_DEBUG)
    target_compile_definitions(libpreopen PRIVATE PO_DEBUG)
endif()

install(TARGETS libpreopen LIBRARY)
