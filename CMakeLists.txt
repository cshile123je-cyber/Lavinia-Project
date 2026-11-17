cmake_minimum_required(VERSION 3.20)
project(XWrapper)

set(CMAKE_CXX_STANDARD 20)

add_library(XWrapper SHARED wrapper.cpp)

target_compile_definitions(XWrapper PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX
    UNICODE
    _UNICODE
    _CRT_SECURE_NO_WARNINGS
)

target_link_libraries(XWrapper PRIVATE kernel32 user32)

if(MSVC)
    target_compile_options(XWrapper PRIVATE /W3 /O2 /MT /GS-)
    set_target_properties(XWrapper PROPERTIES
        OUTPUT_NAME "xwrapper"
    )
endif()
