cmake_minimum_required(VERSION 3.22.1)

project("livekadehtunnel")

add_library(
        livekadeh_native
        SHARED
        native-lib.c
)

target_include_directories(livekadeh_native PRIVATE
        ../../../../../
)

target_compile_definitions(livekadeh_native PRIVATE __ANDROID__)

find_library(
        log-lib
        log)

target_link_libraries(
        livekadeh_native
        ${log-lib})
