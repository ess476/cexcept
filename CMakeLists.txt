cmake_minimum_required(VERSION 3.14)
project(cexcept)

set(CMAKE_CXX_STANDARD 14)

include_directories(.)

add_executable(cexcept
        cexcept.h
        CMakeLists.txt
        main.c)
