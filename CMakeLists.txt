cmake_minimum_required(VERSION 3.14)
project(cexcept C)

set(CMAKE_C_STANDARD 11)
set (CMAKE_C_FLAGS "-rdynamic")

add_executable(cexcept main.c cexcept.h)