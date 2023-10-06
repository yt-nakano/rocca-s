cmake_minimum_required(VERSION 3.14)
project(rocca-s)

add_library(rocca-s SHARED rocca-s_ref.c)

# compile option
target_compile_options(
  rocca-s
  PRIVATE -O3 -march=native)

# header
set_property(
    TARGET rocca-s
    PROPERTY PUBLIC_HEADER
    rocca-s.h
)

# test
add_subdirectory(test)
