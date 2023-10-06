#include(FetchContent)
#FetchContent_Declare(
#  googletest
#  # Specify the commit you depend on and update it regularly.
#  URL https://github.com/google/googletest/archive/refs/tags/v1.13.0.tar.gz
#)

#set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
#FetchContent_MakeAvailable(googletest)

include_directories(
    /usr/include/c++/12
    /usr/include/x86_64-linux-gnu/c++/12
    ${CMAKE_SOURCE_DIR}
)

find_package(absl REQUIRED)
find_package(GTest REQUIRED)

add_executable(test_rocca-s_ref test_rocca-s_ref.cc)
target_link_libraries(test_rocca-s_ref gtest_main gtest absl::base absl::strings rocca-s)
add_test(NAME test COMMAND test_rocca-s_ref)
enable_testing()

