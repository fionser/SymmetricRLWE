cmake_minimum_required(VERSION 3.2)
project(symmetric_rlwe)
set(CMAKE_CXX_STANDARD 11)

set(NTL_HEADER /usr/local/include)
set(NTL_LIB /usr/local/lib)
set(HELIB_HEADER /home/riku/include)
set(HELIB_LIB /home/riku/lib)
include_directories(${NTL_HEADER} ${HELIB_HEADER} include)
link_directories(${NTL_LIB} ${HELIB_LIB})
set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC")

add_subdirectory(src)

if (ENABLE_TESTS)
    enable_testing()
    find_package(GTest REQUIRED)
    add_subdirectory(test)
endif (ENABLE_TESTS)

find_package(OpenMP)
if (OPENMP_FOUND)
    set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${OpenMP_C_FLAGS}")
    set (CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${OpenMP_CXX_FLAGS}")
endif()

add_executable(main main.cpp)
target_link_libraries(main symrlwe helib ntl pthread gmp)

add_executable(example example.cpp)
target_link_libraries(example symrlwe helib ntl pthread gmp)

#add_executable(new_tricks new_tricks.cpp recrypt.cpp)
#target_link_libraries(new_tricks symrlwe helib ntl pthread gmp)

# add_executable(Test_bootstrapping Test_bootstrapping.cpp)
# target_link_libraries(Test_bootstrapping symrlwe helib ntl pthread gmp)
