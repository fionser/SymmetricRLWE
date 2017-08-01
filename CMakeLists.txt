cmake_minimum_required(VERSION 3.2)
project(symmetric_rlwe)
set(CMAKE_CXX_STANDARD 11)

set(NTL_HEADER /home/riku/include)
set(NTL_LIB /home/riku/lib)
set(HELIB_HEADER /home/riku/include)
set(HELIB_LIB /home/riku/lib)
include_directories(${NTL_HEADER} ${HELIB_HEADER} include)
link_directories(${NTL_LIB} ${HELIB_LIB})

add_subdirectory(src)
add_executable(main main.cpp)
target_link_libraries(main symrlwe helib ntl pthread gmp)

