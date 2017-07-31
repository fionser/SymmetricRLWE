cmake_minimum_required(VERSION 3.2)
project(symmetric_rlwe)
set(CMAKE_CXX_STANDARD 11)
include_directories(/home/riku/include/)
link_directories(/home/riku/lib)

add_executable(main main.cpp)
target_link_libraries(main helib ntl pthread gmp)

