cmake_minimum_required(VERSION 3.2)
set(GTEST_INCLUDE_DIRS /home/riku/MyLib/include)
set(GTEST_BOTH_LIBRARIES gtest)
message(STATUS ${GTEST_INCLUDE_DIRS})
include_directories(${GTEST_INCLUDE_DIRS})

set(RUNTIME_LIBS
    symrlwe
    helib
    ntl
    pthread
    gmp)

set(CPP_ITESTS
    greater_than_test
    greater_than_benchmark
    private_greater_than_test
    decision_tree_test
    private_greater_than_benchmark
    bench_other_gt
    )

#The integration tests must be single source code, and are compiled as a standalone application
message(STATUS ${GTEST_BOTH_LIBRARIES})
foreach (CPP_ITEST ${CPP_ITESTS})
    add_executable(${CPP_ITEST} ${CPP_ITEST}.cpp)
    target_link_libraries(${CPP_ITEST} ${RUNTIME_LIBS} ${GTEST_BOTH_LIBRARIES})
endforeach(CPP_ITEST)
