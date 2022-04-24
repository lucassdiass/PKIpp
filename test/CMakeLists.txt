cmake_minimum_required(VERSION 2.6)
project(PKIppTest)

enable_testing()

add_executable( PKIppTest PKIppTest.cc AuthenticationModeTest.cpp ConfidentialityTest.cc )
target_link_libraries(PKIppTest gtest gtest_main pthread PKIpp crypto ssl cryptopp )
add_test( PKIppTest PKIppTest )
