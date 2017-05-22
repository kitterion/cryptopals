set(SRC_HXX
  crypto.h
  file_util.h
  set1.h
)

set(SRC_CXX
  crypto.cpp
  file_util.cpp
  set1.cpp
)

set(SRC_TESTS
  set1_test.cpp
)

find_package(OpenSSL REQUIRED)

add_library(cryptopals ${SRC_CXX} ${SRC_HXX})
target_link_libraries(cryptopals OpenSSL::Crypto)

add_executable(cryptopals_tests ${SRC_TESTS} ${SRC_HXX})
target_link_libraries(cryptopals_tests cryptopals gtest_main)
add_custom_command(
  TARGET cryptopals_tests POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_directory
  ${CMAKE_CURRENT_SOURCE_DIR}/data $<TARGET_FILE_DIR:cryptopals_tests>/data)
