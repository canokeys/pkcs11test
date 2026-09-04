cmake_minimum_required(VERSION 3.15)
project(pkcs11test LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(STRICT_P11 "Pack Cryptoki structures to the required one-byte alignment" ON)

add_library(gtest STATIC
  gtest-1.10.0/googletest/src/gtest-all.cc)
target_include_directories(gtest SYSTEM PUBLIC
  gtest-1.10.0/googletest/include
  gtest-1.10.0/googletest)

set(PKCS11TEST_SOURCES
  pkcs11test.cc
  pkcs11-describe.cc
  describe.cc
  globals.cc
  init.cc
  slot.cc
  session.cc
  object.cc
  login.cc
  rng.cc
  tookan.cc
  keypair.cc
  cipher.cc
  digest.cc
  sign.cc
  hmac.cc
  key.cc
  dual.cc
  canokey_destructive.cc)

add_executable(pkcs11test ${PKCS11TEST_SOURCES})
target_include_directories(pkcs11test PRIVATE
  third_party/pkcs11
  gtest-1.10.0/googletest/include)
if(STRICT_P11)
  target_compile_definitions(pkcs11test PRIVATE STRICT_P11)
endif()
if(DEFINED PKCS11_LONG_SIZE)
  target_compile_definitions(pkcs11test PRIVATE PKCS11_LONG_SIZE=${PKCS11_LONG_SIZE})
endif()
target_link_libraries(pkcs11test PRIVATE gtest)
if(WIN32)
  target_compile_definitions(pkcs11test PRIVATE _CRT_SECURE_NO_WARNINGS)
else()
  target_link_libraries(pkcs11test PRIVATE ${CMAKE_DL_LIBS} pthread)
endif()
