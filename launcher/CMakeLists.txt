# The generic helper launcher library: policy schema (helper_policy.h) and the Linux backend (linux/): the
# invocation contract, the descriptor-only box, the one-directory box and the dynamic-binary box. The caller
# supplies the policy table, the helper directory, each helper's argv and the dynamic box's specifics.
# Links libseccomp (dynamic, LGPL-2.1). Consumers add_subdirectory() this directory; built on its own it
# also builds and registers the contract and manifest tests with strict warnings as errors (tools/gate.sh launcher).
cmake_minimum_required(VERSION 3.25)
project(confine_launcher LANGUAGES CXX)

find_package(PkgConfig REQUIRED)
pkg_check_modules(LIBSECCOMP REQUIRED IMPORTED_TARGET libseccomp>=2.5)

add_library(confine_launcher STATIC
  linux/box.cc
  linux/contract.cc
  linux/directory_box.cc
  linux/dynamic_box.cc
  linux/oneshot_box.cc)
target_include_directories(confine_launcher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_features(confine_launcher PUBLIC cxx_std_20)
target_link_libraries(confine_launcher PUBLIC PkgConfig::LIBSECCOMP)

if(PROJECT_IS_TOP_LEVEL)
  set(_strict -Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wno-sign-conversion -Werror)
  target_compile_options(confine_launcher PRIVATE ${_strict})
  enable_testing()
  add_executable(contract_test tests/contract_test.cc)
  target_link_libraries(contract_test PRIVATE confine_launcher)
  target_compile_options(contract_test PRIVATE ${_strict})
  add_test(NAME launcher.contract COMMAND contract_test)
  add_executable(manifest_test tests/manifest_test.cc)
  target_link_libraries(manifest_test PRIVATE confine_launcher)
  target_compile_options(manifest_test PRIVATE ${_strict})
  add_test(NAME launcher.manifest COMMAND manifest_test)
endif()
