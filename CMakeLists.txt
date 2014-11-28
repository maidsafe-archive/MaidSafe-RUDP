#==================================================================================================#
#                                                                                                  #
#  Copyright 2012 MaidSafe.net limited                                                             #
#                                                                                                  #
#  This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,        #
#  version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which    #
#  licence you accepted on initial access to the Software (the "Licences").                        #
#                                                                                                  #
#  By contributing code to the MaidSafe Software, or to this project generally, you agree to be    #
#  bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root        #
#  directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available   #
#  at: http://www.maidsafe.net/licenses                                                            #
#                                                                                                  #
#  Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed    #
#  under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF   #
#  ANY KIND, either express or implied.                                                            #
#                                                                                                  #
#  See the Licences for the specific language governing permissions and limitations relating to    #
#  use of the MaidSafe Software.                                                                   #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/../../cmake_modules/standard_setup.cmake")
  cmake_minimum_required(VERSION 2.8)  # To suppress warning cluttering error message
  set(Msg "\nThis project can currently only be build as part of the MaidSafe super-project.  For")
  set(Msg "${Msg} full details, see https://github.com/maidsafe/MaidSafe/wiki/Build-Instructions\n")
  message(FATAL_ERROR "${Msg}")
endif()

project(rudp)

include(../../cmake_modules/standard_setup.cmake)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(RudpSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/rudp)
ms_glob_dir(Rudp ${RudpSourcesDir} Rudp)
ms_glob_dir(RudpCore ${RudpSourcesDir}/core "Core\\\\")
ms_glob_dir(RudpOperations ${RudpSourcesDir}/operations "Operations\\\\")
ms_glob_dir(RudpPackets ${RudpSourcesDir}/packets "Packets\\\\")

ms_glob_dir(RudpTests ${RudpSourcesDir}/tests "Main Test")
list(REMOVE_ITEM RudpTestsAllFiles ${RudpSourcesDir}/tests/performance_tool.cc
                                   ${RudpSourcesDir}/tests/rudp_node.cc
                                   ${RudpSourcesDir}/tests/rudp_node_impl.h
                                   ${RudpSourcesDir}/tests/rudp_node_impl.cc
                                   ${RudpSourcesDir}/tests/udp_client.cc
                                   ${RudpSourcesDir}/tests/udp_echo_server.cc)
ms_glob_dir(RudpCoreTests ${RudpSourcesDir}/core/tests "Core Test")
ms_glob_dir(RudpOperationsTests ${RudpSourcesDir}/operations/tests "Operations Test")
ms_glob_dir(RudpPacketsTests ${RudpSourcesDir}/packets/tests "Packets Test")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(maidsafe_rudp ${RudpAllFiles} ${RudpCoreAllFiles} ${RudpOperationsAllFiles} ${RudpPacketsAllFiles})
target_include_directories(maidsafe_rudp PUBLIC ${PROJECT_SOURCE_DIR}/include PRIVATE ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(maidsafe_rudp maidsafe_common)

if(INCLUDE_TESTS)
  ms_add_executable(test_rudp "Tests/RUDP" ${RudpTestsAllFiles}
                                           ${RudpCoreTestsAllFiles}
#                                           ${RudpOperationsTestsAllFiles}
                                           ${RudpPacketsTestsAllFiles})
  target_include_directories(test_rudp PRIVATE ${PROJECT_SOURCE_DIR}/src)
  ms_add_executable(rudp_performance_tool "Tools/RUDP" ${RudpSourcesDir}/tests/performance_tool.cc
                                                       ${RudpSourcesDir}/tests/test_utils.cc
                                                       ${RudpSourcesDir}/tests/test_utils.h)
  target_include_directories(rudp_performance_tool PRIVATE ${PROJECT_SOURCE_DIR}/src)
#  ms_add_executable(rudp_node "Tools/RUDP" ${RudpSourcesDir}/tests/rudp_node.cc
#                                           ${RudpSourcesDir}/tests/rudp_node_impl.h
#                                           ${RudpSourcesDir}/tests/rudp_node_impl.cc)
  target_link_libraries(test_rudp maidsafe_rudp maidsafe_test BoostIostreams)
  target_link_libraries(rudp_performance_tool maidsafe_rudp maidsafe_test)
#  target_link_libraries(rudp_node maidsafe_rudp maidsafe_passport)
  ms_add_executable(udp_server "Tools/RUDP"
                    "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/tests/udp_echo_server.cc")
  ms_add_executable(udp_client "Tools/RUDP"
                    "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/tests/udp_client.cc")
  target_link_libraries(udp_server maidsafe_rudp)
  target_link_libraries(udp_client maidsafe_rudp)
endif()

ms_rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(INCLUDE_TESTS)
  ms_add_default_tests()
  ms_add_gtests(test_rudp)
  ms_add_gtests(rudp_performance_tool)
  ms_test_summary_output()
endif()


#==================================================================================================#
# Package                                                                                          #
#==================================================================================================#
install(TARGETS maidsafe_rudp COMPONENT Development CONFIGURATIONS Debug Release ARCHIVE DESTINATION lib)
install(DIRECTORY ${PROJECT_SOURCE_DIR}/include/ COMPONENT Development DESTINATION include)

if(INCLUDE_TESTS)
  install(TARGETS test_rudp COMPONENT Tests CONFIGURATIONS Debug RUNTIME DESTINATION bin/debug)
  install(TARGETS test_rudp COMPONENT Tests CONFIGURATIONS Release RUNTIME DESTINATION bin)
  install(TARGETS udp_server udp_client COMPONENT Tools CONFIGURATIONS Debug RUNTIME DESTINATION bin/debug)
  install(TARGETS udp_server udp_client COMPONENT Tools CONFIGURATIONS Release RUNTIME DESTINATION bin)
endif()
