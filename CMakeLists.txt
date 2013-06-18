#==================================================================================================#
#                                                                                                  #
#  Copyright (c) 2012 MaidSafe.net limited                                                         #
#                                                                                                  #
#  The following source code is property of MaidSafe.net limited and is not meant for external     #
#  use.  The use of this code is governed by the license file licence.txt found in the root        #
#  directory of this project and also on www.maidsafe.net.                                         #
#                                                                                                  #
#  You are not free to copy, amend or otherwise use this source code without the explicit written  #
#  permission of the board of directors of MaidSafe.net.                                           #
#                                                                                                  #
#==================================================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.10 FATAL_ERROR)
project(rudp)

include(../../cmake_modules/standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)
include_directories(${passport_SOURCE_DIR}/include)
include_directories(${private_SOURCE_DIR}/include)


#==================================================================================================#
# Set up all files as GLOBs                                                                        #
#==================================================================================================#
set(RudpSourcesDir ${PROJECT_SOURCE_DIR}/src/maidsafe/rudp)
glob_dir(Rudp ${RudpSourcesDir} Rudp)
glob_dir(RudpCore ${RudpSourcesDir}/core "Core\\\\")
glob_dir(RudpOperations ${RudpSourcesDir}/operations "Operations\\\\")
glob_dir(RudpPackets ${RudpSourcesDir}/packets "Packets\\\\")

glob_dir(RudpTests ${RudpSourcesDir}/tests "Main Test")
list(REMOVE_ITEM RudpTestsAllFiles ${RudpSourcesDir}/tests/performance_tool.cc
                                   ${RudpSourcesDir}/tests/rudp_node.cc
                                   ${RudpSourcesDir}/tests/rudp_node_impl.h
                                   ${RudpSourcesDir}/tests/rudp_node_impl.cc)
glob_dir(RudpCoreTests ${RudpSourcesDir}/core/tests "Core Test")
glob_dir(RudpOperationsTests ${RudpSourcesDir}/operations/tests "Operations Test")
glob_dir(RudpPacketsTests ${RudpSourcesDir}/packets/tests "Packets Test")


#==================================================================================================#
# Define MaidSafe libraries and executables                                                        #
#==================================================================================================#
ms_add_static_library(rudp ${RudpAllFiles} ${RudpCoreAllFiles} ${RudpOperationsAllFiles} ${RudpPacketsAllFiles})
target_link_libraries(maidsafe_rudp maidsafe_common)

if(MaidsafeTesting)
  ms_add_executable(TESTrudp "Tests/RUDP" ${RudpTestsAllFiles}
                                          ${RudpCoreTestsAllFiles}
#                                          ${RudpOperationsTestsAllFiles}
                                          ${RudpPacketsTestsAllFiles})
#  ms_add_executable(rudp_performance_tool "Tools" ${RudpSourcesDir}/tests/performance_tool.cc
#                                                  ${RudpSourcesDir}/tests/test_utils.cc
#                                                  ${RudpSourcesDir}/tests/test_utils.h)
#  ms_add_executable(rudp_node "Tools" ${RudpSourcesDir}/tests/rudp_node.cc
#                                      ${RudpSourcesDir}/tests/rudp_node_impl.h
#                                      ${RudpSourcesDir}/tests/rudp_node_impl.cc)
  target_link_libraries(TESTrudp maidsafe_rudp)
#  target_link_libraries(rudp_performance_tool maidsafe_rudp)
#  target_link_libraries(rudp_node maidsafe_rudp maidsafe_passport)
endif()

rename_outdated_built_exes()


#==================================================================================================#
# Set compiler and linker flags                                                                    #
#==================================================================================================#
include(standard_flags)


#==================================================================================================#
# Tests                                                                                            #
#==================================================================================================#
if(MaidsafeTesting)
  add_style_test()
  add_gtests(TESTrudp)
  label_as_critical_tests(ManagedConnectionsFuncTest.FUNC_API_NetworkSingle1kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkSingle256kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkSingle512kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkSingle1MBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkSingle2MBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkMultiple1kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkMultiple256kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkMultiple512kBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkMultiple1MBMessages
                          ManagedConnectionsFuncTest.FUNC_API_NetworkMultiple2MBMessages
                          ManagedConnectionsTest.BEH_API_RandomSizeSetup
                          ManagedConnectionsTest.BEH_API_Bootstrap
                          ManagedConnectionsTest.BEH_API_GetAvailableEndpoint
                          ManagedConnectionsTest.BEH_API_PendingConnectionsPruning
                          ManagedConnectionsTest.BEH_API_Add
                          ManagedConnectionsTest.BEH_API_AddDuplicateBootstrap
                          ManagedConnectionsTest.BEH_API_Remove
                          ManagedConnectionsTest.BEH_API_SimpleSend
                          ManagedConnectionsTest.FUNC_API_Send
                          ManagedConnectionsTest.FUNC_API_ParallelSend
                          ManagedConnectionsTest.FUNC_API_ParallelReceive
                          ManagedConnectionsTest.BEH_API_BootstrapTimeout
                          ManagedConnectionsTest.FUNC_API_ConcurrentGetAvailablesAndAdds
                          )
  add_project_experimental()
  test_summary_output()
endif()
