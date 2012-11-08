#==============================================================================#
#                                                                              #
#  Copyright (c) 2012 MaidSafe.net limited                                     #
#                                                                              #
#  The following source code is property of MaidSafe.net limited and is not    #
#  meant for external use.  The use of this code is governed by the license    #
#  file licence.txt found in the root directory of this project and also on    #
#  www.maidsafe.net.                                                           #
#                                                                              #
#  You are not free to copy, amend or otherwise use this source code without   #
#  the explicit written permission of the board of directors of MaidSafe.net.  #
#                                                                              #
#==============================================================================#


set(CMAKE_DISABLE_SOURCE_CHANGES ON)
set(CMAKE_DISABLE_IN_SOURCE_BUILD ON)

cmake_minimum_required(VERSION 2.8.7 FATAL_ERROR)
project(rudp)

include(../../cmake_modules/maidsafe_standard_setup.cmake)

include_directories(${common_SOURCE_DIR}/include)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
file(GLOB SOURCE_FILES_RUDP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/*.cc")
file(GLOB HEADER_FILES_RUDP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/*.h")
file(GLOB API_FILES_RUDP_DIR "${PROJECT_SOURCE_DIR}/include/maidsafe/rudp/*.h")
set(ALL_FILES_RUDP_DIR ${SOURCE_FILES_RUDP_DIR} ${HEADER_FILES_RUDP_DIR} ${API_FILES_RUDP_DIR})
source_group("RUDP Source Files" FILES ${SOURCE_FILES_RUDP_DIR})
source_group("RUDP Header Files" FILES ${HEADER_FILES_RUDP_DIR})
source_group("RUDP API Files" FILES ${API_FILES_RUDP_DIR})

file(GLOB SOURCE_FILES_RUDP_CORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/core/*.cc")
file(GLOB HEADER_FILES_RUDP_CORE_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/core/*.h")
set(ALL_FILES_RUDP_CORE_DIR ${SOURCE_FILES_RUDP_CORE_DIR} ${HEADER_FILES_RUDP_CORE_DIR})
source_group("RUDP Core Source Files" FILES ${SOURCE_FILES_RUDP_CORE_DIR})
source_group("RUDP Core Header Files" FILES ${HEADER_FILES_RUDP_CORE_DIR})

file(GLOB SOURCE_FILES_RUDP_OPERATIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/operations/*.cc")
file(GLOB HEADER_FILES_RUDP_OPERATIONS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/operations/*.h")
set(ALL_FILES_RUDP_OPERATIONS_DIR ${SOURCE_FILES_RUDP_OPERATIONS_DIR} ${HEADER_FILES_RUDP_OPERATIONS_DIR})
source_group("RUDP Operations Source Files" FILES ${SOURCE_FILES_RUDP_OPERATIONS_DIR})
source_group("RUDP Operations Header Files" FILES ${HEADER_FILES_RUDP_OPERATIONS_DIR})

file(GLOB SOURCE_FILES_RUDP_PACKETS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/packets/*.cc")
file(GLOB HEADER_FILES_RUDP_PACKETS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/packets/*.h")
set(ALL_FILES_RUDP_PACKETS_DIR ${SOURCE_FILES_RUDP_PACKETS_DIR} ${HEADER_FILES_RUDP_PACKETS_DIR})
source_group("RUDP Packets Source Files" FILES ${SOURCE_FILES_RUDP_PACKETS_DIR})
source_group("RUDP Packets Header Files" FILES ${HEADER_FILES_RUDP_PACKETS_DIR})

set(ALL_FILES
    ${ALL_FILES_RUDP_DIR}
    ${ALL_FILES_RUDP_CORE_DIR}
    ${ALL_FILES_RUDP_OPERATIONS_DIR}
    ${ALL_FILES_RUDP_PACKETS_DIR})
set(STYLE_RUDP ${ALL_FILES})

####    TESTS    ####
file(GLOB SOURCE_FILES_RUDP_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/tests/*.cc")
file(GLOB HEADER_FILES_RUDP_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/tests/*.h")
set(ALL_FILES_RUDP_TESTS_DIR ${SOURCE_FILES_RUDP_TESTS_DIR} ${HEADER_FILES_RUDP_TESTS_DIR})
source_group("Main Test Source Files" FILES ${SOURCE_FILES_RUDP_TESTS_DIR})
source_group("Main Test Header Files" FILES ${HEADER_FILES_RUDP_TESTS_DIR})

file(GLOB SOURCE_FILES_RUDP_CORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/core/tests/*.cc")
file(GLOB HEADER_FILES_RUDP_CORE_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/core/tests/*.h")
set(ALL_FILES_RUDP_CORE_TESTS_DIR ${SOURCE_FILES_RUDP_CORE_TESTS_DIR} ${HEADER_FILES_RUDP_CORE_TESTS_DIR})
source_group("Core Test Source Files" FILES ${SOURCE_FILES_RUDP_CORE_TESTS_DIR})
source_group("Core Test Header Files" FILES ${HEADER_FILES_RUDP_CORE_TESTS_DIR})

file(GLOB SOURCE_FILES_RUDP_OPERATIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/operations/tests/*.cc")
file(GLOB HEADER_FILES_RUDP_OPERATIONS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/operations/tests/*.h")
set(ALL_FILES_RUDP_OPERATIONS_TESTS_DIR ${SOURCE_FILES_RUDP_OPERATIONS_TESTS_DIR} ${HEADER_FILES_RUDP_OPERATIONS_TESTS_DIR})
source_group("Operations Test Source Files" FILES ${SOURCE_FILES_RUDP_OPERATIONS_TESTS_DIR})
source_group("Operations Test Header Files" FILES ${HEADER_FILES_RUDP_OPERATIONS_TESTS_DIR})

file(GLOB SOURCE_FILES_RUDP_PACKETS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/packets/tests/*.cc")
file(GLOB HEADER_FILES_RUDP_PACKETS_TESTS_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/rudp/packets/tests/*.h")
set(ALL_FILES_RUDP_PACKETS_TESTS_DIR ${SOURCE_FILES_RUDP_PACKETS_TESTS_DIR} ${HEADER_FILES_RUDP_PACKETS_TESTS_DIR})
source_group("Packets Test Source Files" FILES ${SOURCE_FILES_RUDP_PACKETS_TESTS_DIR})
source_group("Packets Test Header Files" FILES ${HEADER_FILES_RUDP_PACKETS_TESTS_DIR})

set(ALL_TEST_FILES
    ${ALL_FILES_RUDP_TESTS_DIR}
    ${ALL_FILES_RUDP_CORE_TESTS_DIR}
#     ${ALL_FILES_RUDP_OPERATIONS_TESTS_DIR}
    ${ALL_FILES_RUDP_PACKETS_TESTS_DIR})
set(STYLE_RUDP ${STYLE_RUDP} ${ALL_TEST_FILES})


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
ms_add_static_library(rudp ${ALL_FILES})
target_link_libraries(maidsafe_rudp maidsafe_common)

if(MAIDSAFE_TESTING)
  ms_add_executable(TESTrudp "Tests/RUDP" ${ALL_TEST_FILES})
  target_link_libraries(TESTrudp maidsafe_rudp)
endif()

rename_outdated_built_exes()


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
include(maidsafe_standard_flags)


###################################################################################################
# Tests                                                                                           #
###################################################################################################
if(MAIDSAFE_TESTING)
  add_style_test(${STYLE_RUDP})
  add_gtests(TESTrudp)
  add_project_experimental()
  test_summary_output()
endif()
