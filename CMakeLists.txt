#==============================================================================#
#                                                                              #
#  Copyright (c) 2010 maidsafe.net limited                                     #
#  All rights reserved.                                                        #
#                                                                              #
#  Redistribution and use in source and binary forms, with or without          #
#  modification, are permitted provided that the following conditions are met: #
#                                                                              #
#      * Redistributions of source code must retain the above copyright        #
#        notice, this list of conditions and the following disclaimer.         #
#      * Redistributions in binary form must reproduce the above copyright     #
#        notice, this list of conditions and the following disclaimer in the   #
#        documentation and/or other materials provided with the distribution.  #
#      * Neither the name of the maidsafe.net limited nor the names of its     #
#        contributors may be used to endorse or promote products derived from  #
#        this software without specific prior written permission.              #
#                                                                              #
#  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" #
#  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE   #
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE  #
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE  #
#  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR         #
#  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF        #
#  SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS    #
#  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN     #
#  CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)     #
#  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE  #
#  POSSIBILITY OF SUCH DAMAGE.                                                 #
#                                                                              #
#==============================================================================#
#                                                                              #
#  Written by maidsafe.net team                                                #
#                                                                              #
#==============================================================================#


CMAKE_MINIMUM_REQUIRED(VERSION 2.8 FATAL_ERROR)
MESSAGE("================================================================================\n")
SET(CMAKE_CACHEFILE "${CMAKE_CACHEFILE_DIR}/CMakeCache.txt")
IF(WIN32)
  STRING(REPLACE "/" "\\" CMAKE_CACHEFILE ${CMAKE_CACHEFILE})
ENDIF()

SET(ERROR_MESSAGE "No generator previously specified.  Run:\n")
SET(ERROR_MESSAGE_CMAKE_PATH "cmake ../../..")
GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after PROJECT command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"Visual Studio 9 2008\"\n\n")
ELSEIF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE()
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH}\n\n")
ENDIF()

IF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()


SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  SET(PROJECT_NAME maidsafe_dht)
ELSE()
  SET(PROJECT_NAME maidsafe_dht_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)


# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)

SET(${PROJECT_NAME}_ROOT ${PROJECT_SOURCE_DIR})
SET(${PROJECT_NAME}_SOURCE_DIR ${${PROJECT_NAME}_ROOT}/src)
SET(SOURCE_DIR ${${PROJECT_NAME}_ROOT}/src)

IF(NOT MAIDSAFE_TEST_TYPE)
  SET(MAIDSAFE_TEST_TYPE "ALL" CACHE STRING "Choose the type of TEST, options are: ALL BEH FUNC" FORCE)
  SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: All")
ELSE()
  IF(${MAIDSAFE_TEST_TYPE} MATCHES _)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: All")
  ELSEIF(${MAIDSAFE_TEST_TYPE} MATCHES BEH)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Behavioural")
  ELSEIF(${MAIDSAFE_TEST_TYPE} MATCHES FUNC)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Functional")
  ELSE()
    SET(MAIDSAFE_TEST_TYPE "_" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
    SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: All")
  ENDIF()
ENDIF()

ENABLE_TESTING()
SET_PROPERTY(GLOBAL PROPERTY USE_FOLDERS ON)

IF(UNIX)
  EXECUTE_PROCESS(COMMAND date +%a%d%m%y OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
ELSE()
  EXECUTE_PROCESS(COMMAND CMD /C DATE /T OUTPUT_VARIABLE pddate OUTPUT_STRIP_TRAILING_WHITESPACE)
  STRING(REPLACE "/" "" pddate ${pddate})
  STRING(SUBSTRING ${pddate} 0 4 pddateddmm)
  STRING(SUBSTRING ${pddate} 6 2 pddateyy)
  SET(pddate ${pddateddmm}${pddateyy})
  STRING(REPLACE " " "_" pddate ${pddate})
ENDIF()

IF(APPLE)
  SET(CMAKE_OSX_SYSROOT "/")
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  IF(MSVC)
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is OK to release.")
    MESSAGE("-----------------------------------------------------------------------")
  ENDIF()
ELSE()
  IF(MSVC)
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is NOT OK to release.")
    MESSAGE("---------------------------------------------------------------------------")
  ENDIF()
  SET(pddate "DEVELOPER_${pddate}")
ENDIF()

SET(CMAKE_include_directories_BEFORE ON)

# setup a single target path for libraries and executables -
# this avoids copying all the dlls and exes together
UNSET(CMAKE_RUNTIME_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_LIBRARY_OUTPUT_DIRECTORY CACHE)
UNSET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY CACHE)
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Executable target dir (x64).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Shared library target dir (x64).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/x64 CACHE PATH "Static library target dir (x64).")
  ELSE()
    SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Executable target dir (win32).")
    SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Shared library target dir (win32).")
    SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin/win32 CACHE PATH "Static library target dir (win32).")
  ENDIF()
ELSE()
  SET(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Executable target dir.")
  SET(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Shared library target dir.")
  SET(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${${PROJECT_NAME}_BINARY_DIR}/bin CACHE PATH "Static library target dir.")
ENDIF()

IF(NOT DEFINED ${KDEV})
  SET(CMAKE_DEBUG_POSTFIX _d)
  SET(CMAKE_RELWITHDEBINFO_POSTFIX _rwdi)
  SET(CMAKE_MINSIZEREL_POSTFIX _msr)

  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET(TEST_POSTFIX ${CMAKE_DEBUG_POSTFIX})
  ELSEIF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
    SET(TEST_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})
  ELSEIF(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
    SET(TEST_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})
  ENDIF()
ENDIF()
# Create CTestCustom.cmake to avoid inclusion of coverage results from third-party code
FILE(WRITE ${${PROJECT_NAME}_BINARY_DIR}/CTestCustom.cmake "SET(CTEST_CUSTOM_COVERAGE_EXCLUDE \${CTEST_CUSTOM_COVERAGE_EXCLUDE} \".pb.\" \"cryptopp/\" \"distributed_network/\" \"libupnp/\" \"nat-pmp/\" \"protobuf/\" \"tests/\" \"thirdpartylibs/\" \"upnp/\")\n\n")

###################################################################################################
# Set default directories to be searched for include files and libs                              #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${${PROJECT_NAME}_ROOT}/build)

IF(DEFINED ADD_LIBRARY_DIR)
  IF(DEFAULT_LIBRARY_DIR)
    LIST(REMOVE_DUPLICATES DEFAULT_LIBRARY_DIR)
  ENDIF()
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE PATH "Path to libraries directories" FORCE)
ENDIF()

###################################################################################################
# MaidSafe Common library search                                                                  #
###################################################################################################
INCLUDE(maidsafe_FindCommon)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${MaidSafeCommon_INCLUDE_DIR})

###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
SET(REQUIRED_BOOST_COMPONENTS date_time filesystem program_options regex system thread unit_test_framework)
INCLUDE(maidsafe_FindBoost)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})

###################################################################################################
# Cryptopp library search                                                                         #
###################################################################################################
INCLUDE(maidsafe_FindCryptopp)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Cryptopp_INCLUDE_DIR})

###################################################################################################
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(maidsafe_FindGtest)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
IF(NOT WIN32)
  SET(Gtest_LIBRARY "${Gtest_LIBRARY};pthread")
ENDIF()

###################################################################################################
# Google Mock library search                                                                      #
###################################################################################################
INCLUDE(maidsafe_FindGmock)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gmock_INCLUDE_DIR})

###################################################################################################
# Google Log library search                                                                       #
###################################################################################################
INCLUDE(maidsafe_FindGlog)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Glog_INCLUDE_DIR})

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES_KADEMLIA RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/*.proto")
FILE(GLOB PROTO_FILES_TRANSPORT RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/*.proto")
SET(PROTO_FILES "${PROTO_FILES_KADEMLIA};${PROTO_FILES_TRANSPORT}")
INCLUDE(maidsafe_FindProtobuf)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})

###################################################################################################
# MySQL++ library search                                                                          #
###################################################################################################
#INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindMysqlpp.cmake)
IF(Mysqlpp_FOUND)
  SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Mysqlpp_INCLUDE_DIR} ${Mysql_INCLUDE_DIR})
  SET(LIBS_DIRS ${LIBS_DIRS} ${Mysqlpp_LIBRARY_DIR} ${Mysql_LIBRARY_DIR})
  SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Mysqlpp_LIBRARY_DIR_DEBUG} ${Mysql_LIBRARY_DIR_DEBUG})
ENDIF()

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
FIND_PACKAGE(PythonInterp)
IF(PYTHONINTERP_FOUND)
  MESSAGE("-- Found python executable: style checking enabled.")
ELSE()
  MESSAGE("-- Didn't find python executable: style checking disabled.")
ENDIF()

###################################################################################################
# All other libraries search                                                                      #
###################################################################################################
IF(UNIX)
  SET(SYS_LIB dl pthread)
  IF(NOT APPLE)
    SET(SYS_LIB rt c m ${SYS_LIB})
  ENDIF()
ELSEIF(WIN32)
  IF(MSVC)
    SET(SYS_LIB ws2_32 odbc32 odbccp32 WSock32 IPHlpApi)
  ELSE()
    SET(SYS_LIB advapi32 kernel32 ws2_32 iphlpapi mswsock)
  ENDIF()
ENDIF()
FOREACH(library ${SYS_LIB})
  FIND_LIBRARY(CURRENT_LIB ${library})
  IF(CURRENT_LIB)
    MESSAGE("-- Found library ${CURRENT_LIB}")
    GET_FILENAME_COMPONENT(CURRENT_LIBRARY_DIR ${CURRENT_LIB} PATH)
    SET(LIBS_DIRS ${LIBS_DIRS} ${CURRENT_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${CURRENT_LIBRARY_DIR})
  ELSE()
    SET(ERROR_MESSAGE "\nCould not find library ${library}.")
    IF(MSVC)
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}\nRun cmake from a Visual Studio Command Prompt.")
    ELSE()
      SET(ERROR_MESSAGE "${ERROR_MESSAGE}  Run\n${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to ${library} directory>")
    ENDIF()
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  UNSET(CURRENT_LIB CACHE)
ENDFOREACH()

LIST(REMOVE_DUPLICATES LIBS_DIRS)
LIST(REMOVE_DUPLICATES LIBS_DIRS_DEBUG)
LINK_DIRECTORIES(${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

INCLUDE_DIRECTORIES(BEFORE ${${PROJECT_NAME}_SOURCE_DIR})
LIST(REMOVE_DUPLICATES INCLUDE_DIRS)
INCLUDE_DIRECTORIES(BEFORE SYSTEM ${INCLUDE_DIRS})

MESSAGE("================================================================================")

IF(MSVC)
  SET(CMAKE_CXX_FLAGS "")
  SET(CMAKE_CXX_FLAGS_INIT "")
  SET(CMAKE_CXX_FLAGS_RELEASE "")
  SET(CMAKE_CXX_FLAGS_DEBUG "")
ENDIF()

###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
FILE(GLOB SOURCE_FILES_MAIDSAFE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/*.cc")
FILE(GLOB HEADER_FILES_MAIDSAFE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/*.h")
SET(ALL_FILES_MAIDSAFE_DIR ${SOURCE_FILES_MAIDSAFE_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
SOURCE_GROUP("maidsafe-dht Source Files" FILES ${SOURCE_FILES_MAIDSAFE_DIR})
SOURCE_GROUP("maidsafe-dht Header Files" FILES ${HEADER_FILES_MAIDSAFE_DIR})

FILE(GLOB SOURCE_FILES_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/*.cc")
FILE(GLOB HEADER_FILES_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/*.h")
SET(ALL_FILES_KADEMLIA_DIR ${SOURCE_FILES_KADEMLIA_DIR} ${HEADER_FILES_KADEMLIA_DIR})
SET(STYLE_KADEMLIA ${ALL_FILES_KADEMLIA_DIR})
LIST(REMOVE_ITEM STYLE_KADEMLIA "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/kademlia.pb.cc")
LIST(REMOVE_ITEM STYLE_KADEMLIA "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/kademlia.pb.h")
LIST(REMOVE_ITEM STYLE_KADEMLIA "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/rpcs.pb.cc")
LIST(REMOVE_ITEM STYLE_KADEMLIA "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/rpcs.pb.h")
SOURCE_GROUP("kademlia Source Files" FILES ${SOURCE_FILES_KADEMLIA_DIR})
SOURCE_GROUP("kademlia Header Files" FILES ${HEADER_FILES_KADEMLIA_DIR})

LIST(APPEND ALL_FILES_LIBUPNP_DIR
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/igd_desc_parse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/minixml.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/minisoap.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/miniwget.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/upnpcommands.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/upnpreplyparse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/upnperrors.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/miniupnpc.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/libupnp/minissdpc.c)
SOURCE_GROUP("libupnp Source Files" FILES ${ALL_FILES_LIBUPNP_DIR})

FILE(GLOB SOURCE_FILES_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/nat-pmp/*.cc")
FILE(GLOB HEADER_FILES_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/nat-pmp/*.h")
SET(ALL_FILES_NATPMP_DIR ${SOURCE_FILES_NATPMP_DIR} ${HEADER_FILES_NATPMP_DIR})
SOURCE_GROUP("nat-pnp Source Files" FILES ${SOURCE_FILES_NATPMP_DIR})
SOURCE_GROUP("nat-pnp Header Files" FILES ${HEADER_FILES_NATPMP_DIR})

FILE(GLOB SOURCE_FILES_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/*.cc")
FILE(GLOB HEADER_FILES_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/*.h")
SET(ALL_FILES_TRANSPORT_DIR ${SOURCE_FILES_TRANSPORT_DIR} ${HEADER_FILES_TRANSPORT_DIR})
SET(STYLE_TRANSPORT ${ALL_FILES_TRANSPORT_DIR})
LIST(REMOVE_ITEM STYLE_TRANSPORT "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/transport.pb.cc")
LIST(REMOVE_ITEM STYLE_TRANSPORT "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/transport.pb.h")
SOURCE_GROUP("transport Source Files" FILES ${SOURCE_FILES_TRANSPORT_DIR})
SOURCE_GROUP("transport Header Files" FILES ${HEADER_FILES_TRANSPORT_DIR})

FILE(GLOB SOURCE_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/upnp/*.cc")
FILE(GLOB HEADER_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/upnp/*.h")
LIST(REMOVE_ITEM SOURCE_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/upnp/upnp_client_impl.cc")
LIST(REMOVE_ITEM HEADER_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/upnp/upnp_client_impl.h")
SET(ALL_FILES_UPNP_DIR ${SOURCE_FILES_UPNP_DIR} ${HEADER_FILES_UPNP_DIR})
SOURCE_GROUP("upnp Source Files" FILES ${SOURCE_FILES_UPNP_DIR})
SOURCE_GROUP("upnp Header Files" FILES ${HEADER_FILES_UPNP_DIR})

LIST(APPEND DHT_SOURCE_FILES ${ALL_FILES_KADEMLIA_DIR}
                             ${ALL_FILES_TRANSPORT_DIR}
                             ${ALL_FILES_LIBUPNP_DIR}
                             ${ALL_FILES_UPNP_DIR}
                             ${ALL_FILES_NATPMP_DIR}
                             ${ALL_FILES_MAIDSAFE_DIR})

####    TESTS    ####
FILE(GLOB ALL_FILES_TEST_MAIN "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/*.cc"
                              "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/*.h")
FILE(GLOB ALL_FILES_TEST_BENCHMARK_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/benchmark/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/benchmark/*.h")
FILE(GLOB ALL_FILES_TEST_DEMO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/demo/*.cc"
                                  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/demo/*.h")
FILE(GLOB ALL_FILES_TEST_NODE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/functional_kademlia/*.cc"
                                                "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/functional_kademlia/*.h")
LIST(REMOVE_ITEM ALL_FILES_TEST_NODE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/functional_kademlia/testnodefunctional.cc")
FILE(GLOB ALL_FILES_TEST_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/*.cc"
                                      "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/*.h")
FILE(GLOB ALL_FILES_TEST_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/nat-pmp/*.cc"
                                    "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/nat-pmp/*.h")
FILE(GLOB ALL_FILES_TEST_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/transport/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/transport/*.h")
FILE(GLOB ALL_FILES_TEST_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/upnp/*.cc"
                                  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/upnp/*.h")
IF(Mysqlpp_FOUND)
  FILE(GLOB ALL_FILES_NETWORK_TEST_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/distributed_network/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/distributed_network/*.h")
ENDIF()


###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTkademlia ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_KADEMLIA_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTnode EXCLUDE_FROM_ALL ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_FUNCTIONAL_KADEMLIA_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTtransport ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_TRANSPORT_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTnatpmp ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_NATPMP_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTupnp ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_UPNP_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
# Need to use __declspec(dllimport) in all API header files before linking to SHARED library target
#ADD_EXECUTABLE(kaddemo ${ALL_FILES_TEST_DEMO_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(KademliaDemo EXCLUDE_FROM_ALL ${ALL_FILES_TEST_DEMO_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
#ADD_EXECUTABLE(benchmark ${ALL_FILES_TEST_BENCHMARK_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(benchmark_static EXCLUDE_FROM_ALL ${ALL_FILES_TEST_BENCHMARK_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
IF(Mysqlpp_FOUND)
  ADD_EXECUTABLE(distributed_net_clients EXCLUDE_FROM_ALL ${ALL_FILES_NETWORK_TEST_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ENDIF()

# Force renaming of exes to match standard CMake library renaming policy
IF(NOT MSVC)
  SET_TARGET_PROPERTIES(TESTkademlia PROPERTIES
                          DEBUG_OUTPUT_NAME TESTkademlia${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTkademlia${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTkademlia${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTnode PROPERTIES
                          DEBUG_OUTPUT_NAME TESTnode${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTnode${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTnode${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTtransport PROPERTIES
                          DEBUG_OUTPUT_NAME TESTtransport${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTtransport${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTtransport${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTnatpmp PROPERTIES
                          DEBUG_OUTPUT_NAME TESTnatpmp${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTnatpmp${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTnatpmp${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTupnp PROPERTIES
                          DEBUG_OUTPUT_NAME TESTupnp${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTupnp${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTupnp${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(KademliaDemo PROPERTIES
                          DEBUG_OUTPUT_NAME KademliaDemo${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME KademliaDemo${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME KademliaDemo${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(benchmark_static PROPERTIES
                          DEBUG_OUTPUT_NAME benchmark_static${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME benchmark_static${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME benchmark_static${CMAKE_MINSIZEREL_POSTFIX})
  IF(Mysqlpp_FOUND)
    SET_TARGET_PROPERTIES(distributed_net_clients PROPERTIES
                            DEBUG_OUTPUT_NAME distributed_net_clients${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME distributed_net_clients${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME distributed_net_clients${CMAKE_MINSIZEREL_POSTFIX})
  ENDIF()
ENDIF()

SET(TEST_TARGETS TESTupnp TESTnatpmp TESTnode TESTkademlia TESTtransport)
SET_TARGET_PROPERTIES(${TEST_TARGETS} KademliaDemo benchmark_static PROPERTIES FOLDER "Tests")
IF(Mysqlpp_FOUND)
  SET_TARGET_PROPERTIES(distributed_net_clients PROPERTIES FOLDER "Tests")
ENDIF()

# Need to use __declspec(dllexport) in all API header files before adding SHARED library target
#ADD_LIBRARY(maidsafe_dht SHARED ${DHT_SOURCE_FILES})
ADD_LIBRARY(maidsafe_dht_static STATIC ${DHT_SOURCE_FILES})

#Rename maidsafe_dht_static as maidsafe_dht on way out NOT in MSVC names clash of static and import lib
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES OUTPUT_NAME maidsafe_dht)
#ENDIF()

# When this target is built, it removes all .gcda files from the build directory and its subdirectories
IF(UNIX)
  FIND_FILE(CLEAN_COVERAGE_CMAKE clean_coverage.cmake ${MaidSafeCommon_MODULES_DIR})
  IF(CLEAN_COVERAGE_CMAKE)
    ADD_CUSTOM_TARGET(CleanCoverage COMMAND ${CMAKE_COMMAND} -DSEARCH_DIR=${CMAKE_BINARY_DIR} -P ${CLEAN_COVERAGE_CMAKE})
  ENDIF()
ENDIF()

SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES FOLDER "MaidSafe Libraries")


###################################################################################################
# Builds                                                                                          #
###################################################################################################
ADD_DEFINITIONS(-DSTATICLIB)
ADD_DEFINITIONS(-DBOOST_FILESYSTEM_NO_DEPRECATED -DBOOST_FILESYSTEM_VERSION=3)

TARGET_LINK_LIBRARIES(maidsafe_dht_static
                        maidsafe_common_static
                        ${Cryptopp_LIBRARY}
                        ${Protobuf_LIBRARY}
                        ${Glog_LIBRARY}
                        ${Boost_DATE_TIME_LIBRARIES}
                        ${Boost_FILESYSTEM_LIBRARIES}
                        ${Boost_THREAD_LIBRARIES}
                        ${Boost_SYSTEM_LIBRARIES}
                        ${Boost_REGEX_LIBRARIES}
                        ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static ${Gtest_LIBRARY} ${Gmock_LIBRARY})
TARGET_LINK_LIBRARIES(TESTnode maidsafe_dht_static ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static ${Gtest_LIBRARY})
TARGET_LINK_LIBRARIES(KademliaDemo maidsafe_dht_static ${Boost_PROGRAM_OPTIONS_LIBRARIES})
TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static ${Boost_PROGRAM_OPTIONS_LIBRARIES})
IF(Mysqlpp_FOUND)
  TARGET_LINK_LIBRARIES(distributed_net_clients maidsafe_dht_static ${Mysqlpp_LIBRARY})
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  ADD_DEFINITIONS(-DDEBUG)
ENDIF()

IF(WIN32)
  ADD_DEFINITIONS(-DWIN32 -D_WIN32 -D__WINDOWS__ -D__WIN32__)
ENDIF()

IF(MSVC)
  ADD_DEFINITIONS(-D__MSVC__ -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501)
  ADD_DEFINITIONS(-D_CONSOLE -D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)

  # prevents std::min() and std::max() to be overwritten
  ADD_DEFINITIONS(-DNOMINMAX)

  # flag to link to static version of Google Glog
  ADD_DEFINITIONS(-DGOOGLE_GLOG_DLL_DECL=)

  # prevents from automatic linking of boost libraries
  ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB)

  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MT /Gy /W4 /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /EHsc /MTd /W4 /c /ZI /TP")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "/EHsc /MT")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/EHsc /MT")

  # warning 4503 disabled due to excessive generation through use of Boost multi_index
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/node.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/routing_table.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_contact.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/functional_kademlia/test_node.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/nat-pmp/test_natpmp.cc
                                PROPERTIES COMPILE_FLAGS "/wd4503")

  # warnings 4503, 4512 & 4996 disabled due to generation through use of Boost Signals2
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/message_handler.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/message_handler.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/contact.cc
                                PROPERTIES COMPILE_FLAGS "/wd4503 /wd4512 /wd4996")

  # warning level set low for protocol buffer generated files
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/transport.pb.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/kademlia.pb.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/rpcs.pb.cc
                                PROPERTIES COMPILE_FLAGS "/W0")

  # CMake defaults to passing stack size in LINKER_FLAGS of 10MB.  Set this to windows default of 1MB
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}")
  STRING(REGEX REPLACE "/STACK:[0-9]+" "" CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS}")

  # Given a link dir of "a/b/c", MSVC adds "a/b/c/" AND "a/b/c/CMAKE_BUILD_TYPE" as link dirs, so we
  # can't just use "LINK_DIRECTORIES" as some Google debug libs have the same name as the release version.
  FOREACH(LIBS_DIR ${LIBS_DIRS})
    STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
    SET(LINKER_LIBS_DIRS_RELEASE "${LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
  ENDFOREACH()
  FOREACH(LIBS_DIR_DEBUG ${LIBS_DIRS_DEBUG})
    STRING(REPLACE "\\" "\\\\" LIBS_DIR_DEBUG ${LIBS_DIR_DEBUG})
    SET(LINKER_LIBS_DIRS_DEBUG "${LINKER_LIBS_DIRS_DEBUG} /LIBPATH:\"${LIBS_DIR_DEBUG}\"")
  ENDFOREACH()
  SET_TARGET_PROPERTIES(TESTkademlia TESTnode TESTnatpmp TESTtransport TESTupnp KademliaDemo benchmark_static PROPERTIES
                          LINK_FLAGS "/STACK:1048576"
                          LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                          LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                          LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
  IF(Mysqlpp_FOUND)
    SET_TARGET_PROPERTIES(distributed_net_clients PROPERTIES
                            LINK_FLAGS "/STACK:1048576"
                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${LINKER_LIBS_DIRS_RELEASE}"
                            LINK_FLAGS_DEBUG "${LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_RELWITHDEBINFO "${LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_MINSIZEREL "${LINKER_LIBS_DIRS_DEBUG}")
  ENDIF()

  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
ENDIF()


IF(UNIX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem ${CMAKE_INCLUDE_PATH} -isystem -W -Wall -Wextra -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
  FILE(GLOB PROTO_SOURCE_FILES_KADEMLIA "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/*.pb.cc")
  FILE(GLOB PROTO_SOURCE_FILES_TRANSPORT "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/*.pb.cc")
  SET(PROTO_SOURCE_FILES "${PROTO_SOURCE_FILES_KADEMLIA};${PROTO_SOURCE_FILES_TRANSPORT}")
  SET_SOURCE_FILES_PROPERTIES(${PROTO_SOURCE_FILES}
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/main.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_node_id.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_service.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_routing_table.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_datastore.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_contact.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/nat-pmp/test_natpmp.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/transport/test_tcp_transport.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/upnp/test_upnp.cc
                                PROPERTIES COMPILE_FLAGS "-w")
  IF(APPLE)
    ADD_DEFINITIONS(-DMAIDSAFE_APPLE -DBSD)
    SET(CMAKE_AR "/usr/bin/libtool")
    SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE")
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -D__FreeBSD__=10 -Wshadow -Wunused-variable -Wunused-parameter -Wunused-function -Wunused -Wno-system-headers -Wno-deprecated -Woverloaded-virtual -Wwrite-strings -Wuninitialized")
    SET(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> -static -o <TARGET> <LINK_FLAGS> <OBJECTS>" "<CMAKE_RANLIB> <TARGET>")
    SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov")
  ELSE()
    ADD_DEFINITIONS(-DMAIDSAFE_LINUX)
    SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -pedantic -pedantic-errors -std=c++0x -Weffc++")
  ENDIF()
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/kademlia/test_node_impl.cc" PROPERTY COMPILE_FLAGS "-w")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/rpcs.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/node_impl.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/service.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/tcp_transport.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/tcp_connection.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/tests/transport/test_transport_api.cc" PROPERTY COMPILE_FLAGS "-w -fPIC -Wall -Wextra -pedantic -pedantic-errors -std=c++0x")
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
INCLUDE(CTest)
INCLUDE(maidsafe_AddGtests)

SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CONTINUOUS_DURATION 600)
SET(CTEST_CONTINUOUS_MINIMUM_INTERVAL 10)
SET(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK_KAD python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${STYLE_KADEMLIA} ${ALL_FILES_TEST_KADEMLIA_DIR} ${ALL_FILES_TEST_FUNCTIONAL_KADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_TRANSPORT python ${MaidSafeCommon_TOOLS_DIR}/cpplint.py ${STYLE_TRANSPORT} ${ALL_FILES_TEST_TRANSPORT_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_TRANSPORT PROPERTY LABELS Functional Transport CodingStyle)
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${${PROJECT_NAME}_ROOT})
    ADD_TEST(STYLE_CHECK ${MaidSafeCommon_TOOLS_DIR}/run_cpplint.bat ${STYLE_CHECK_SOURCE})
    SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
  ENDIF()
ENDIF()

FOREACH(TEST_TARGET ${TEST_TARGETS})
  ADD_GTESTS(${TEST_TARGET})
ENDFOREACH()

IF(UNIX)
  SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF()

IF(INSTALL_PREFIX)
  IF(WIN32)
    STRING(REPLACE "\\" "/" INSTALL_PREFIX ${INSTALL_PREFIX})
  ENDIF()
  SET(CMAKE_INSTALL_PREFIX "${INSTALL_PREFIX}")
ENDIF()

###################################################################################################
MESSAGE("")
LIST(LENGTH ALL_GTESTS GTEST_COUNT)
MESSAGE("${MAIDSAFE_TEST_TYPE_MESSAGE}.   ${GTEST_COUNT} Google Tests.")
MESSAGE("")
MESSAGE("    To include all tests,                ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=ALL")
MESSAGE("    To include behavioural tests,        ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=BEH")
MESSAGE("    To include functional tests,        ${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_TEST_TYPE=FUNC")
MESSAGE("================================================================================")
MESSAGE("")
MESSAGE("Install prefix is set to \"${CMAKE_INSTALL_PREFIX}\"")
MESSAGE("")
IF(WIN32)
  MESSAGE("    To alter this (e.g. to c:\\dht),       ${ERROR_MESSAGE_CMAKE_PATH} -DINSTALL_PREFIX=c:\\dht")
ELSE()
  MESSAGE("    To alter this (e.g. to /usr),           ${ERROR_MESSAGE_CMAKE_PATH} -DINSTALL_PREFIX=/usr")
ENDIF()
MESSAGE("================================================================================")
MESSAGE("")

SET(MAIDSAFE_KAD_INSTALL_FILES
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/node-api.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/config.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/contact.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/node_id.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/kademlia/message_handler.h)
SET(MAIDSAFE_MAIN_INSTALL_FILES
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/maidsafe-dht.h)
SET(MAIDSAFE_TRANS_INSTALL_FILES
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/transport.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/message_handler.h
      ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe-dht/transport/tcp_transport.h)

IF(MSVC)
  INSTALL(TARGETS maidsafe_dht_static # maidsafe_dht
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib
          )
ELSE()
  INSTALL(TARGETS maidsafe_dht_static # maidsafe_dht
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
          )
ENDIF()

INSTALL(FILES ${MAIDSAFE_KAD_INSTALL_FILES} DESTINATION include/maidsafe-dht/kademlia)
INSTALL(FILES ${MAIDSAFE_MAIN_INSTALL_FILES} DESTINATION include/maidsafe-dht)
INSTALL(FILES ${MAIDSAFE_TRANS_INSTALL_FILES} DESTINATION include/maidsafe-dht/transport)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  SET(CPACK_PACKAGE_VERSION_MAJOR "0")
  SET(CPACK_PACKAGE_VERSION_MINOR "1")
  SET(CPACK_PACKAGE_VERSION_PATCH ${pddate})
  SET(CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})
  SET(CPACK_PACKAGE_NAME "maidsafe_dht")
  SET(CPACK_PACKAGE_CONTACT "dev@maidsafe.net")
  SET(CPACK_PACKAGE_VENDOR "maidsafe.net")
  SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Implementation of Kademlia DHT")
  SET(CPACK_PACKAGE_INSTALL_DIRECTORY "maidsafe-dht")
#  SET(CPACK_RESOURCE_FILE_README "${${PROJECT_NAME}_ROOT}/docs/readme.txt")
  IF(UNIX)
    SET(CPACK_SET_DESTDIR on)
    SET(CPACK_GENERATOR DEB;RPM;TGZ)
    MESSAGE("Package install directory is set to \"${CPACK_PACKAGE_INSTALL_DIRECTORY}\"")
    MESSAGE("================================================================================")
  ELSE()
    SET(CPACK_GENERATOR ZIP)
  ENDIF()
  INCLUDE(CPack)
ELSE()
  FILE(REMOVE ${${PROJECT_NAME}_BINARY_DIR}/CPackConfig.cmake ${${PROJECT_NAME}_BINARY_DIR}/CPackSourceConfig.cmake)
ENDIF()
