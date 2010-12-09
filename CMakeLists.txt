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
#  Significant contribution made by Stephan Menzel                             #
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
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - MinGW Makefiles\"\n\n")
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

IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (${KDEV}))
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
  SET(MAIDSAFE_TEST_TYPE "BEH" CACHE STRING "Choose the type of TEST, options are: _ BEH FUNC" FORCE)
  SET(MAIDSAFE_TEST_TYPE_MESSAGE "Tests included: Behavioural")
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

EXECUTE_PROCESS(COMMAND svn info ${${PROJECT_NAME}_SOURCE_DIR}/.. OUTPUT_VARIABLE SVN_INFO OUTPUT_STRIP_TRAILING_WHITESPACE)
IF(SVN_INFO)
  STRING(REGEX REPLACE "\n" ";" SVN_INFO ${SVN_INFO})
  FOREACH(SVN_INFO_LINE ${SVN_INFO})
    IF(SVN_INFO_LINE MATCHES ^Revision)
      SET(SVN_MESSAGE "Repository at ${SVN_INFO_LINE}")
    ENDIF()
  ENDFOREACH()
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  IF(MSVC)
    MESSAGE("${SVN_MESSAGE}")
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is OK to release.  ${SVN_MESSAGE}")
    MESSAGE("-----------------------------------------------------------------------")
  ENDIF()
ELSE()
  IF(MSVC)
    MESSAGE("${SVN_MESSAGE}")
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is NOT OK to release.  ${SVN_MESSAGE}")
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


IF(NOT ${KDEV})
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
FILE(WRITE ${${PROJECT_NAME}_BINARY_DIR}/CTestCustom.cmake "SET(CTEST_CUSTOM_COVERAGE_EXCLUDE \${CTEST_CUSTOM_COVERAGE_EXCLUDE} \"cryptopp/\" \"distributed_network/\" \"libupnp/\" \"nat-pmp/\" \"protobuf/\" \"tests/\" \"udt/\" \"upnp/\")\n\n")

###################################################################################################
# Set default directories to be searched for included files and libs                              #
###################################################################################################
IF(DEFINED ADD_LIBRARY_DIR)
  IF(DEFAULT_LIBRARY_DIR)
    LIST(REMOVE_DUPLICATES DEFAULT_LIBRARY_DIR)
  ENDIF()
  SET(DEFAULT_LIBRARY_DIR ${DEFAULT_LIBRARY_DIR} ${ADD_LIBRARY_DIR} CACHE PATH "Path to libraries directories" FORCE)
ENDIF()

IF(MSVC)
  SET(CMAKE_INCLUDE_PATH "c:\\msvc\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\msvc\\lib" ${DEFAULT_LIBRARY_DIR})
ELSEIF(WIN32) # MinGW builds
  SET(CMAKE_INCLUDE_PATH "c:\\MinGW\\include")
  SET(CMAKE_LIBRARY_PATH "c:\\MinGW\\lib" ${DEFAULT_LIBRARY_DIR})
ELSE()
  SET(CMAKE_INCLUDE_PATH "/usr/include")
  SET(CMAKE_LIBRARY_PATH "/usr/lib" ${DEFAULT_LIBRARY_DIR})
ENDIF()

###################################################################################################
# Boost libraries search                                                                          #
###################################################################################################
SET(REQUIRED_BOOST_COMPONENTS date_time filesystem program_options regex system thread unit_test_framework)
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindBoost.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Boost_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Boost_LIBRARY_DIRS})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Boost_LIBRARY_DIRS})

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.proto")
SET(PROTOBUF_REQUIRED FALSE)
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindProtobuf.cmake)
IF(NOT Protobuf_FOUND)
  SET(PROTOBUF_REQUIRED TRUE)
  INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_BuildProtobuf.cmake)
ENDIF()
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Protobuf_LIBRARY_DIR_DEBUG})

###################################################################################################
# Google Mock and Test library                                                                    #
###################################################################################################
SET(gtest_force_shared_crt ON CACHE INTERNAL "" FORCE)
ADD_SUBDIRECTORY(${${PROJECT_NAME}_ROOT}/thirdpartylibs/googlemock)
INCLUDE_DIRECTORIES(BEFORE ${gtest_SOURCE_DIR}/include ${gtest_SOURCE_DIR} ${gmock_SOURCE_DIR}/include ${gmock_SOURCE_DIR})

###################################################################################################
# Google Log library search - Glog can't currently be compiled on Windows with MinGW              #
###################################################################################################
IF((NOT WIN32) OR MSVC)
  INCLUDE(${${PROJECT_NAME}_ROOT}/build//maidsafe_FindGlog.cmake)
  IF(Glog_FOUND)
    SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Glog_INCLUDE_DIR})
    SET(LIBS_DIRS ${LIBS_DIRS} ${Glog_LIBRARY_DIR})
    SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Glog_LIBRARY_DIR_DEBUG})
  ENDIF()
ENDIF()

###################################################################################################
# MySQL++ library search                                                                          #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindMysqlpp.cmake)
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
FILE(GLOB SOURCE_FILES_MAIDSAFE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.cc")
FILE(GLOB HEADER_FILES_MAIDSAFE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.h")
SET(ALL_FILES_MAIDSAFE_DIR ${SOURCE_FILES_MAIDSAFE_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
SOURCE_GROUP("maidsafe Source Files" FILES ${SOURCE_FILES_MAIDSAFE_DIR})
SOURCE_GROUP("maidsafe Header Files" FILES ${HEADER_FILES_MAIDSAFE_DIR})

FILE(GLOB SOURCE_FILES_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/*.cc")
FILE(GLOB HEADER_FILES_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/*.h")
SET(ALL_FILES_BASE_DIR ${SOURCE_FILES_BASE_DIR} ${HEADER_FILES_BASE_DIR})
SOURCE_GROUP("base Source Files" FILES ${SOURCE_FILES_BASE_DIR})
SOURCE_GROUP("base Header Files" FILES ${HEADER_FILES_BASE_DIR})

FILE(GLOB SOURCE_FILES_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/*.cc")
FILE(GLOB HEADER_FILES_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/*.h")
SET(ALL_FILES_KADEMLIA_DIR ${SOURCE_FILES_KADEMLIA_DIR} ${HEADER_FILES_KADEMLIA_DIR})
SET(STYLE_KADEMLIA ${ALL_FILES_KADEMLIA_DIR})
SOURCE_GROUP("kademlia Source Files" FILES ${SOURCE_FILES_KADEMLIA_DIR})
SOURCE_GROUP("kademlia Header Files" FILES ${HEADER_FILES_KADEMLIA_DIR})

LIST(APPEND ALL_FILES_LIBUPNP_DIR
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/igd_desc_parse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minixml.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minisoap.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/miniwget.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnpcommands.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnpreplyparse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnperrors.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/miniupnpc.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minissdpc.c)
SOURCE_GROUP("libupnp Source Files" FILES ${ALL_FILES_LIBUPNP_DIR})

FILE(GLOB SOURCE_FILES_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/nat-pmp/*.cc")
FILE(GLOB HEADER_FILES_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/nat-pmp/*.h")
SET(ALL_FILES_NATPMP_DIR ${SOURCE_FILES_NATPMP_DIR} ${HEADER_FILES_NATPMP_DIR})
SOURCE_GROUP("nat-pnp Source Files" FILES ${SOURCE_FILES_NATPMP_DIR})
SOURCE_GROUP("nat-pnp Header Files" FILES ${HEADER_FILES_NATPMP_DIR})

FILE(GLOB SOURCE_FILES_PROTOBUF_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.cc*")
FILE(GLOB HEADER_FILES_PROTOBUF_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.h")
SET(ALL_FILES_PROTOBUF_DIR ${SOURCE_FILES_PROTOBUF_DIR} ${HEADER_FILES_PROTOBUF_DIR})
SOURCE_GROUP("protobuf Source Files" FILES ${SOURCE_FILES_PROTOBUF_DIR})
SOURCE_GROUP("protobuf Header Files" FILES ${HEADER_FILES_PROTOBUF_DIR})

FILE(GLOB SOURCE_FILES_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/rpcprotocol/*.cc")
FILE(GLOB HEADER_FILES_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/rpcprotocol/*.h")
SET(ALL_FILES_RPCPROTO_DIR ${SOURCE_FILES_RPCPROTO_DIR} ${HEADER_FILES_RPCPROTO_DIR})
SOURCE_GROUP("rpcprotocol Source Files" FILES ${SOURCE_FILES_RPCPROTO_DIR})
SOURCE_GROUP("rpcprotocol Header Files" FILES ${HEADER_FILES_RPCPROTO_DIR})

FILE(GLOB SOURCE_FILES_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/*.cc")
FILE(GLOB HEADER_FILES_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/*.h")
SET(ALL_FILES_TRANSPORT_DIR ${SOURCE_FILES_TRANSPORT_DIR} ${HEADER_FILES_TRANSPORT_DIR})
SOURCE_GROUP("transport Source Files" FILES ${SOURCE_FILES_TRANSPORT_DIR})
SOURCE_GROUP("transport Header Files" FILES ${HEADER_FILES_TRANSPORT_DIR})

FILE(GLOB SOURCE_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/*.cc")
FILE(GLOB HEADER_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/*.h")
LIST(REMOVE_ITEM SOURCE_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM HEADER_FILES_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/upnpclientimpl.h")
SET(ALL_FILES_UPNP_DIR ${SOURCE_FILES_UPNP_DIR} ${HEADER_FILES_UPNP_DIR})
SOURCE_GROUP("upnp Source Files" FILES ${SOURCE_FILES_UPNP_DIR})
SOURCE_GROUP("upnp Header Files" FILES ${HEADER_FILES_UPNP_DIR})

LIST(APPEND DHT_SOURCE_FILES ${ALL_FILES_BASE_DIR}
                             ${ALL_FILES_KADEMLIA_DIR}
                             ${ALL_FILES_TRANSPORT_DIR}
                             ${ALL_FILES_PROTOBUF_DIR}
                             ${ALL_FILES_RPCPROTO_DIR}
                             ${ALL_FILES_LIBUPNP_DIR}
                             ${ALL_FILES_UPNP_DIR}
                             ${ALL_FILES_NATPMP_DIR}
                             ${ALL_FILES_MAIDSAFE_DIR})

####    TESTS    ####
FILE(GLOB ALL_FILES_TEST_MAIN "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/*.cc"
                              "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/*.h")
FILE(GLOB ALL_FILES_TEST_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/base/*.cc"
                                  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/base/*.h")
FILE(GLOB ALL_FILES_TEST_BENCHMARK_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/benchmark/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/benchmark/*.h")
FILE(GLOB ALL_FILES_TEST_BOOST_DIR  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/boost/*.cc")
FILE(GLOB ALL_FILES_TEST_DEMO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/demo/*.cc"
                                  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/demo/*.h")
FILE(GLOB ALL_FILES_TEST_FUNCTIONALKADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/*.cc"
                                                "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/*.h")
LIST(REMOVE_ITEM ALL_FILES_TEST_FUNCTIONALKADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/testknodefunctional.cc")
FILE(GLOB ALL_FILES_TEST_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/*.cc"
                                      "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/*.h")
FILE(GLOB ALL_FILES_TEST_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/*.cc"
                                    "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/*.h")
FILE(GLOB ALL_FILES_TEST_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/*.cc"
                                      "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/*.h")
SET(STYLE_RPCPROTO_DIR ${ALL_FILES_TEST_RPCPROTO_DIR})
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/testservices.pb.cc")
FILE(GLOB ALL_FILES_TEST_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/*.h")
FILE(GLOB ALL_FILES_TEST_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/upnp/*.cc"
                                  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/upnp/*.h")
IF(Mysqlpp_FOUND)
  FILE(GLOB ALL_FILES_NETWORK_TEST_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/distributed_network/*.cc"
                                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/distributed_network/*.h")
ENDIF()

###################################################################################################
# Traverse subdirs for imported 3rd party libs                                                    #
###################################################################################################
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/udt ${CMAKE_BINARY_DIR}/udt)
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/cryptopp ${CMAKE_BINARY_DIR}/cryptopp)

###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTbase ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_BASE_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTkademlia ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_KADEMLIA_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTknode ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_FUNCTIONALKADEMLIA_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTtransport ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_TRANSPORT_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTrpcprotocol ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_RPCPROTO_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTnatpmp ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_NATPMP_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTupnp ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_UPNP_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(TESTboost ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_BOOST_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/log.cc")
# Need to use __declspec(dllimport) in all API header files before linking to SHARED library target
#ADD_EXECUTABLE(kaddemo ${ALL_FILES_TEST_DEMO_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(kaddemo_static ${ALL_FILES_TEST_DEMO_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
#ADD_EXECUTABLE(benchmark ${ALL_FILES_TEST_BENCHMARK_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ADD_EXECUTABLE(benchmark_static ${ALL_FILES_TEST_BENCHMARK_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
IF(Mysqlpp_FOUND)
  ADD_EXECUTABLE(distributed_net_clients ${ALL_FILES_NETWORK_TEST_DIR} ${HEADER_FILES_MAIDSAFE_DIR})
ENDIF()

# Force renaming of exes to match standard CMake library renaming policy
IF(NOT MSVC)
  SET_TARGET_PROPERTIES(TESTbase PROPERTIES
                          DEBUG_OUTPUT_NAME TESTbase${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTbase${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTbase${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTkademlia PROPERTIES
                          DEBUG_OUTPUT_NAME TESTkademlia${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTkademlia${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTkademlia${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTknode PROPERTIES
                          DEBUG_OUTPUT_NAME TESTknode${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTknode${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTknode${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTtransport PROPERTIES
                          DEBUG_OUTPUT_NAME TESTtransport${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTtransport${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTtransport${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTrpcprotocol PROPERTIES
                          DEBUG_OUTPUT_NAME TESTrpcprotocol${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTrpcprotocol${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTrpcprotocol${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTnatpmp PROPERTIES
                          DEBUG_OUTPUT_NAME TESTnatpmp${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTnatpmp${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTnatpmp${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTupnp PROPERTIES
                          DEBUG_OUTPUT_NAME TESTupnp${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTupnp${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTupnp${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(kaddemo_static PROPERTIES
                          DEBUG_OUTPUT_NAME kaddemo_static${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME kaddemo_static${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME kaddemo_static${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(benchmark_static PROPERTIES
                          DEBUG_OUTPUT_NAME benchmark_static${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME benchmark_static${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME benchmark_static${CMAKE_MINSIZEREL_POSTFIX})
  SET_TARGET_PROPERTIES(TESTboost PROPERTIES
                          DEBUG_OUTPUT_NAME TESTboost${CMAKE_DEBUG_POSTFIX}
                          RELWITHDEBINFO_OUTPUT_NAME TESTboost${CMAKE_RELWITHDEBINFO_POSTFIX}
                          MINSIZEREL_OUTPUT_NAME TESTboost${CMAKE_MINSIZEREL_POSTFIX})
  IF(Mysqlpp_FOUND)
    SET_TARGET_PROPERTIES(distributed_net_clients PROPERTIES
                            DEBUG_OUTPUT_NAME distributed_net_clients${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME distributed_net_clients${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME distributed_net_clients${CMAKE_MINSIZEREL_POSTFIX})
  ENDIF()
ENDIF()
# Need to use __declspec(dllexport) in all API header files before adding SHARED library target
#ADD_LIBRARY(maidsafe_dht SHARED ${DHT_SOURCE_FILES})
ADD_LIBRARY(maidsafe_dht_static STATIC ${DHT_SOURCE_FILES})
TARGET_LINK_LIBRARIES(maidsafe_dht_static udt_static cryptopp_static)

#Rename maidsafe_dht_static as maidsafe_dht on way out NOT in MSVC names clash of static and import lib
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES OUTPUT_NAME maidsafe_dht)
#ENDIF()

# When this target is built, it removes all .gcda files from the build directory and its subdirectories
IF(UNIX)
  ADD_CUSTOM_TARGET(CleanCoverage COMMAND ${CMAKE_COMMAND} -DSEARCH_DIR=${CMAKE_BINARY_DIR} -P ${${PROJECT_NAME}_ROOT}/build/tools/clean_coverage.cmake)
ENDIF()

###################################################################################################
# Builds                                                                                          #
###################################################################################################
ADD_DEFINITIONS(-DSTATICLIB)
IF(Glog_FOUND)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
ADD_DEFINITIONS(-DBOOST_FILESYSTEM_NO_DEPRECATED -DBOOST_FILESYSTEM_VERSION=3)

#Ensure we pick up correct libs and not some older installed one
IF(MSVC)
#  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.lib)
#  SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.dll)
#  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES IMPORTED_LOCATION bin/libcryptopp.lib)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.dll)
#  SET_TARGET_PROPERTIES(udt_static PROPERTIES IMPORTED_LOCATION bin/libudt.lib)
#  SET_TARGET_PROPERTIES(udt PROPERTIES  IMPORTED_LOCATION bin/libudt.dll)
ELSE()
  IF(WIN32)
#    SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.dll)
#    SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.dll)
#    SET_TARGET_PROPERTIES(udt PROPERTIES IMPORTED_LOCATION bin/libudt.dll)
  ELSE()
#    SET_TARGET_PROPERTIES(maidsafe_dht PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.so)
#    SET_TARGET_PROPERTIES(cryptopp PROPERTIES IMPORTED_LOCATION bin/libcryptopp.so)
#    SET_TARGET_PROPERTIES(udt PROPERTIES IMPORTED_LOCATION bin/libudt.so)
  ENDIF()
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES IMPORTED_LOCATION bin/libmaidsafe_dht.a)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES IMPORTED_LOCATION bin/libcryptopp.a)
  SET_TARGET_PROPERTIES(udt_static PROPERTIES IMPORTED_LOCATION bin/libudt.a)
ENDIF()

TARGET_LINK_LIBRARIES(maidsafe_dht_static
                        udt_static
                        cryptopp_static
                        ${Protobuf_LIBRARY}
                        ${Glog_LIBRARY}
                        ${Boost_DATE_TIME_LIBRARIES}
                        ${Boost_FILESYSTEM_LIBRARIES}
                        ${Boost_THREAD_LIBRARIES}
                        ${Boost_SYSTEM_LIBRARIES}
                        ${Boost_REGEX_LIBRARIES}
                        ${SYS_LIB})
TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static gtest_main gmock_main)
TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static gtest_main)
TARGET_LINK_LIBRARIES(TESTboost ${Glog_LIBRARY} ${Boost_UNIT_TEST_FRAMEWORK_LIBRARIES} gtest_main ${SYS_LIB})
TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static ${Boost_PROGRAM_OPTIONS_LIBRARIES})
TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static ${Boost_PROGRAM_OPTIONS_LIBRARIES})
IF(Mysqlpp_FOUND)
  TARGET_LINK_LIBRARIES(distributed_net_clients maidsafe_dht_static ${Mysqlpp_LIBRARY})
ENDIF()

IF(NOT MSVC)
#  IF(WIN32)
#    TARGET_LINK_LIBRARIES(maidsafe_dht "-Wl,--enable-auto-import" udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo "-Wl,--enable-auto-import" maidsafe_dht udt cryptopp)
#    TARGET_LINK_LIBRARIES(benchmark "-Wl,--enable-auto-import" maidsafe_dht udt cryptopp)
#  ELSEIF(APPLE)
#    TARGET_LINK_LIBRARIES(maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(benchmark maidsafe_dht udt cryptopp ${SYS_LIB})
#  ELSE()
#    TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht udt cryptopp ${SYS_LIB})
#    TARGET_LINK_LIBRARIES(benchmark maidsafe_dht udt cryptopp ${SYS_LIB})
#  ENDIF()
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  ADD_DEFINITIONS(-DDEBUG)
ENDIF()

IF(WIN32)
  ADD_DEFINITIONS(-DWIN32 -D_WIN32 -D__WINDOWS__ -D__WIN32__)
ENDIF()

IF(MSVC)
  ADD_DEFINITIONS(-D__MSVC__ -DWIN32_LEAN_AND_MEAN -D_WIN32_WINNT=0x501 -DUDT_STATIC)
  ADD_DEFINITIONS(-D_CONSOLE -D_UNICODE -DUNICODE -D_BIND_TO_CURRENT_VCLIBS_VERSION=1)

  # prevents std::min() and std::max() to be overwritten
  ADD_DEFINITIONS(-DNOMINMAX)

  # flag to link to static version of Google Glog
  IF(Glog_FOUND)
    ADD_DEFINITIONS(-DGOOGLE_GLOG_DLL_DECL=)
  ENDIF()

  # prevents from automatic linking of boost libraries
  ADD_DEFINITIONS(-DBOOST_ALL_NO_LIB)

  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MD /Gy /W3 /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /EHsc /MDd  /c /ZI /TP")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "/EHsc /MD")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/EHsc /MD")

  # warning 4503 disabled due to excessive generation through use of Boost multi_index
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/knode.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/knode.h
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/routingtable.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/routingtable.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/routingtable.h
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testcontact.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/testknode.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/testnatpmp.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/testtransport.cc
                                PROPERTIES COMPILE_FLAGS "/wd4503")

  # warning 4996 disabled due to generation through use of Boost Signals2
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/udttransport.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/udtconnection.cc
                                PROPERTIES COMPILE_FLAGS "/wd4996")

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
  SET_TARGET_PROPERTIES(TESTbase TESTkademlia TESTknode TESTnatpmp TESTrpcprotocol TESTtransport TESTupnp kaddemo_static benchmark_static TESTboost PROPERTIES
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

  # Next version of CMake accommodates per-build-type STATIC_LIBRARY_FLAGS.  Until then, this has no effect.
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")
ENDIF()


IF(UNIX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -g -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -isystem ${CMAKE_INCLUDE_PATH} -isystem ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/ -isystem ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/ -W -Wall -Wextra -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -g -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
  SET_SOURCE_FILES_PROPERTIES(${SOURCE_FILES_PROTOBUF_DIR}
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/crypto.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/utils.cc
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
#  SET_PROPERTY(TARGET TESTkademlia PROPERTY COMPILE_FLAGS "-w")
  SET_PROPERTY(SOURCE "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknodeimpl.cc" PROPERTY COMPILE_FLAGS "-w")
ELSEIF(WIN32 AND NOT MSVC)
  ADD_DEFINITIONS(-D__MINGW__ -DWIN32_LEAN_AND_MEAN -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0501)
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG -DWIN32_LEAN_AND_MEAN -D__MINGW__  -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32 -D_WIN32_WINNT=0x0501")
  SET(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -Wextra -pedantic -Wuninitialized -D_WIN32_WINNT=0x0501 -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O2")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp PROPERTIES LINK_FLAGS "-lgcov -pg -fprofile-arcs -ftest-coverage")
  ENDIF()
  SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp kaddemo_static benchmark_static PROPERTIES LINK_FLAGS "-mthreads")
  IF(Mysqlpp_FOUND)
    SET_TARGET_PROPERTIES(distributed_net_clients PROPERTIES LINK_FLAGS "-mthreads")
  ENDIF()
ENDIF()


###################################################################################################
# Tests                                                                                           #
###################################################################################################
INCLUDE(CTest)

SET(CTEST_CUSTOM_MAXIMUM_PASSED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CUSTOM_MAXIMUM_FAILED_TEST_OUTPUT_SIZE 50000)
SET(CTEST_CONTINUOUS_DURATION 600)
SET(CTEST_CONTINUOUS_MINIMUM_INTERVAL 10)
SET(CTEST_START_WITH_EMPTY_BINARY_DIRECTORY true)
IF(PYTHONINTERP_FOUND)
  IF(UNIX)
    ADD_TEST(STYLE_CHECK_KAD python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${STYLE_KADEMLIA} ${ALL_FILES_TEST_KADEMLIA_DIR} ${ALL_FILES_TEST_FUNCTIONALKADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_BASE python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${ALL_FILES_BASE_DIR} ${ALL_FILES_TEST_BASE_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_BASE PROPERTY LABELS Functional Base CodingStyle)
    ADD_TEST(STYLE_CHECK_RPC python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${ALL_FILES_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_RPC PROPERTY LABELS Functional RpcProtocol CodingStyle)
    ADD_TEST(STYLE_CHECK_TRANSPORT python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${ALL_FILES_TRANSPORT_DIR} ${ALL_FILES_TEST_TRANSPORT_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_TRANSPORT PROPERTY LABELS Functional Transport CodingStyle)
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${${PROJECT_NAME}_ROOT})
    ADD_TEST(STYLE_CHECK ${${PROJECT_NAME}_ROOT}/build/tools/run_cpplint.bat ${STYLE_CHECK_SOURCE})
    SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
  ENDIF()
ENDIF()

FUNCTION(GET_TEST_PARAMETERS GTEST_SOURCE_FILE GTEST_GROUP_NAME)
  # Find start of parameter list
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_PARAMETER_CASE REGEX ^INSTANTIATE_TEST_CASE_P.*${GTEST_GROUP_NAME},)
  IF(NOT GTEST_PARAMETER_CASE)
    RETURN()
  ENDIF()
  # Get instantiation name
  STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_PARAMETER_CASE_AS_LIST ${GTEST_PARAMETER_CASE})
  LIST(GET GTEST_PARAMETER_CASE_AS_LIST 1 GTEST_INSTANTIATION_NAME)
  # Read file into variable FULL_FILE
  FILE(STRINGS ${GTEST_SOURCE_FILE} FULL_FILE REGEX .)
  # Get line number of start of parameter list
  LIST(FIND FULL_FILE ${GTEST_PARAMETER_CASE} PARAMETER_VALUES_INDEX)
  # Use comma count to add appendices to list until closing bracket is found
  SET(PARAMETER_COUNT 0)
  WHILE(NOT END_OF_PARAM_LIST)
    LIST(GET FULL_FILE ${PARAMETER_VALUES_INDEX} GTEST_PARAMS)
    STRING(REGEX MATCHALL [,] COMMA_LIST ${GTEST_PARAMS})
    FOREACH(COMMA ${COMMA_LIST})
      SET(GTEST_PARAMETER_APPENDICES ${GTEST_PARAMETER_APPENDICES} "/${PARAMETER_COUNT}")
      MATH(EXPR PARAMETER_COUNT ${PARAMETER_COUNT}+1)
    ENDFOREACH()
    STRING(REGEX MATCH [\)] END_OF_PARAM_LIST ${GTEST_PARAMS})
    MATH(EXPR PARAMETER_VALUES_INDEX ${PARAMETER_VALUES_INDEX}+1)
  ENDWHILE()
  IF(NOT PARAMETER_COUNT EQUAL 0)
    LIST(REMOVE_AT GTEST_PARAMETER_APPENDICES -1)
  ENDIF()
  SET(GTEST_INSTANTIATION_NAME ${GTEST_INSTANTIATION_NAME}/ PARENT_SCOPE)
  SET(GTEST_PARAMETER_APPENDICES ${GTEST_PARAMETER_APPENDICES} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(GET_TEST_TYPES GTEST_SOURCE_FILE GTEST_GROUP_NAME)
  # Find TYPED_TEST_CASE and retrieve associated typedef
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_TYPED_TEST_CASE REGEX ^TYPED_TEST_CASE)
  IF(NOT GTEST_TYPED_TEST_CASE)
    RETURN()
  ENDIF()
  STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_TYPED_TEST_CASE ${GTEST_TYPED_TEST_CASE})
  LIST(GET GTEST_TYPED_TEST_CASE 3 GTEST_TYPEDEF)
  # Get type list from typedef
  FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_TYPES REGEX ">\ ${GTEST_TYPEDEF}")
  # Read file into variable FULL_FILE
  FILE(STRINGS ${GTEST_SOURCE_FILE} FULL_FILE REGEX .)
  # Get line number of end of type list
  LIST(FIND FULL_FILE ${GTEST_TYPES} PARAMETER_VALUES_INDEX)
  # Use comma count to add appendices to list until opening bracket is found
  SET(PARAMETER_COUNT 0)
  SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} "/${PARAMETER_COUNT}")
  WHILE(NOT START_OF_TYPE_LIST)
    LIST(GET FULL_FILE ${PARAMETER_VALUES_INDEX} GTEST_PARAMS)
    STRING(REGEX MATCHALL [,] COMMA_LIST ${GTEST_PARAMS})
    FOREACH(COMMA ${COMMA_LIST})
      MATH(EXPR PARAMETER_COUNT ${PARAMETER_COUNT}+1)
      SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} "/${PARAMETER_COUNT}")
    ENDFOREACH()
    STRING(REGEX MATCH [<] START_OF_TYPE_LIST ${GTEST_PARAMS})
    MATH(EXPR PARAMETER_VALUES_INDEX ${PARAMETER_VALUES_INDEX}-1)
  ENDWHILE()
  SET(GTEST_TYPE_APPENDICES ${GTEST_TYPE_APPENDICES} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(ADD_MAIDSAFE_TEST GTEST_GROUP_NAME GTEST_NAME TEST_PATH)
  ADD_TEST(${GTEST_GROUP_NAME}.${GTEST_NAME} ${TEST_PATH} --gtest_filter=${GTEST_GROUP_NAME}.${GTEST_NAME})
  IF("${GTEST_NAME}" MATCHES "^FUNC_" OR "${GTEST_NAME}" MATCHES "^DISABLED_FUNC_")
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY LABELS Functional ${GTEST_GROUP_NAME})
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY TIMEOUT 600)
  ELSEIF("${GTEST_NAME}" MATCHES "^BEH_" OR "${GTEST_NAME}" MATCHES "^DISABLED_BEH_")
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY LABELS Behavioural ${GTEST_GROUP_NAME})
    SET_PROPERTY(TEST ${GTEST_GROUP_NAME}.${GTEST_NAME} PROPERTY TIMEOUT 60)
  ELSE()
    MESSAGE("")
    MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    MESSAGE("")
    MESSAGE(AUTHOR_WARNING "${GTEST_NAME} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
    MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
  ENDIF()
ENDFUNCTION()

SET(TEST_EXECUTABLES TESTupnp TESTnatpmp TESTbase TESTknode TESTkademlia TESTtransport TESTrpcprotocol TESTboost)
FOREACH(TEST_EXECUTABLE ${TEST_EXECUTABLES})
  IF(TEST_EXECUTABLE STREQUAL "TESTupnp")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_UPNP_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTnatpmp")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_NATPMP_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTbase")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_BASE_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTknode")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_FUNCTIONALKADEMLIA_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTkademlia")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_KADEMLIA_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTtransport")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_TRANSPORT_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTrpcprotocol")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_RPCPROTO_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTboost")
    SET(GTEST_SOURCE_FILES ${ALL_FILES_TEST_BOOST_DIR})
  ENDIF()
  FOREACH(GTEST_SOURCE_FILE ${GTEST_SOURCE_FILES})
    FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_NAMES REGEX "^(TYPED_)?TEST(_[FP])?\\(")
    SET(GTEST_NAMES ${GTEST_NAMES})
    FOREACH(GTEST_NAME ${GTEST_NAMES})
      STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_NAME ${GTEST_NAME})
      LIST(GET GTEST_NAME 0 GTEST_TEST_TYPE)
      LIST(GET GTEST_NAME 1 GTEST_GROUP_NAME)
      LIST(GET GTEST_NAME 3 GTEST_NAME)
      IF("${GTEST_NAME}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
        IF(${GTEST_TEST_TYPE} MATCHES ^TEST_P$)
          SET(GTEST_PARAMETER_APPENDICES)
          SET(GTEST_INSTANTIATION_NAME)
          GET_TEST_PARAMETERS(${GTEST_SOURCE_FILE} ${GTEST_GROUP_NAME})
          FOREACH(GTEST_PARAMETER_APPENDIX ${GTEST_PARAMETER_APPENDICES})
            ADD_MAIDSAFE_TEST(${GTEST_INSTANTIATION_NAME}${GTEST_GROUP_NAME} ${GTEST_NAME}${GTEST_PARAMETER_APPENDIX} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
          ENDFOREACH()
        ELSEIF(${GTEST_TEST_TYPE} MATCHES ^TYPED_TEST$)
          SET(GTEST_TYPE_APPENDICES)
          GET_TEST_TYPES(${GTEST_SOURCE_FILE} ${GTEST_GROUP_NAME})
          FOREACH(GTEST_TYPE_APPENDIX ${GTEST_TYPE_APPENDICES})
            ADD_MAIDSAFE_TEST(${GTEST_GROUP_NAME}${GTEST_TYPE_APPENDIX} ${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
          ENDFOREACH()
        ELSEIF(${GTEST_TEST_TYPE} MATCHES ^TYPED_TEST_P$)
          # MESSAGE("Ignoring ${GTEST_GROUP_NAME}.${GTEST_NAME}")
        ELSE()
          ADD_MAIDSAFE_TEST(${GTEST_GROUP_NAME} ${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX})
        ENDIF()
      ENDIF()
    ENDFOREACH()
  ENDFOREACH()
ENDFOREACH()
ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_SendOneMessageFromOneToAnother" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_SendOneMessageFromOneToAnother" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")

ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_StartListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_StartListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")

ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_PrepareToSend" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_PrepareToSend" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")

ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_StopListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_StopListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")

ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_StopAllListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_StopAllListening" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")

ADD_MAIDSAFE_TEST("TCP/TransportAPITest/0" "BEH_TRANS_Send" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
ADD_MAIDSAFE_TEST("UDT/TransportAPITest/0" "BEH_TRANS_Send" "${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/TESTtransport${TEST_POSTFIX}")
IF(UNIX)
  SET(MEMORYCHECK_COMMAND "/usr/bin/valgrind --show-reachable=no")
ENDIF()

IF(NOT INSTALL_PREFIX)
  IF(MINGW)
    SET(CMAKE_INSTALL_PREFIX "/MinGW")
  ELSEIF(NOT MSVC)
    SET(CMAKE_INSTALL_PREFIX "/usr")
  ENDIF()
ELSE()
  IF(WIN32)
    STRING(REPLACE "\\" "/" INSTALL_PREFIX ${INSTALL_PREFIX})
  ENDIF()
  SET(CMAKE_INSTALL_PREFIX "${INSTALL_PREFIX}")
ENDIF()

###################################################################################################
MESSAGE("")
MESSAGE("${MAIDSAFE_TEST_TYPE_MESSAGE}")
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

SET(MAIDSAFE_BASE_INSTALL_FILES
      maidsafe/base/alternativestore.h
      maidsafe/base/crypto.h
      maidsafe/base/log.h
      maidsafe/base/online.h
      maidsafe/base/routingtable.h
      maidsafe/base/utils.h
      maidsafe/base/validationinterface.h)
SET(MAIDSAFE_KAD_INSTALL_FILES
      maidsafe/kademlia/contact.h
      maidsafe/kademlia/kadid.h
      maidsafe/kademlia/knode-api.h)
SET(MAIDSAFE_MAIN_INSTALL_FILES
      maidsafe/maidsafe-dht.h
      maidsafe/maidsafe-dht_config.h)
SET(MAIDSAFE_PROTO_INSTALL_FILES
      maidsafe/protobuf/contact_info.pb.h
      maidsafe/protobuf/general_messages.pb.h
      maidsafe/protobuf/kademlia_service_messages.pb.h
      maidsafe/protobuf/signed_kadvalue.pb.h)
SET(MAIDSAFE_RPC_INSTALL_FILES
      maidsafe/rpcprotocol/channel-api.h
      maidsafe/rpcprotocol/channelmanager-api.h)
SET(MAIDSAFE_TRANS_INSTALL_FILES
      maidsafe/transport/transport.h
      maidsafe/transport/udttransport.h)
# Check the script /build/Win_MSVC/extract_includes.bat matches this list
FILE(STRINGS ${${PROJECT_NAME}_ROOT}/build/Win_MSVC/extract_includes.bat EXTRACT_INCLUDE_BAT)
STRING(REPLACE "\\" "/" EXTRACT_INCLUDE_BAT "${EXTRACT_INCLUDE_BAT}")
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_BASE_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_BASE_INSTALL_FILES ${ABS_MAIDSAFE_BASE_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_KAD_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_KAD_INSTALL_FILES ${ABS_MAIDSAFE_KAD_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_MAIN_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_MAIN_INSTALL_FILES ${ABS_MAIDSAFE_MAIN_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_PROTO_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_PROTO_INSTALL_FILES ${ABS_MAIDSAFE_PROTO_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_RPC_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_RPC_INSTALL_FILES ${ABS_MAIDSAFE_RPC_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
FOREACH(MAIDSAFE_INSTALL_FILE ${MAIDSAFE_TRANS_INSTALL_FILES})
  STRING(REGEX MATCH src/${MAIDSAFE_INSTALL_FILE} FOUND ${EXTRACT_INCLUDE_BAT})
  IF(NOT FOUND)
    MESSAGE(FATAL_ERROR "\nUpdate build/Win_MSVC/extract_includes.bat to include ${MAIDSAFE_INSTALL_FILE}\n")
  ENDIF()
  SET(ABS_MAIDSAFE_TRANS_INSTALL_FILES ${ABS_MAIDSAFE_TRANS_INSTALL_FILES} ${${PROJECT_NAME}_SOURCE_DIR}/${MAIDSAFE_INSTALL_FILE})
ENDFOREACH()
EXECUTE_PROCESS(COMMAND CMD /C "${${PROJECT_NAME}_ROOT}/build/Win_MSVC/extract_includes.bat > NUL 2>&1")

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

INSTALL(FILES ${ABS_MAIDSAFE_BASE_INSTALL_FILES} DESTINATION include/maidsafe/base)
INSTALL(FILES ${ABS_MAIDSAFE_KAD_INSTALL_FILES} DESTINATION include/maidsafe/kademlia)
INSTALL(FILES ${ABS_MAIDSAFE_MAIN_INSTALL_FILES} DESTINATION include/maidsafe)
INSTALL(FILES ${ABS_MAIDSAFE_PROTO_INSTALL_FILES} DESTINATION include/maidsafe/protobuf)
INSTALL(FILES ${ABS_MAIDSAFE_RPC_INSTALL_FILES} DESTINATION include/maidsafe/rpcprotocol)
INSTALL(FILES ${ABS_MAIDSAFE_TRANS_INSTALL_FILES} DESTINATION include/maidsafe/transport)

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  SET(CPACK_PACKAGE_VERSION_MAJOR "0")
  SET(CPACK_PACKAGE_VERSION_MINOR "1")
  SET(CPACK_PACKAGE_VERSION_PATCH ${pddate})
  SET(CPACK_PACKAGE_VERSION ${CPACK_PACKAGE_VERSION_MAJOR}.${CPACK_PACKAGE_VERSION_MINOR}.${CPACK_PACKAGE_VERSION_PATCH})
  SET(CPACK_PACKAGE_NAME "maidsafe_dht")
  SET(CPACK_PACKAGE_CONTACT "dev@maidsafe.net")
  SET(CPACK_PACKAGE_VENDOR "maidsafe.net")
  SET(CPACK_PACKAGE_DESCRIPTION_SUMMARY "Implementation of Kademlia DHT")
  SET(CPACK_PACKAGE_INSTALL_DIRECTORY "maidsafe")
  SET(CPACK_RESOURCE_FILE_README "${${PROJECT_NAME}_ROOT}/docs/readme.txt")
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
