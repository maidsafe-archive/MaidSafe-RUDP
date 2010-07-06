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
SET(KDEV 0)
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"Visual Studio 9 2008\"\n\n")
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Release)
  SET(ERROR_MESSAGE_CMAKE_PATH "   cmake ..\\..")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"Unix Makefiles\"\n\n")
  SET(KDEV 1)
ELSEIF(UNIX)
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\trm ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - Unix Makefiles\"\n\n")
ELSE()
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\tdel ${CMAKE_CACHEFILE}\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}then run e.g:\n\t${ERROR_MESSAGE_CMAKE_PATH} -G\"CodeBlocks - MinGW Makefiles\"\n\n")
ENDIF()



SET(ERROR_MESSAGE "${ERROR_MESSAGE}To see a full list of generators, run:\n\t${ERROR_MESSAGE_CMAKE_PATH} --help\n")
SET(CMAKE_GEN ${CMAKE_GENERATOR} CACHE INTERNAL "" FORCE)
IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR ${ERROR_MESSAGE})
ENDIF()

IF(CMAKE_BUILD_TYPE_DIR MATCHES "Release")
  SET(PROJECT_NAME maidsafe_dht)
ELSE()
  SET(PROJECT_NAME maidsafe_dht_${CMAKE_BUILD_TYPE_DIR})
ENDIF()
OPTION (BUILD_SHARED_LIBS "Build shared libraries." OFF)


# This call resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
PROJECT(${PROJECT_NAME})
SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR})

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

EXECUTE_PROCESS(COMMAND svn info OUTPUT_VARIABLE SVN_INFO OUTPUT_STRIP_TRAILING_WHITESPACE)
IF(SVN_INFO)
  STRING(REGEX REPLACE "\n" ";" SVN_INFO ${SVN_INFO})
  FOREACH(SVN_INFO_LINE ${SVN_INFO})
    IF(SVN_INFO_LINE MATCHES ^Revision)
      SET(SVN_MESSAGE "Repository at ${SVN_INFO_LINE}")
    ENDIF()
  ENDFOREACH()
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Release")
  IF(MSVC OR ${KDEV})
    MESSAGE("${SVN_MESSAGE}")
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is OK to release.  ${SVN_MESSAGE}")
    MESSAGE("-----------------------------------------------------------------------")
  ENDIF()
ELSE()
  IF(MSVC OR ${KDEV})
    MESSAGE("${SVN_MESSAGE}")
    MESSAGE("---------------------------")
  ELSE()
    MESSAGE("Building a package which is NOT OK to release.  ${SVN_MESSAGE}")
    MESSAGE("---------------------------------------------------------------------------")
  ENDIF()
  SET(pddate "DEVELOPER_${pddate}")
ENDIF()


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
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(TEST_POSTFIX ${CMAKE_DEBUG_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "RelWithDebInfo")
  SET(TEST_POSTFIX ${CMAKE_RELWITHDEBINFO_POSTFIX})
ELSEIF(CMAKE_BUILD_TYPE MATCHES "MinSizeRel")
  SET(TEST_POSTFIX ${CMAKE_MINSIZEREL_POSTFIX})
ENDIF()

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
# Google Test library search                                                                      #
###################################################################################################
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGtest.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Gtest_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Gtest_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Gtest_LIBRARY_DIR_DEBUG})

###################################################################################################
# Protocol Buffers library search                                                                 #
###################################################################################################
FILE(GLOB PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.proto")
FILE(GLOB TEST_PROTO_FILES RELATIVE ${${PROJECT_NAME}_SOURCE_DIR} "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/*.proto")
SET(PROTO_FILES ${PROTO_FILES} ${TEST_PROTO_FILES})
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindProtobuf.cmake)
SET(INCLUDE_DIRS ${INCLUDE_DIRS} ${Protobuf_INCLUDE_DIR})
SET(LIBS_DIRS ${LIBS_DIRS} ${Protobuf_LIBRARY_DIR})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG} ${Protobuf_LIBRARY_DIR_DEBUG})

###################################################################################################
# Python library search                                                                           #
###################################################################################################
UNSET(PYTHON_EXECUTABLE CACHE)
INCLUDE(FindPythonInterp)
INCLUDE(FindPythonLibs)
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
    SET(ERROR_MESSAGE "\nCould not find library ${library}.  Run\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DADD_LIBRARY_DIR=<Path to ${library} directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  UNSET(CURRENT_LIB CACHE)
ENDFOREACH()

IF(MSVC)
  SET(SYS_LIB ${SYS_LIB})
ELSE()
  SET(SYS_LIB ${SYS_LIB} ${Glog_LIBRARY} ${Protobuf_LIBRARY})
ENDIF()

SET(LIBS_DIRS ${LIBS_DIRS})
SET(LIBS_DIRS_DEBUG ${LIBS_DIRS_DEBUG})
LIST(REMOVE_DUPLICATES LIBS_DIRS)
LIST(REMOVE_DUPLICATES LIBS_DIRS_DEBUG)
LINK_DIRECTORIES(${CMAKE_ARCHIVE_OUTPUT_DIRECTORY})

INCLUDE_DIRECTORIES(${${PROJECT_NAME}_SOURCE_DIR})
LIST(REMOVE_DUPLICATES INCLUDE_DIRS)
INCLUDE_DIRECTORIES(AFTER SYSTEM ${INCLUDE_DIRS})

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
LIST(APPEND M_LIBUPNP_DIR
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/igd_desc_parse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minixml.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minisoap.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/miniwget.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnpcommands.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnpreplyparse.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/upnperrors.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/miniupnpc.c
       ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/libupnp/minissdpc.c)
SOURCE_GROUP("libupnp Source Files" FILES ${M_LIBUPNP_DIR})

FILE(GLOB M_NATPMP_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/nat-pmp/*.c*")
FILE(GLOB M_NATPMP_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/nat-pmp/*.h*")
SET(M_NATPMP_DIR ${M_NATPMP_C} ${M_NATPMP_H})
SOURCE_GROUP("nat-pnp Source Files" FILES ${M_NATPMP_C})
SOURCE_GROUP("nat-pnp Header Files" FILES ${M_NATPMP_H})

FILE(GLOB M_UPNP_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/*.c*")
FILE(GLOB M_UPNP_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/*.h*")
LIST(REMOVE_ITEM M_UPNP_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/upnpclientimpl.cc")
LIST(REMOVE_ITEM M_UPNP_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/upnp/upnpclientimpl.h")
SET(M_UPNP_DIR ${M_UPNP_C} ${M_UPNP_H})
SOURCE_GROUP("upnp Source Files" FILES ${M_UPNP_C})
SOURCE_GROUP("upnp Header Files" FILES ${M_UPNP_H})

FILE(GLOB M_PROTOBUF_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.c*")
FILE(GLOB M_PROTOBUF_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/protobuf/*.h*")
SET(M_PROTOBUF_DIR ${M_PROTOBUF_C} ${M_PROTOBUF_H})
SOURCE_GROUP("protobuf Source Files" FILES ${M_PROTOBUF_C})
SOURCE_GROUP("protobuf Header Files" FILES ${M_PROTOBUF_H})

FILE(GLOB M_BASE_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/*.c*")
FILE(GLOB M_BASE_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/*.h*")
SET(M_BASE_DIR ${M_BASE_C} ${M_BASE_H})
SOURCE_GROUP("base Source Files" FILES ${M_BASE_C})
SOURCE_GROUP("base Header Files" FILES ${M_BASE_H})

FILE(GLOB M_KADEMLIA_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/*.c*")
FILE(GLOB M_KADEMLIA_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/kademlia/*.h*")
SET(M_KADEMLIA_DIR ${M_KADEMLIA_C} ${M_KADEMLIA_H})
SET(STYLE_KADEMLIA ${M_KADEMLIA_DIR})
SOURCE_GROUP("kademlia Source Files" FILES ${M_KADEMLIA_C})
SOURCE_GROUP("kademlia Header Files" FILES ${M_KADEMLIA_H})

FILE(GLOB M_RPCPROTO_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/rpcprotocol/*.c*")
FILE(GLOB M_RPCPROTO_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/rpcprotocol/*.h*")
SET(M_RPCPROTO_DIR ${M_RPCPROTO_C} ${M_RPCPROTO_H})
SOURCE_GROUP("rpcprotocol Source Files" FILES ${M_RPCPROTO_C})
SOURCE_GROUP("rpcprotocol Header Files" FILES ${M_RPCPROTO_H})

FILE(GLOB M_TRANSPORT_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/*.c*")
FILE(GLOB M_TRANSPORT_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/transport/*.h*")
SET(M_TRANSPORT_DIR ${M_TRANSPORT_C} ${M_TRANSPORT_H})
SOURCE_GROUP("transport Source Files" FILES ${M_TRANSPORT_C})
SOURCE_GROUP("transport Header Files" FILES ${M_TRANSPORT_H})

FILE(GLOB MAIDSAFE_C "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.c*")
FILE(GLOB MAIDSAFE_H "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/*.h*")
SET(MAIDSAFE_DIR ${MAIDSAFE_C} ${MAIDSAFE_H})
SOURCE_GROUP("maidsafe Source Files" FILES ${MAIDSAFE_C})
SOURCE_GROUP("maidsafe Header Files" FILES ${MAIDSAFE_H})

####    TESTS    ####
FILE(GLOB T_BASE_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/base/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/base/*.h*")
FILE(GLOB T_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/*.h*")
LIST(REMOVE_ITEM T_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknode.cc")
FILE(GLOB T_TRANSPORT_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/*.c*"
                          "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/*.h*")
FILE(GLOB T_MAIN "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/main.cc"
                 "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/validationimpl.h")
FILE(GLOB T_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/*.c*"
                         "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/*.h*")
SET(STYLE_RPCPROTO_DIR ${T_RPCPROTO_DIR})
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/testservices.pb.h")
LIST(REMOVE_ITEM STYLE_RPCPROTO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/rpcprotocol/testservices.pb.cc")
FILE(GLOB T_NATPMP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/*.c*"
                       "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/*.h*")
FILE(GLOB T_UPNP_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/upnp/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/upnp/*.h*")
FILE(GLOB T_FUNC_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/*.c*"
                              "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/functionalkademlia/*.h*")
LIST(REMOVE_ITEM T_FUNC_KADEMLIA_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknode.cc")
FILE(GLOB T_DEMO_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/demo/*.c*"
                     "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/demo/*.h*")
FILE(GLOB T_BENCHMARK_DIR "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/benchmark/*.c*"
                          "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/benchmark/*.h*")
LIST(APPEND DHT_SOURCE_FILES ${M_BASE_DIR} ${M_KADEMLIA_DIR} ${M_TRANSPORT_DIR} ${M_PROTOBUF_DIR} ${M_RPCPROTO_DIR} ${M_LIBUPNP_DIR} ${M_UPNP_DIR} ${M_NATPMP_DIR} ${MAIDSAFE_DIR})

FILE(GLOB T_BOOST_DIR  "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/boost/*.c*")



###################################################################################################
# Traverse subdirs for imported 3rd party libs                                                    #
###################################################################################################
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/udt ${CMAKE_BINARY_DIR}/udt)
ADD_SUBDIRECTORY(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/cryptopp ${CMAKE_BINARY_DIR}/cryptopp)

###################################################################################################
# All Platforms:  Add Test Exes and Create all maidsafe_dht libs                                  #
###################################################################################################
ADD_EXECUTABLE(TESTbase ${T_MAIN} ${T_BASE_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTkademlia ${T_MAIN} ${T_KADEMLIA_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTknode "${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknode.cc" ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTtransport ${T_MAIN} ${T_TRANSPORT_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTrpcprotocol ${T_MAIN} ${T_RPCPROTO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTnatpmp ${T_MAIN} ${T_NATPMP_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTupnp ${T_MAIN} ${T_UPNP_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(TESTboost ${T_MAIN} ${T_BOOST_DIR})
# Need to use __declspec(dllimport) in all API header files before linking to SHARED library target
#ADD_EXECUTABLE(kaddemo ${T_DEMO_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(kaddemo_static ${T_DEMO_DIR} ${MAIDSAFE_H})
#ADD_EXECUTABLE(benchmark ${T_BENCHMARK_DIR} ${MAIDSAFE_H})
ADD_EXECUTABLE(benchmark_static ${T_BENCHMARK_DIR} ${MAIDSAFE_H})

# Force renaming of exes to match standard CMake library renaming policy
IF((NOT MSVC) AND (NOT ${KDEV}))
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
ENDIF()
# Need to use __declspec(dllexport) in all API header files before adding SHARED library target
#ADD_LIBRARY(maidsafe_dht SHARED ${DHT_SOURCE_FILES})
ADD_LIBRARY(maidsafe_dht_static STATIC ${DHT_SOURCE_FILES})

#Rename maidsafe_dht_static as maidsafe_dht on way out NOT in MSVC names clash of static and import lib
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES OUTPUT_NAME maidsafe_dht)
#ENDIF()

###################################################################################################
# Builds                                                                                          #
###################################################################################################
ADD_DEFINITIONS(-DSTATICLIB)
IF(Glog_FOUND)
  ADD_DEFINITIONS(-DHAVE_GLOG)
ENDIF()
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

IF(NOT MSVC)
  SET(SYS_LIB ${SYS_LIB} ${Boost_LIBRARIES})
  TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static udt_static cryptopp_static ${Gtest_LIBRARY} ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTboost ${Gtest_LIBRARY} ${SYS_LIB})
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
  TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
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
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknode.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/nat-pmp/testnatpmp.cc
                              ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/transport/testtransport.cc
                                PROPERTIES COMPILE_FLAGS "/wd4503")

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

  # Next version of CMake accommodates per-build-type STATIC_LIBRARY_FLAGS.  Until then, this has no effect.
  SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES STATIC_LIBRARY_FLAGS_RELEASE "/LTCG")

  SET(DEBUG_LIBS ${Glog_LIBRARY_DEBUG} ${Protobuf_LIBRARY_DEBUG} ${Boost_DATE_TIME_LIBRARY_DEBUG} ${Boost_FILESYSTEM_LIBRARY_DEBUG} ${Boost_THREAD_LIBRARY_DEBUG}
      ${Boost_PROGRAM_OPTIONS_LIBRARY_DEBUG} ${Boost_SYSTEM_LIBRARY_DEBUG} ${Boost_REGEX_LIBRARY_DEBUG})
  SET(RELEASE_LIBS ${Glog_LIBRARY} ${Protobuf_LIBRARY} ${Boost_DATE_TIME_LIBRARY_RELEASE} ${Boost_FILESYSTEM_LIBRARY_RELEASE} ${Boost_THREAD_LIBRARY_RELEASE}
      ${Boost_PROGRAM_OPTIONS_LIBRARY_RELEASE} ${Boost_SYSTEM_LIBRARY_RELEASE} ${Boost_REGEX_LIBRARY_RELEASE})

  TARGET_LINK_LIBRARIES(TESTbase maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTkademlia maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTknode maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTtransport maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTupnp maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(kaddemo_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(benchmark_static maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
  TARGET_LINK_LIBRARIES(TESTboost ${SYS_LIB})

#  TARGET_LINK_LIBRARIES(maidsafe_dht udt_static cryptopp_static iphlpapi.lib)
#  TARGET_LINK_LIBRARIES(kaddemo maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})
#  TARGET_LINK_LIBRARIES(benchmark maidsafe_dht_static udt_static cryptopp_static ${SYS_LIB})

  FOREACH (DLIB ${DEBUG_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTknode debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTtransport debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTupnp debug ${DLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static debug ${DLIB})
    TARGET_LINK_LIBRARIES(benchmark_static debug ${DLIB})
    TARGET_LINK_LIBRARIES(TESTboost debug ${DLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht debug ${DLIB})
#    TARGET_LINK_LIBRARIES(kaddemo debug ${DLIB})
#    TARGET_LINK_LIBRARIES(benchmark debug ${DLIB})
  ENDFOREACH()
  TARGET_LINK_LIBRARIES(TESTbase debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTkademlia debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTknode debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTnatpmp debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTtransport debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTupnp debug ${Gtest_LIBRARY_DEBUG})
  TARGET_LINK_LIBRARIES(TESTboost debug ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY_DEBUG} debug ${Gtest_LIBRARY_DEBUG})

  FOREACH(RLIB ${RELEASE_LIBS})
    TARGET_LINK_LIBRARIES(TESTbase optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTkademlia optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTknode optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTtransport optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTupnp optimized ${RLIB})
    TARGET_LINK_LIBRARIES(kaddemo_static optimized ${RLIB})
    TARGET_LINK_LIBRARIES(benchmark_static optimized ${RLIB})
    TARGET_LINK_LIBRARIES(TESTboost optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(maidsafe_dht optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(kaddemo optimized ${RLIB})
#    TARGET_LINK_LIBRARIES(benchmark optimized ${RLIB})
  ENDFOREACH()
  TARGET_LINK_LIBRARIES(TESTbase optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTkademlia optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTknode optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTnatpmp optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTrpcprotocol optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTtransport optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTupnp optimized ${Gtest_LIBRARY})
  TARGET_LINK_LIBRARIES(TESTboost optimized ${Boost_UNIT_TEST_FRAMEWORK_LIBRARY_RELEASE} optimized ${Gtest_LIBRARY})
ENDIF()

####APPLE##############################
IF(APPLE)
  SET(CMAKE_AR "/usr/bin/libtool")
  SET(CMAKE_CXX_CREATE_STATIC_LIBRARY "<CMAKE_AR> -static -o <TARGET> <LINK_FLAGS> <OBJECTS>" "<CMAKE_RANLIB> <TARGET>")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D_DARWIN_C_SOURCE")
  ADD_DEFINITIONS(-DMAIDSAFE_APPLE -DBSD)
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS} -finline-functions -funswitch-loops -fgcse-after-reload -ftree-vectorize -D_FORTIFY_SOURCE=2 -D__FreeBSD__=10 -D_FILE_OFFSET_BITS=64 -g -O0 -Wall -W -Wshadow -Wunused-variable -Wunused-parameter -Wunused-function -Wunused -Wno-system-headers -Wno-deprecated -Woverloaded-virtual -Wwrite-strings -fprofile-arcs -ftest-coverage")
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized -O2")
  SET(MAIDSAFE_DHT_CXX_FLAGS_DEBUG "${MAIDSAFE_DHT_CXX_FLAGS}")
  SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} -Wall -Wextra -pedantic ")
  SET(CMAKE_LDFLAGS "-fprofile-arcs -ftest-coverage")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES LINK_FLAGS " -ggdb  -pg -fprofile-arcs -ftest-coverage")
  ENDIF()
  SET(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS}" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov" CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} -lgcov" CACHE INTERNAL "" FORCE)
  SET(SILENT_BUILD "-w -fPIC -DNDEBUG -pipe")

######LINUX################################
ELSEIF(UNIX AND NOT APPLE)
  ADD_DEFINITIONS(-DMAIDSAFE_LINUX)
  #SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fPIC -Wall -Wextra -pedantic -ansi -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(MAIDSAFE_DHT_CXX_FLAGS "${CMAKE_CXX_FLAGS}  -fPIC -Wall -Weffc++ -Wextra -pedantic -pedantic-errors -std=c++0x -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(MAIDSAFE_DHT_CXX_FLAGS_DEBUG " ${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_DEBUG} -ggdb -pg -fprofile-arcs -ftest-coverage ")
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${MAIDSAFE_DHT_CXX_FLAGS} ${CMAKE_CXX_FLAGS_RELEASE}   -O2")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(maidsafe_dht_static PROPERTIES LINK_FLAGS "-pg -fprofile-arcs -ftest-coverage")
  ENDIF()
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage " CACHE INTERNAL "" FORCE)
  SET(CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO "${CMAKE_EXE_LINKER_FLAGS_RELWITHDEBINFO} " CACHE INTERNAL "" FORCE)
  SET(SILENT_BUILD "-w -fPIC -DNDEBUG  -march=native -mtune=native -pipe")

#######WINDOWS##############
ELSEIF(WIN32 AND NOT MSVC)
  ADD_DEFINITIONS(-D__MINGW__ -DWIN32_LEAN_AND_MEAN -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -D_WIN32_WINNT=0x0501)
  SET(MAIDSAFE_DHT_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wuninitialized -O")
  SET(MAIDSAFE_DHT_CXX_FLAGS "-Wall -Wextra -pedantic  -D_WIN32_WINNT=0x0501 -D_FORTIFY_SOURCE=2 -D_FILE_OFFSET_BITS=64")
  SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNDEBUG -DWIN32_LEAN_AND_MEAN -D__MINGW__  -D_GLIBCXX_USE_WCHAR_T -DUNICODE -D_UNICODE -DWIN32 -D_WIN32_WINNT=0x0501")
  IF(CMAKE_BUILD_TYPE MATCHES "Debug")
    SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp PROPERTIES LINK_FLAGS "-lgcov  -pg -fprofile-arcs -ftest-coverage")
  ENDIF()

  SET_TARGET_PROPERTIES(TESTbase TESTtransport TESTrpcprotocol TESTkademlia TESTknode TESTnatpmp TESTupnp kaddemo_static benchmark_static PROPERTIES LINK_FLAGS "-mthreads ")
  SET(SILENT_BUILD  "-w -finline-functions -O3 -DNDEBUG -D_WIN32_WINNT=0x0501 -D_WIN32")
ENDIF()

IF(NOT MSVC)
  IF(CMAKE_BUILD_TYPE MATCHES "Release")
    SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_RELEASE}")
  ELSE()
    SET(MAIDSAFE_DHT_CXX_FLAGS "${MAIDSAFE_DHT_CXX_FLAGS} ${MAIDSAFE_DHT_CXX_FLAGS_DEBUG}")
  ENDIF()
  SET_SOURCE_FILES_PROPERTIES(${DHT_SOURCE_FILES} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_BASE_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_TRANSPORT_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_RPCPROTO_DIR} COMPILE_FLAGS ${SILENT_BUILD})
  SET_SOURCE_FILES_PROPERTIES(${T_UPNP_DIR} COMPILE_FLAGS ${SILENT_BUILD})
  SET_SOURCE_FILES_PROPERTIES(${T_NATPMP_DIR} COMPILE_FLAGS ${SILENT_BUILD})
  SET_SOURCE_FILES_PROPERTIES(${T_DEMO_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${T_BENCHMARK_DIR} COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  #SET_TARGET_PROPERTIES(TESTkademlia TESTknode PROPERTIES COMPILE_FLAGS ${MAIDSAFE_DHT_CXX_FLAGS})
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/crypto.cc PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/base/utils.cc PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*boost/*" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("*google/protobuf/repeated_field.h" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${M_PROTOBUF_DIR} PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES("${M_UPNP_DIR}" PROPERTIES COMPILE_FLAGS "${SILENT_BUILD}")
  SET_SOURCE_FILES_PROPERTIES(${M_LIBUPNP_DIR} PROPERTIES COMPILE_FLAGS "${CMAKE_C_FLAGS}")
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
    ADD_TEST(STYLE_CHECK_KAD python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${STYLE_KADEMLIA} ${T_KADEMLIA_DIR} ${T_FUNC_KADEMLIA_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_KAD PROPERTY LABELS Functional Kademlia CodingStyle)
    ADD_TEST(STYLE_CHECK_BASE python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${M_BASE_DIR} ${T_BASE_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_BASE PROPERTY LABELS Functional Base CodingStyle)
    ADD_TEST(STYLE_CHECK_RPC python ${${PROJECT_NAME}_ROOT}/build/tools/cpplint.py ${M_RPCPROTO_DIR} ${STYLE_RPCPROTO_DIR})
    SET_PROPERTY(TEST STYLE_CHECK_RPC PROPERTY LABELS Functional RpcProtocol CodingStyle)
  ELSE()
    STRING(REPLACE "/" "\\\\" STYLE_CHECK_SOURCE ${${PROJECT_NAME}_ROOT})
    ADD_TEST(STYLE_CHECK ${${PROJECT_NAME}_ROOT}/build/tools/run_cpplint.bat ${STYLE_CHECK_SOURCE})
    SET_PROPERTY(TEST STYLE_CHECK PROPERTY LABELS Functional CodingStyle)
  ENDIF()
ENDIF()

SET(TEST_EXECUTABLES TESTupnp TESTnatpmp TESTbase TESTknode TESTkademlia TESTtransport TESTrpcprotocol TESTboost)
FOREACH(TEST_EXECUTABLE ${TEST_EXECUTABLES})
  IF(TEST_EXECUTABLE STREQUAL "TESTupnp")
    SET(GTEST_SOURCE_FILES ${T_UPNP_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTnatpmp")
    SET(GTEST_SOURCE_FILES ${T_NATPMP_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTbase")
    SET(GTEST_SOURCE_FILES ${T_BASE_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTknode")
    SET(GTEST_SOURCE_FILES ${${PROJECT_NAME}_SOURCE_DIR}/maidsafe/tests/kademlia/testknode.cc)
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTkademlia")
    SET(GTEST_SOURCE_FILES ${T_KADEMLIA_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTtransport")
    SET(GTEST_SOURCE_FILES ${T_TRANSPORT_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTrpcprotocol")
    SET(GTEST_SOURCE_FILES ${T_RPCPROTO_DIR})
  ELSEIF(TEST_EXECUTABLE STREQUAL "TESTboost")
    SET(GTEST_SOURCE_FILES ${T_BOOST_DIR})
  ENDIF()
  FOREACH(GTEST_SOURCE_FILE ${GTEST_SOURCE_FILES})
    FILE(STRINGS ${GTEST_SOURCE_FILE} GTEST_NAMES REGEX ^TEST)
    FOREACH(GTEST_NAME ${GTEST_NAMES})
      STRING(REGEX REPLACE ["\) \(,"] ";" GTEST_NAME ${GTEST_NAME})
      LIST(GET GTEST_NAME 1 GTEST_GROUP_NAME)
      LIST(GET GTEST_NAME 3 GTEST_NAME)
      IF("${GTEST_NAME}" MATCHES "(${MAIDSAFE_TEST_TYPE}).+")
        ADD_TEST(${GTEST_NAME} ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/${TEST_EXECUTABLE}${TEST_POSTFIX} --gtest_filter=*${GTEST_NAME}*)
        IF("${GTEST_NAME}" MATCHES "^FUNC_" OR "${GTEST_NAME}" MATCHES "^DISABLED_FUNC_")
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY LABELS Functional ${GTEST_GROUP_NAME})
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY TIMEOUT 600)
        ELSEIF("${GTEST_NAME}" MATCHES "^BEH_" OR "${GTEST_NAME}" MATCHES "^DISABLED_BEH_")
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY LABELS Behavioural ${GTEST_GROUP_NAME})
          SET_PROPERTY(TEST ${GTEST_NAME} PROPERTY TIMEOUT 60)
        ELSE()
          MESSAGE("")
          MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
          MESSAGE("")
          MESSAGE(AUTHOR_WARNING "${GTEST_NAME} should be named \"BEH_...\" or \"FUNC_...\" (with an optional \"DISABLED_\" prepended).")
          MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
        ENDIF()
      ENDIF()
      SET(GTESTS ${GTESTS} ${GTEST_NAME})
    ENDFOREACH()
  ENDFOREACH()
ENDFOREACH()

# Check for repeated test names
IF(NOT CMAKE_SUPPRESS_DEVELOPER_WARNINGS)
  SET(WARNING_MESSAGE)
  SET(GTEST_NAMES ${GTESTS})
  LIST(LENGTH GTEST_NAMES GTESTS_COUNT)
  WHILE(GTESTS_COUNT GREATER 1)
    LIST(GET GTEST_NAMES 0 GTEST_NAME)
    LIST(REMOVE_AT GTEST_NAMES 0)
    STRING(REGEX MATCH ${GTEST_NAME} REPEATED_NAME ${GTEST_NAMES})
    IF(REPEATED_NAME)
      IF(NOT WARNING_MESSAGE)
        MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
      ENDIF()
      SET(REPEATED_IN)
      FOREACH(GTEST_TEST_NAME ${GTEST_NAMES})
        STRING(REGEX MATCH ${GTEST_NAME} OTHER_REPEATED_NAME ${GTEST_TEST_NAME})
        IF(OTHER_REPEATED_NAME)
          SET(REPEATED_IN "${REPEATED_IN};${GTEST_TEST_NAME}")
        ENDIF()
      ENDFOREACH()
      SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n\"${REPEATED_NAME}\" repeated in tests\n")
      SET(WARNING_MESSAGE "${WARNING_MESSAGE}  -- ${REPEATED_NAME}\n")
      FOREACH(REPEATED_IN_TEST ${REPEATED_IN})
        SET(WARNING_MESSAGE "${WARNING_MESSAGE}  -- ${REPEATED_IN_TEST}\n")
      ENDFOREACH()
    ENDIF()
    LIST(LENGTH GTEST_NAMES GTESTS_COUNT)
  ENDWHILE()
  IF(WARNING_MESSAGE)
    MESSAGE(AUTHOR_WARNING ${WARNING_MESSAGE})
    MESSAGE("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    MESSAGE("================================================================================")
  ENDIF()
ENDIF()

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
      maidsafe/transport/transport-api.h
      maidsafe/transport/transporthandler-api.h
      maidsafe/transport/transportudt.h)
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

IF(CMAKE_BUILD_TYPE MATCHES Release)
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
