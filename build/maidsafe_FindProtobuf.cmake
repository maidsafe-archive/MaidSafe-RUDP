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
#                                                                              #
#  Module used to locate Google Protocol Buffers libs, headers & compiler and  #
#  run protoc against maidsafe_dht .proto files if their contents have changed #
#  or if protobuf version has changed.                                         #
#                                                                              #
#  Settable variables to aid with finding protobuf and protoc are:             #
#    PROTOBUF_LIB_DIR, PROTOBUF_INC_DIR, PROTOC_EXE_DIR and PROTOBUF_ROOT_DIR  #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Protobuf_INCLUDE_DIR, Protobuf_LIBRARY_DIR, Protobuf_LIBRARY and          #
#    Protobuf_PROTOC_EXECUTABLE                                                #
#                                                                              #
#  For MSVC, Protobuf_LIBRARY_DIR_DEBUG and Protobuf_LIBRARY_DEBUG are also    #
#  set and cached.                                                             #
#                                                                              #
#==============================================================================#


UNSET(Protobuf_INCLUDE_DIR CACHE)
UNSET(Protobuf_LIBRARY_DIR CACHE)
UNSET(Protobuf_LIBRARY CACHE)
UNSET(Protobuf_LIBRARY_DIR_DEBUG CACHE)
UNSET(Protobuf_LIBRARY_DEBUG CACHE)
UNSET(Protobuf_PROTOC_EXECUTABLE CACHE)
UNSET(PROTOBUF_LIBRARY_RELEASE CACHE)
UNSET(PROTOBUF_LIBRARY_DEBUG CACHE)
UNSET(PROTOC_EXE_RELEASE CACHE)

IF(PROTOBUF_LIB_DIR)
  SET(PROTOBUF_LIB_DIR ${PROTOBUF_LIB_DIR} CACHE PATH "Path to Google Protocol Buffers libraries directory" FORCE)
ENDIF()
IF(PROTOBUF_INC_DIR)
  SET(PROTOBUF_INC_DIR ${PROTOBUF_INC_DIR} CACHE PATH "Path to Google Protocol Buffers include directory" FORCE)
ENDIF()
IF(PROTOC_EXE_DIR)
  SET(PROTOC_EXE_DIR ${PROTOC_EXE_DIR} CACHE PATH "Path to Google Protocol Buffers executable (protoc) directory" FORCE)
ENDIF()
IF(PROTOBUF_ROOT_DIR)
  SET(PROTOBUF_ROOT_DIR ${PROTOBUF_ROOT_DIR} CACHE PATH "Path to Google Protocol Buffers root directory" FORCE)
ENDIF()

IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Release)
ELSE()
  SET(PROTOBUF_LIBPATH_SUFFIX lib)
ENDIF()

FIND_LIBRARY(PROTOBUF_LIBRARY_RELEASE NAMES protobuf libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
FIND_PROGRAM(PROTOC_EXE_RELEASE NAMES protoc PATHS ${PROTOC_EXE_DIR} ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Debug)
  FIND_LIBRARY(PROTOBUF_LIBRARY_DEBUG NAMES libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Protobuf_INCLUDE_DIR google/protobuf/service.h PATHS ${PROTOBUF_INC_DIR} ${PROTOBUF_ROOT_DIR}/src)

GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR ${PROTOBUF_LIBRARY_RELEASE} PATH)
SET(Protobuf_LIBRARY_DIR ${PROTOBUF_LIBRARY_DIR} CACHE PATH "Path to Google Protocol Buffers libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR_DEBUG ${PROTOBUF_LIBRARY_DEBUG} PATH)
  SET(Protobuf_LIBRARY_DIR_DEBUG ${PROTOBUF_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Protocol Buffers debug libraries directory" FORCE)
ENDIF()

IF(NOT PROTOBUF_LIBRARY_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOBUF LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_LIB_DIR=<Path to protobuf lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_LIBRARY ${PROTOBUF_LIBRARY_RELEASE} CACHE PATH "Path to Google Protocol Buffers library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT PROTOBUF_LIBRARY_DEBUG)
    SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO *DEBUG* PROTOBUF LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Protobuf_LIBRARY_DEBUG ${PROTOBUF_LIBRARY_DEBUG} CACHE PATH "Path to Google Protocol Buffers debug library" FORCE)
  ENDIF()
ENDIF()

IF(NOT Protobuf_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO HEADER FILE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_INC_DIR=<Path to protobuf include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(NOT PROTOC_EXE_RELEASE)
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOC EXE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOC_EXE_DIR=<Path to protoc directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_PROTOC_EXECUTABLE ${PROTOC_EXE_RELEASE} CACHE PATH "Path to Google Protocol Buffers executable (protoc) directory" FORCE)
ENDIF()

EXECUTE_PROCESS(COMMAND ${Protobuf_PROTOC_EXECUTABLE} "--version" OUTPUT_VARIABLE TMP_CURRENT_PROTOC_VERSION)
STRING(STRIP ${TMP_CURRENT_PROTOC_VERSION} CURRENT_PROTOC_VERSION)

MESSAGE("-- Found Google Protocol Buffers library")
IF(MSVC)
  MESSAGE("-- Found Google Protocol Buffers Debug library")
ENDIF()

#Function to generate CC and header files derived from proto files
FUNCTION(GENERATE_PROTOBUF_FILES SRCS HDRS)
  IF(NOT ARGN)
    MESSAGE(SEND_ERROR "Error: PROTOBUF_GENERATE_CPP() called without any proto files")
    RETURN()
  ENDIF()

  FOREACH(FIL ${ARGN})
    GET_FILENAME_COMPONENT(ABS_FIL ${FIL} NAME)
    GET_FILENAME_COMPONENT(FIL_WE ${FIL} NAME_WE)
    GET_FILENAME_COMPONENT(FILES_PATH ${FIL} PATH)
    SET(FILES_PATH "${${PROJECT_NAME}_SOURCE_DIR}/${FILES_PATH}")

    LIST(APPEND ${SRCS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.cc")
    LIST(APPEND ${HDRS} "${CMAKE_CURRENT_BINARY_DIR}/${FIL_WE}.pb.h")

    MESSAGE("--   Generated files from ${FIL}")
    EXECUTE_PROCESS(WORKING_DIRECTORY ${FILES_PATH}
                    COMMAND ${Protobuf_PROTOC_EXECUTABLE}
                      "--cpp_out=."
                      "${ABS_FIL}")
  ENDFOREACH()

  SET_SOURCE_FILES_PROPERTIES(${${SRCS}} ${${HDRS}} PROPERTIES GENERATED TRUE)
  SET(${SRCS} ${${SRCS}} PARENT_SCOPE)
  SET(${HDRS} ${${HDRS}} PARENT_SCOPE)
ENDFUNCTION()

FUNCTION(COMPARE_VAR_VS_FILE DIFF)
  FILE(STRINGS ${${PROJECT_NAME}_SOURCE_DIR}/${ARGV2} TMP_CONTENT)
  SET(CONTENT ${TMP_CONTENT} CACHE STRING "")
  IF(NOT "${CONTENT}" STREQUAL "${${ARGV1}}")
    SET(${ARGV1} ${TMP_CONTENT} CACHE INTERNAL "Google proto file - Contents for ${ARGV2}" FORCE)
    SET(${DIFF} "FALSE" PARENT_SCOPE)
  ELSE()
    SET(${DIFF} "TRUE" PARENT_SCOPE)
  ENDIF()
  UNSET(CONTENT CACHE)
ENDFUNCTION()

FUNCTION(SET_PROTOFILEVAR_CONTENT)
  FILE(STRINGS ${${PROJECT_NAME}_SOURCE_DIR}/${ARGV1} TMP_CONTENT)
  SET(${ARGV0} ${TMP_CONTENT} CACHE INTERNAL "Google proto file - Contents for ${ARGV1}" FORCE)
  UNSET(TMP_CONTENT CACHE)
ENDFUNCTION()

IF(PROTOC_VERSION STREQUAL CURRENT_PROTOC_VERSION)
  FOREACH(FNAME ${PROTO_FILES})
    GET_FILENAME_COMPONENT(FIL_WE ${FNAME} NAME_WE)
    COMPARE_VAR_VS_FILE(CONTENTS_DIFF ${FIL_WE} ${FNAME})
    IF(NOT CONTENTS_DIFF)
      GENERATE_PROTOBUF_FILES(PROTO_SRCS PROTO_HDRS ${FNAME})
    ENDIF()
  ENDFOREACH()
ELSE()
  GENERATE_PROTOBUF_FILES(PROTO_SRCS PROTO_HDRS ${PROTO_FILES})
  FOREACH(FNAME ${PROTO_FILES})
    GET_FILENAME_COMPONENT(FIL_WE ${FNAME} NAME_WE)
    SET_PROTOFILEVAR_CONTENT(${FIL_WE} ${FNAME})
  ENDFOREACH()
  SET(PROTOC_VERSION ${CURRENT_PROTOC_VERSION} CACHE STATIC "Google Protocol Buffers - Current version" FORCE)
ENDIF()
