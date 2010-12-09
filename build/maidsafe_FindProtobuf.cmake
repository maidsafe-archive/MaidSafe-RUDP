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
#  If PROTOBUF_REQUIRED is set to TRUE, failure of this module will result in  #
#  a FATAL_ERROR message being generated.                                      #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Protobuf_INCLUDE_DIR, Protobuf_LIBRARY_DIR, Protobuf_LIBRARY,             #
#    Protobuf_PROTOC_EXECUTABLE, and Protobuf_FOUND                            #
#                                                                              #
#  For MSVC, Protobuf_LIBRARY_DIR_DEBUG is also set and cached.                #
#                                                                              #
#==============================================================================#


#Function to generate CC and header files derived from proto files
FUNCTION(GENERATE_PROTO_FILES PROTO_FILE CACHE_NAME)
  FILE(STRINGS ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE} PROTO_STRING)
  UNSET(NEW_${ARGV1} CACHE)
  SET(NEW_${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - new file contents for ${ARGV1}")
  IF((FORCE_PROTOC_COMPILE) OR (NOT "${NEW_${ARGV1}}" STREQUAL "${${ARGV1}}"))
    GET_FILENAME_COMPONENT(PROTO_FILE_NAME ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE} NAME)
    EXECUTE_PROCESS(COMMAND ${Protobuf_PROTOC_EXECUTABLE}
                      --proto_path=${${PROJECT_NAME}_SOURCE_DIR}
                      --cpp_out=${${PROJECT_NAME}_SOURCE_DIR}
                      ${${PROJECT_NAME}_SOURCE_DIR}/${PROTO_FILE}
                      RESULT_VARIABLE PROTO_RES
                      ERROR_VARIABLE PROTO_ERR)
    UNSET(${ARGV1} CACHE)
    IF(NOT ${PROTO_RES})
      MESSAGE("--   Generated files from ${PROTO_FILE_NAME}")
      SET(${ARGV1} ${PROTO_STRING} CACHE STRING "Google Protocol Buffers - file contents for ${PROTO_FILE}")
    ELSE()
      MESSAGE(FATAL_ERROR "Failed trying to generate files from ${PROTO_FILE_NAME}\n${PROTO_ERR}")
    ENDIF()
  ENDIF()
  UNSET(NEW_${ARGV1} CACHE)
ENDFUNCTION()

UNSET(Protobuf_INCLUDE_DIR CACHE)
UNSET(Protobuf_LIBRARY_DIR CACHE)
UNSET(Protobuf_LIBRARY CACHE)
UNSET(Protobuf_LIBRARY_DIR_DEBUG CACHE)
UNSET(Protobuf_LIBRARY_DEBUG CACHE)
UNSET(Protobuf_LIBRARY_RELEASE CACHE)
UNSET(Protobuf_PROTOC_EXECUTABLE CACHE)
UNSET(PROTOBUF_LIBRARY_DEBUG CACHE)
UNSET(PROTOC_EXE_RELEASE CACHE)
SET(Protobuf_FOUND FALSE)

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
  SET(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${PROTOBUF_ROOT_DIR})
ENDIF()

IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Release)
ELSE()
  SET(PROTOBUF_LIBPATH_SUFFIX lib bin)
ENDIF()

FIND_LIBRARY(Protobuf_LIBRARY_RELEASE NAMES protobuf libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
FIND_PROGRAM(PROTOC_EXE_RELEASE NAMES protoc PATHS ${PROTOC_EXE_DIR} ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
IF(MSVC)
  SET(PROTOBUF_LIBPATH_SUFFIX vsprojects/Debug)
  FIND_LIBRARY(Protobuf_LIBRARY_DEBUG NAMES libprotobuf PATHS ${PROTOBUF_LIB_DIR} ${PROTOBUF_ROOT_DIR} PATH_SUFFIXES ${PROTOBUF_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Protobuf_INCLUDE_DIR google/protobuf/service.h PATHS ${PROTOBUF_INC_DIR} ${PROTOBUF_ROOT_DIR}/src)

GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR ${Protobuf_LIBRARY_RELEASE} PATH)
SET(Protobuf_LIBRARY_DIR ${PROTOBUF_LIBRARY_DIR} CACHE PATH "Path to Google Protocol Buffers libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(PROTOBUF_LIBRARY_DIR_DEBUG ${Protobuf_LIBRARY_DEBUG} PATH)
  SET(Protobuf_LIBRARY_DIR_DEBUG ${PROTOBUF_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Protocol Buffers debug libraries directory" FORCE)
ENDIF()

IF(NOT Protobuf_LIBRARY_RELEASE)
  IF(NOT PROTOBUF_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOBUF LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_LIB_DIR=<Path to protobuf lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_LIBRARY ${Protobuf_LIBRARY_RELEASE} CACHE PATH "Path to Google Protocol Buffers library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT Protobuf_LIBRARY_DEBUG)
    IF(NOT PROTOBUF_REQUIRED)
      RETURN()
    ENDIF()
    SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO *DEBUG* PROTOBUF LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Protobuf_LIBRARY debug ${Protobuf_LIBRARY_DEBUG} optimized ${Protobuf_LIBRARY} CACHE PATH "Path to Google Protocol Buffers libraries" FORCE)
  ENDIF()
ENDIF()

IF(NOT Protobuf_INCLUDE_DIR)
  IF(NOT PROTOBUF_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO HEADER FILE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_INC_DIR=<Path to protobuf include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(NOT PROTOC_EXE_RELEASE)
  IF(NOT PROTOBUF_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Protocol Buffers.  NO PROTOC EXE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/protobuf\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If protobuf is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DPROTOC_EXE_DIR=<Path to protoc directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DPROTOBUF_ROOT_DIR=<Path to protobuf root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Protobuf_PROTOC_EXECUTABLE ${PROTOC_EXE_RELEASE} CACHE PATH "Path to Google Protocol Buffers executable (protoc) directory" FORCE)
ENDIF()
SET(Protobuf_FOUND TRUE)

EXECUTE_PROCESS(COMMAND ${Protobuf_PROTOC_EXECUTABLE} "--version" OUTPUT_VARIABLE TMP_CURRENT_PROTOC_VERSION)
STRING(STRIP ${TMP_CURRENT_PROTOC_VERSION} CURRENT_PROTOC_VERSION)
IF(NOT PROTOC_VERSION STREQUAL CURRENT_PROTOC_VERSION)
  SET(PROTOC_VERSION ${CURRENT_PROTOC_VERSION} CACHE STATIC "Google Protocol Buffers - Current version" FORCE)
  SET(FORCE_PROTOC_COMPILE TRUE)
ENDIF()

MESSAGE("-- Found Google Protocol Buffers library")
IF(MSVC)
  MESSAGE("-- Found Google Protocol Buffers Debug library")
ENDIF()

FOREACH(PROTO_FILE ${PROTO_FILES})
  STRING(REGEX REPLACE "[\\/.]" "_" PROTO_CACHE_NAME ${PROTO_FILE})
  GENERATE_PROTO_FILES(${PROTO_FILE} ${PROTO_CACHE_NAME})
ENDFOREACH()
