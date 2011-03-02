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
#  Module used to locate Google Logging libs and headers.                      #
#                                                                              #
#  Currently Glog can't be compiled on Windows using MinGW.                    #
#                                                                              #
#  Settable variables to aid with finding Glog are:                            #
#    GLOG_LIB_DIR, GLOG_INC_DIR and GLOG_ROOT_DIR                              #
#                                                                              #
#  If GLOG_REQUIRED is set to TRUE, failure of this module will result in      #
#  a FATAL_ERROR message being generated.                                      #
#                                                                              #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Glog_INCLUDE_DIR, Glog_LIBRARY_DIR, Glog_LIBRARY, Glog_FOUND              #
#                                                                              #
#  For MSVC, Glog_LIBRARY_DIR_DEBUG is also set and cached.                    #
#                                                                              #
#==============================================================================#

UNSET(Glog_INCLUDE_DIR CACHE)
UNSET(Glog_LIBRARY_DIR CACHE)
UNSET(Glog_LIBRARY_DIR_DEBUG CACHE)
UNSET(Glog_LIBRARY CACHE)
UNSET(Glog_LIBRARY_DEBUG CACHE)
UNSET(Glog_LIBRARY_RELEASE CACHE)
UNSET(Glog_FOUND CACHE)

IF(GLOG_LIB_DIR)
  SET(GLOG_LIB_DIR ${GLOG_LIB_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
ENDIF()
IF(GLOG_INC_DIR)
  SET(GLOG_INC_DIR ${GLOG_INC_DIR} CACHE PATH "Path to Google Logging include directory" FORCE)
ENDIF()
IF(GLOG_ROOT_DIR)
  SET(GLOG_ROOT_DIR ${GLOG_ROOT_DIR} CACHE PATH "Path to Google Logging root directory" FORCE)
  SET(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${GLOG_ROOT_DIR})
ELSE()
  SET(GLOG_ROOT_DIR ${${PROJECT_NAME}_SOURCE_DIR}/../thirdpartylibs/glog)
  SET(CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${GLOG_ROOT_DIR})
ENDIF()

IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Release)
ELSE()
  SET(GLOG_LIBPATH_SUFFIX lib lib64)
ENDIF()

FIND_LIBRARY(Glog_LIBRARY_RELEASE NAMES libglog.a libglog_static.lib PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Debug)
  FIND_LIBRARY(Glog_LIBRARY_DEBUG NAMES libglog_static.lib PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
ENDIF()

FIND_PATH(Glog_INCLUDE_DIR glog/logging.h PATHS ${GLOG_INC_DIR} ${GLOG_ROOT_DIR}/src/windows NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR ${Glog_LIBRARY_RELEASE} PATH)
SET(Glog_LIBRARY_DIR ${GLOG_LIBRARY_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR_DEBUG ${Glog_LIBRARY_DEBUG} PATH)
  SET(Glog_LIBRARY_DIR_DEBUG ${GLOG_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Logging debug libraries directory" FORCE)
ENDIF()


IF(NOT Glog_LIBRARY_RELEASE)
  IF(NOT GLOG_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Logging.   NO GLOG LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_LIB_DIR=<Path to glog lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Glog_LIBRARY ${Glog_LIBRARY_RELEASE} CACHE PATH "Path to Google Logging library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT Glog_LIBRARY_DEBUG)
    IF(NOT GLOG_REQUIRED)
      RETURN()
    ENDIF()
    SET(ERROR_MESSAGE "\nCould not find Google Logging.  NO *DEBUG* GLOG LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(Glog_LIBRARY debug ${Glog_LIBRARY_DEBUG} optimized ${Glog_LIBRARY} CACHE PATH "Path to Google Logging libraries" FORCE)
  ENDIF()
ENDIF()

IF(NOT Glog_INCLUDE_DIR)
  IF(NOT GLOG_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Logging.  NO HEADER FILE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_INC_DIR=<Path to glog include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(Glog_FOUND TRUE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
ENDIF()

MESSAGE("-- Found Google Logging library")
IF(MSVC)
  MESSAGE("-- Found Google Logging Debug library")
ENDIF()
