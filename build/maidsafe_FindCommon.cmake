#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 maidsafe.net limited                                     #
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
#  Module used to locate MaidSafe-Common tools, cmake modules and the          #
#    maidsafe_common libs and headers.                                         #
#                                                                              #
#  Settable variables to aid with finding MaidSafe-Common are:                 #
#    MAIDSAFE_COMMON_LIB_DIR, MAIDSAFE_COMMON_INC_DIR,                         #
#    MAIDSAFE_COMMON_SHARE_DIR and MAIDSAFE_COMMON_ROOT_DIR                    #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    MaidSafeCommon_INCLUDE_DIR, MaidSafeCommon_LIBRARY_DIR,                   #
#    MaidSafeCommon_LIBRARY, MaidSafeCommon_MODULES_DIR, and                   #
#    MaidSafeCommon_TOOLS_DIR.                                                 #
#                                                                              #
#==============================================================================#

UNSET(MaidSafeCommon_INCLUDE_DIR CACHE)
UNSET(MaidSafeCommon_LIBRARY_DIR CACHE)
UNSET(MaidSafeCommon_LIBRARY_DIR_DEBUG CACHE)
UNSET(MaidSafeCommon_LIBRARY CACHE)
UNSET(MaidSafeCommon_LIBRARY_DEBUG CACHE)
UNSET(MaidSafeCommon_LIBRARY_RELEASE CACHE)
UNSET(MaidSafeCommon_MODULES_DIR CACHE)
UNSET(MaidSafeCommon_TOOLS_DIR CACHE)

IF(NOT MAIDSAFE_COMMON_ROOT_DIR AND DEFAULT_THIRD_PARTY_ROOT)
  SET(MAIDSAFE_COMMON_ROOT_DIR ${DEFAULT_THIRD_PARTY_ROOT})
ENDIF()

SET(MAIDSAFE_PATH_SUFFIX maidsafe_common_lib/build/common_lib/lib lib)
FIND_LIBRARY(MaidSafeCommon_LIBRARY_RELEASE NAMES maidsafe_common PATHS ${MAIDSAFE_COMMON_LIB_DIR} ${MAIDSAFE_COMMON_ROOT_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)
FIND_LIBRARY(MaidSafeCommon_LIBRARY_DEBUG NAMES maidsafe_common_d PATHS ${MAIDSAFE_COMMON_LIB_DIR} ${MAIDSAFE_COMMON_ROOT_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

SET(MAIDSAFE_PATH_SUFFIX maidsafe_common_lib/build/common_lib/include include)
FIND_PATH(MaidSafeCommon_INCLUDE_DIR maidsafe/common/version.h PATHS ${MAIDSAFE_COMMON_INC_DIR} ${MAIDSAFE_COMMON_ROOT_DIR} PATH_SUFFIXES ${MAIDSAFE_PATH_SUFFIX} NO_SYSTEM_ENVIRONMENT_PATH NO_CMAKE_SYSTEM_PATH)

GET_FILENAME_COMPONENT(MAIDSAFE_COMMON_LIBRARY_DIR ${MaidSafeCommon_LIBRARY_RELEASE} PATH)
SET(MaidSafeCommon_LIBRARY_DIR ${MAIDSAFE_COMMON_LIBRARY_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(MAIDSAFE_COMMON_LIBRARY_DIR_DEBUG ${MaidSafeCommon_LIBRARY_DEBUG} PATH)
  SET(MaidSafeCommon_LIBRARY_DIR_DEBUG ${MAIDSAFE_COMMON_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Logging debug libraries directory" FORCE)
ENDIF()


IF(NOT MaidSafeCommon_LIBRARY_RELEASE)
  IF(NOT MAIDSAFE_COMMON_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Logging.   NO MAIDSAFE_COMMON LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_LIB_DIR=<Path to glog lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_ROOT_DIR=<Path to glog root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(MaidSafeCommon_LIBRARY ${MaidSafeCommon_LIBRARY_RELEASE} CACHE PATH "Path to Google Logging library" FORCE)
ENDIF()

IF(MSVC)
  IF(NOT MaidSafeCommon_LIBRARY_DEBUG)
    IF(NOT MAIDSAFE_COMMON_REQUIRED)
      RETURN()
    ENDIF()
    SET(ERROR_MESSAGE "\nCould not find Google Logging.  NO *DEBUG* MAIDSAFE_COMMON LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_ROOT_DIR=<Path to glog root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ELSE()
    SET(MaidSafeCommon_LIBRARY debug ${MaidSafeCommon_LIBRARY_DEBUG} optimized ${MaidSafeCommon_LIBRARY} CACHE PATH "Path to Google Logging libraries" FORCE)
  ENDIF()
ENDIF()

IF(NOT MaidSafeCommon_INCLUDE_DIR)
  IF(NOT MAIDSAFE_COMMON_REQUIRED)
    RETURN()
  ENDIF()
  SET(ERROR_MESSAGE "\nCould not find Google Logging.  NO HEADER FILE - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Logging is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_INC_DIR=<Path to glog include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DMAIDSAFE_COMMON_ROOT_DIR=<Path to glog root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ELSE()
  SET(MaidSafeCommon_FOUND TRUE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
ENDIF()

MESSAGE("-- Found Google Logging library")
IF(MSVC)
  MESSAGE("-- Found Google Logging Debug library")
ENDIF()
