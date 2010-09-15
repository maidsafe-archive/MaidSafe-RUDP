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
#  Variables set and cached by this module are:                                #
#    Glog_INCLUDE_DIR, Glog_LIBRARY_DIR, Glog_LIBRARY, Glog_FOUND              #
#                                                                              #
#  For MSVC, Glog_LIBRARY_DIR_DEBUG and Glog_LIBRARY_DEBUG are also set and    #
#  cached.                                                                     #
#                                                                              #
#==============================================================================#

IF(WIN32 AND NOT MSVC)
  MESSAGE(FATAL_ERROR "\nThis module is only applicable on Windows when building for Microsoft Visual Studio.\n\n")
ENDIF()

UNSET(WARNING_MESSAGE)
UNSET(Glog_INCLUDE_DIR CACHE)
UNSET(Glog_LIBRARY_DIR CACHE)
UNSET(Glog_LIBRARY_DIR_DEBUG CACHE)
UNSET(Glog_LIBRARY CACHE)
UNSET(Glog_LIBRARY_DEBUG CACHE)
UNSET(Glog_FOUND CACHE)

IF(GLOG_LIB_DIR)
  SET(GLOG_LIB_DIR ${GLOG_LIB_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
ENDIF()
IF(GLOG_INC_DIR)
  SET(GLOG_INC_DIR ${GLOG_INC_DIR} CACHE PATH "Path to Google Logging include directory" FORCE)
ENDIF()
IF(GLOG_ROOT_DIR)
  SET(GLOG_ROOT_DIR ${GLOG_ROOT_DIR} CACHE PATH "Path to Google Logging root directory" FORCE)
ENDIF()

IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Release)
ELSE()
  SET(GLOG_LIBPATH_SUFFIX lib lib64)
ENDIF()

FIND_LIBRARY(Glog_LIBRARY NAMES libglog.a glog libglog_static PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX})
IF(MSVC)
  SET(GLOG_LIBPATH_SUFFIX Debug)
  FIND_LIBRARY(Glog_LIBRARY_DEBUG NAMES libglog_static PATHS ${GLOG_LIB_DIR} ${GLOG_ROOT_DIR} PATH_SUFFIXES ${GLOG_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Glog_INCLUDE_DIR glog/logging.h PATHS ${GLOG_INC_DIR} ${GLOG_ROOT_DIR}/src/windows)

GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR ${Glog_LIBRARY} PATH)
SET(Glog_LIBRARY_DIR ${GLOG_LIBRARY_DIR} CACHE PATH "Path to Google Logging libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(GLOG_LIBRARY_DIR_DEBUG ${Glog_LIBRARY_DEBUG} PATH)
  SET(Glog_LIBRARY_DIR_DEBUG ${GLOG_LIBRARY_DIR_DEBUG} CACHE PATH "Path to Google Logging debug libraries directory" FORCE)
ENDIF()


IF(NOT Glog_LIBRARY)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Google Logging library")
ELSE()
  MESSAGE("-- Found Google Logging library")
ENDIF()

IF(MSVC)
  IF(NOT Glog_LIBRARY_DEBUG)
    SET(WARNING_MESSAGE TRUE)
    MESSAGE("-- Did not find Google Logging Debug library")
  ELSE()
    MESSAGE("-- Found Google Logging Debug library")
  ENDIF()
ENDIF()

IF(NOT Glog_INCLUDE_DIR)
  SET(WARNING_MESSAGE TRUE)
  MESSAGE("-- Did not find Google Logging library headers")
ENDIF()

IF(WARNING_MESSAGE)
  SET(WARNING_MESSAGE "   You can download it at http://code.google.com/p/google-glog\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   If Google Logging is already installed, run:\n")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_LIB_DIR=<Path to glog lib directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_INC_DIR=<Path to glog include directory> and/or")
  SET(WARNING_MESSAGE "${WARNING_MESSAGE}\n   ${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>")
  MESSAGE("${WARNING_MESSAGE}")
  SET(Glog_FOUND FALSE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
  UNSET(Glog_INCLUDE_DIR CACHE)
  UNSET(Glog_LIBRARY_DIR CACHE)
  UNSET(Glog_LIBRARY_DIR_DEBUG CACHE)
  UNSET(Glog_LIBRARY CACHE)
  UNSET(Glog_LIBRARY_DEBUG CACHE)
ELSE()
  SET(Glog_FOUND TRUE CACHE INTERNAL "Found Google Logging library and headers" FORCE)
ENDIF()

