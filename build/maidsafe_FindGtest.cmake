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
#                                                                              #
#  Module used to locate GoogleTest libs and headers.                          #
#                                                                              #
#  If using MSVC, finds only Gtest libs which have been compiled using         #
#  dynamically-linked C runtime library (i.e. with /MD set rather than /MT)    #
#                                                                              #
#  Settable variables to aid with finding Gtest are:                           #
#    GTEST_LIB_DIR, GTEST_INC_DIR and GTEST_ROOT_DIR                           #
#                                                                              #
#  Variables set and cached by this module are:                                #
#    Gtest_INCLUDE_DIR, Gtest_LIBRARY_DIR, Gtest_LIBRARY                       #
#                                                                              #
#  For MSVC, Gtest_LIBRARY_DIR_DEBUG and Gtest_LIBRARY_DEBUG are also set      #
#  and cached.                                                                 #
#                                                                              #
#==============================================================================#


UNSET(Gtest_INCLUDE_DIR CACHE)
UNSET(Gtest_LIBRARY_DIR CACHE)
UNSET(Gtest_LIBRARY_DIR_DEBUG CACHE)
UNSET(Gtest_LIBRARY CACHE)
UNSET(Gtest_LIBRARY_DEBUG CACHE)

IF(GTEST_LIB_DIR)
  SET(GTEST_LIB_DIR ${GTEST_LIB_DIR} CACHE PATH "Path to GoogleTest libraries directory" FORCE)
ENDIF()
IF(GTEST_INC_DIR)
  SET(GTEST_INC_DIR ${GTEST_INC_DIR} CACHE PATH "Path to GoogleTest include directory" FORCE)
ENDIF()
IF(GTEST_ROOT_DIR)
  SET(GTEST_ROOT_DIR ${GTEST_ROOT_DIR} CACHE PATH "Path to GoogleTest root directory" FORCE)
ENDIF()

IF(MSVC)
  IF(CMAKE_CL_64)
    SET(GTEST_LIBPATH_SUFFIX msvc/x64/Release)
  ELSE()
    SET(GTEST_LIBPATH_SUFFIX msvc/gtest-md/Release)
  ENDIF()
ELSE()
  SET(GTEST_LIBPATH_SUFFIX lib lib64)
ENDIF()

FIND_LIBRARY(Gtest_LIBRARY NAMES gtest gtest-md PATHS ${GTEST_LIB_DIR} ${GTEST_ROOT_DIR} PATH_SUFFIXES ${GTEST_LIBPATH_SUFFIX})
IF(MSVC)
  IF(CMAKE_CL_64)
    SET(GTEST_LIBPATH_SUFFIX msvc/x64/Debug)
  ELSE()
    SET(GTEST_LIBPATH_SUFFIX msvc/gtest-md/Debug)
  ENDIF()
  FIND_LIBRARY(Gtest_LIBRARY_DEBUG NAMES gtestd gtest-mdd PATHS ${GTEST_LIB_DIR} ${GTEST_ROOT_DIR} PATH_SUFFIXES ${GTEST_LIBPATH_SUFFIX})
ENDIF()

FIND_PATH(Gtest_INCLUDE_DIR gtest/gtest.h PATHS ${GTEST_INC_DIR} ${GTEST_ROOT_DIR}/include)

GET_FILENAME_COMPONENT(GTEST_LIBRARY_DIR ${Gtest_LIBRARY} PATH)
SET(Gtest_LIBRARY_DIR ${GTEST_LIBRARY_DIR} CACHE PATH "Path to GoogleTest libraries directory" FORCE)
IF(MSVC)
  GET_FILENAME_COMPONENT(GTEST_LIBRARY_DIR_DEBUG ${Gtest_LIBRARY_DEBUG} PATH)
  SET(Gtest_LIBRARY_DIR_DEBUG ${GTEST_LIBRARY_DIR_DEBUG} CACHE PATH "Path to GoogleTest debug libraries directory" FORCE)
ENDIF()

IF(NOT Gtest_LIBRARY)
  SET(ERROR_MESSAGE "\nCould not find Google Test.  NO GTEST LIBRARY - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/googletest\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Test is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGTEST_LIB_DIR=<Path to gtest lib directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGTEST_ROOT_DIR=<Path to gtest root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

IF(MSVC)
  IF(NOT Gtest_LIBRARY_DEBUG)
    SET(ERROR_MESSAGE "\nCould not find Google Test.  NO *DEBUG* GTEST LIBRARY - ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/googletest\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Test is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGTEST_ROOT_DIR=<Path to gtest root directory>")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
ENDIF()

IF(NOT Gtest_INCLUDE_DIR)
  SET(ERROR_MESSAGE "\nCould not find Google Test.  NO GTEST.H - ")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/googletest\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Google Test is already installed, run:\n")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGTEST_INC_DIR=<Path to gtest include directory> and/or")
  SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGTEST_ROOT_DIR=<Path to gtest root directory>")
  MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
ENDIF()

MESSAGE("-- Found Google Test library")
IF(MSVC)
  MESSAGE("-- Found Google Test Debug library")
ENDIF()
