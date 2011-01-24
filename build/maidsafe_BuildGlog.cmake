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
#  Module used to build Google Logging libs & compiler.                        #
#                                                                              #
#==============================================================================#

IF(MSVC)
  UNSET(GLOG_SLN CACHE)
  UNSET(GLOG_VSPROJECTS_DIR CACHE)
  FIND_FILE(GLOG_SLN NAMES google-glog.sln PATHS ${${PROJECT_NAME}_SOURCE_DIR}/../thirdpartylibs/glog NO_DEFAULT_PATH)
  # Make a copy of .sln file to work with to avoid modified .sln being accidentally committed to repository
  IF(NOT GLOG_SLN)
    SET(ERROR_MESSAGE "\nCould not find Google Logging source.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}The Glog source should be in the thirdpartylibs directory.  ")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}You can download it at http://code.google.com/p/google-glog\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Glog is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  FILE(COPY ${GLOG_SLN} DESTINATION ${${PROJECT_NAME}_BINARY_DIR})
  FILE(RENAME ${${PROJECT_NAME}_BINARY_DIR}/google-glog.sln ${${PROJECT_NAME}_SOURCE_DIR}/../thirdpartylibs/glog/google-glog_copy.sln)
  UNSET(GLOG_SLN CACHE)
  FIND_FILE(GLOG_SLN NAMES google-glog_copy.sln PATHS ${${PROJECT_NAME}_SOURCE_DIR}/../thirdpartylibs/glog NO_DEFAULT_PATH)
  GET_FILENAME_COMPONENT(GLOG_ROOT_DIR ${GLOG_SLN} PATH)
  MESSAGE("-- Upgrading Google Logging solution")
  EXECUTE_PROCESS(COMMAND devenv ${GLOG_SLN} /Upgrade OUTPUT_VARIABLE OUTVAR RESULT_VARIABLE RESVAR)
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}")
  ENDIF()
  MESSAGE("-- Building Google Logging debug libraries")
  EXECUTE_PROCESS(COMMAND devenv ${GLOG_SLN} /Build "Debug|Win32" /Project libglog_static OUTPUT_VARIABLE OUTVAR RESULT_VARIABLE RESVAR)
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}")
  ENDIF()
  MESSAGE("-- Building Google Logging release libraries")
  EXECUTE_PROCESS(COMMAND devenv ${GLOG_SLN} /Build "Release|Win32" /Project libglog_static OUTPUT_VARIABLE OUTVAR RESULT_VARIABLE RESVAR)
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}")
  ENDIF()
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}")
  ENDIF()
ELSE()
  UNSET(GLOG_CONFIGURE CACHE)
  SET(GLOG_SRC_DIR ${${PROJECT_NAME}_SOURCE_DIR}/../thirdpartylibs/glog)
  FIND_FILE(GLOG_CONFIGURE configure PATHS ${GLOG_SRC_DIR} NO_DEFAULT_PATH)
  IF(NOT GLOG_CONFIGURE)
    SET(ERROR_MESSAGE "${OUTVAR}\n${ERRVAR}\nCould not configure Google Logging.\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}If Glog is already installed, run:\n")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_INC_DIR=<Path to glog include directory> and/or")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_LIB_DIR=<Path to glog lib directory> and/or")
    SET(ERROR_MESSAGE "${ERROR_MESSAGE}\n${ERROR_MESSAGE_CMAKE_PATH} -DGLOG_ROOT_DIR=<Path to glog root directory>\n")
    MESSAGE(FATAL_ERROR "${ERROR_MESSAGE}")
  ENDIF()
  SET(GLOG_ROOT_DIR ${CMAKE_BINARY_DIR}/thirdpartylibs/glog CACHE PATH "Path to Google Logging root directory" FORCE)
  FILE(MAKE_DIRECTORY ${GLOG_ROOT_DIR})
  GET_FILENAME_COMPONENT(GLOG_SRC_DIR ${GLOG_CONFIGURE} PATH)
  MESSAGE("-- Configuring Google Logging library")
  MESSAGE("     This may take a few minutes...")
  EXECUTE_PROCESS(COMMAND sh ${GLOG_CONFIGURE} --prefix=${GLOG_ROOT_DIR} --enable-shared=no WORKING_DIRECTORY ${GLOG_SRC_DIR} OUTPUT_VARIABLE OUTVAR RESULT_VARIABLE RESVAR ERROR_VARIABLE ERRVAR)
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}")
  ENDIF()
  MESSAGE("-- Making Google Logging library")
  MESSAGE("     This may take a few minutes...")
  EXECUTE_PROCESS(COMMAND make -i -C ${GLOG_SRC_DIR} install OUTPUT_VARIABLE OUTVAR RESULT_VARIABLE RESVAR ERROR_VARIABLE ERRVAR)
  IF(NOT ${RESVAR} EQUAL 0)
    MESSAGE("${OUTVAR}\n${ERRVAR}")
  ENDIF()
ENDIF()
INCLUDE(${${PROJECT_NAME}_ROOT}/build/maidsafe_FindGlog.cmake)
