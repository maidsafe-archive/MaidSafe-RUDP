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


SET_DIRECTORY_PROPERTIES(PROPERTIES INCLUDE_DIRECTORIES "")

FILE(GLOB cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
FILE(GLOB cryptopp_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

# Not used
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/eccrypto.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/eprecomp.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/cryptlib_bds.cpp")

# Set up test
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/adhoc.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/bench.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/bench2.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/datatest.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dlltest.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/fipsalgt.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/regtest.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/test.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/validat1.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/validat2.cpp")
LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/validat3.cpp")

SET(cryptopp_TEST_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/adhoc.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/bench.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/bench2.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/datatest.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/dlltest.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/fipsalgt.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/regtest.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/test.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/validat1.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/validat2.cpp
                          ${CMAKE_CURRENT_SOURCE_DIR}/validat3.cpp)

LIST(REMOVE_ITEM cryptopp_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/bench.h")
LIST(REMOVE_ITEM cryptopp_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/factory.h")
LIST(REMOVE_ITEM cryptopp_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/validate.h")

SET(cryptopp_TEST_HEADERS ${CMAKE_CURRENT_SOURCE_DIR}/bench.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/factory.h
                          ${CMAKE_CURRENT_SOURCE_DIR}/validate.h)
IF(NOT MINGW)
ADD_EXECUTABLE(cryptest ${cryptopp_TEST_SOURCES} ${cryptopp_TEST_HEADERS})
  # Need to copy test data to correct location
  FILE(GLOB cryptopp_TEST_DATA "${CMAKE_CURRENT_SOURCE_DIR}/TestData/*.dat")
  FILE(GLOB cryptopp_TEST_VECTORS "${CMAKE_CURRENT_SOURCE_DIR}/TestVectors/*.txt")
  FILE(MAKE_DIRECTORY cryptopp)
  FILE(COPY ${cryptopp_TEST_DATA} DESTINATION TestData)
  FILE(COPY ${cryptopp_TEST_VECTORS} DESTINATION TestVectors)
ENDIF()
#ADD_LIBRARY(cryptopp SHARED ${cryptopp_SOURCES} ${cryptopp_HEADERS})
ADD_LIBRARY(cryptopp_static STATIC ${cryptopp_SOURCES} ${cryptopp_HEADERS})
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES OUTPUT_NAME cryptopp)
#ENDIF()

IF(MSVC)
  INSTALL(TARGETS cryptopp_static # cryptopp
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib)
ELSE()
  IF(NOT MINGW)
    SET_TARGET_PROPERTIES(cryptest PROPERTIES
                            DEBUG_OUTPUT_NAME cryptest${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME cryptest${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME cryptest${CMAKE_MINSIZEREL_POSTFIX})
  ENDIF()
  INSTALL(TARGETS cryptopp_static # cryptopp
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib)
ENDIF()

IF(NOT WIN32)
  ADD_DEFINITIONS(-DNDEBUG)
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(OPT_FLAG "")
ELSE()
  SET(OPT_FLAG "-O2")
ENDIF()
IF(APPLE)
  ADD_DEFINITIONS(-DCRYPTOPP_DISABLE_ASM)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-w -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions ${OPT_FLAG}")
  TARGET_LINK_LIBRARIES(cryptest cryptopp_static)
ELSEIF(UNIX AND NOT APPLE)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-w -pipe -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-fPIC -w -pipe -finline-functions ${OPT_FLAG}")
  TARGET_LINK_LIBRARIES(cryptest cryptopp_static)
ELSEIF(WIN32 AND NOT MSVC)
#  SET_TARGET_PROPERTIES(cryptopp PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
  #  TARGET_LINK_LIBRARIES(cryptest cryptopp_static odbc32 odbccp32 Ws2_32)
ELSEIF(WIN32 AND MSVC)
  CMAKE_POLICY(SET CMP0008 NEW)
  SET_TARGET_PROPERTIES(cryptopp_static PROPERTIES COMPILE_FLAGS "/D_WINDOWS /DUSE_PRECOMPILED_HEADERS /DWIN32 /D_VC80_UPGRADE=0x0710 /EHsc /W3")
  SET_TARGET_PROPERTIES(cryptest PROPERTIES COMPILE_FLAGS "/D_CONSOLE /DWIN32 /D_VC80_UPGRADE=0x0710 /D_MBCS /EHsc /W3 /Zm400"
                                            LINK_FLAGS "/STACK:1048576"
                                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG"
                                            LINK_FLAGS_RELWITHDEBINFO "/LTCG"
                                            LINK_FLAGS_MINSIZEREL "/LTCG")
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob2 /Oi /Oy /GL /DNDEBUG /GF /MD /Gy /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Oi /D_DEBUG /MDd /arch:SSE /ZI")
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/dll.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/iterhash.cpp") # this file doesn't use precompiled headers
  LIST(REMOVE_ITEM cryptopp_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp") # this file is used to create precompiled headers
  SET_SOURCE_FILES_PROPERTIES(${cryptopp_SOURCES} PROPERTIES
                               COMPILE_FLAGS "/Yu\"pch.h\"")
  SET_SOURCE_FILES_PROPERTIES(${CMAKE_CURRENT_SOURCE_DIR}/pch.cpp PROPERTIES
                               COMPILE_FLAGS "/Yc\"pch.h\"")
  TARGET_LINK_LIBRARIES(cryptest cryptopp_static odbc32.lib odbccp32.lib Ws2_32.lib)
ENDIF()

IF(NOT MINGW)
ADD_TEST(cryptest ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} v)
ADD_TEST(cryptest_aes ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} tv aes)
ADD_TEST(cryptest_sha ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} tv sha)
ADD_TEST(cryptest_rsa_pss ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} tv rsa_pss)
ADD_TEST(cryptest_rsa_oaep ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} tv rsa_oaep)
ADD_TEST(cryptest_rsa_pkcs1_1_5 ${CMAKE_RUNTIME_OUTPUT_DIRECTORY}/cryptest${TEST_POSTFIX} tv rsa_pkcs1_1_5)

SET_PROPERTY(TEST cryptest PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest PROPERTY TIMEOUT 60)
SET_PROPERTY(TEST cryptest_aes PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest_aes PROPERTY TIMEOUT 60)
SET_PROPERTY(TEST cryptest_sha PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest_sha PROPERTY TIMEOUT 60)
SET_PROPERTY(TEST cryptest_rsa_pss PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest_rsa_pss PROPERTY TIMEOUT 60)
SET_PROPERTY(TEST cryptest_rsa_oaep PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest_rsa_oaep PROPERTY TIMEOUT 60)
SET_PROPERTY(TEST cryptest_rsa_pkcs1_1_5 PROPERTY LABELS Behavioural crypto ${CMAKE_BUILD_TYPE})
SET_PROPERTY(TEST cryptest_rsa_pkcs1_1_5 PROPERTY TIMEOUT 60)
ENDIF()
