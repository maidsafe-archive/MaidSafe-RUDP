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


SET(TEST_LIBS_DIRS ${Boost_LIBRARY_DIRS} ${Gtest_LIBRARY_DIR})
SET(TEST_LIBS_DIRS_DEBUG ${Boost_LIBRARY_DIRS} ${Gtest_LIBRARY_DIR_DEBUG})
SET_PROPERTY(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY INCLUDE_DIRECTORIES ${${PROJECT_NAME}_SOURCE_DIR} ${Boost_INCLUDE_DIR} ${Gtest_INCLUDE_DIR})

FILE(GLOB SOURCE_FILES_UDT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
FILE(GLOB HEADER_FILES_UDT_DIR "${CMAKE_CURRENT_SOURCE_DIR}/*.h")
SET(ALL_FILES_UDT_DIR ${SOURCE_FILES_UDT_DIR} ${HEADER_FILES_UDT_DIR})
SOURCE_GROUP("UDT Source Files" FILES ${SOURCE_FILES_UDT_DIR})
SOURCE_GROUP("UDT Header Files" FILES ${HEADER_FILES_UDT_DIR})

FILE(GLOB ALL_FILES_UDT_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.cpp" "${CMAKE_CURRENT_SOURCE_DIR}/tests/*.h")
SET(ALL_FILES_UDT_TESTS_DIR ${ALL_FILES_UDT_TESTS_DIR} PARENT_SCOPE)

#ADD_LIBRARY(udt SHARED ${ALL_FILES_UDT_DIR})
ADD_LIBRARY(udt_static STATIC ${ALL_FILES_UDT_DIR})
SET_TARGET_PROPERTIES(udt_static PROPERTIES OUTPUT_NAME udt)
ADD_EXECUTABLE(TESTudt ${ALL_FILES_UDT_TESTS_DIR})

#IF(WIN32)
#  TARGET_LINK_LIBRARIES(udt ws2_32.lib)
#ENDIF()

IF(MSVC)
  INSTALL(TARGETS udt_static # udt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION bin
            ARCHIVE DESTINATION lib
          )
ELSE()
  IF(NOT ${KDEV})
    SET_TARGET_PROPERTIES(TESTudt PROPERTIES
                            DEBUG_OUTPUT_NAME TESTudt${CMAKE_DEBUG_POSTFIX}
                            RELWITHDEBINFO_OUTPUT_NAME TESTudt${CMAKE_RELWITHDEBINFO_POSTFIX}
                            MINSIZEREL_OUTPUT_NAME TESTudt${CMAKE_MINSIZEREL_POSTFIX})
  ENDIF()
  INSTALL(TARGETS udt_static # udt
            RUNTIME DESTINATION bin
            LIBRARY DESTINATION lib
            ARCHIVE DESTINATION lib
          )
ENDIF()

IF(CMAKE_BUILD_TYPE MATCHES "Debug")
  SET(OPT_FLAG "")
ELSE()
  SET(OPT_FLAG "-O3")
ENDIF()

TARGET_LINK_LIBRARIES(TESTudt udt_static ${Boost_DATE_TIME_LIBRARIES} ${Boost_THREAD_LIBRARIES} ${Gtest_LIBRARY})

IF(APPLE)
  ADD_DEFINITIONS(-DOSX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-w -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions -fno-strict-aliasing ${OPT_FLAG}")
ELSEIF(UNIX AND NOT APPLE)
  ADD_DEFINITIONS(-DLINUX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-w -pipe -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-fPIC -w -pipe -finline-functions -fno-strict-aliasing ${OPT_FLAG}")
ELSEIF(WIN32 AND NOT MSVC)
  ADD_DEFINITIONS(-D__MINGW__)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-DDLL_EXPORTS  -mthreads -w -finline-functions -fno-strict-aliasing ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
ELSEIF(WIN32 AND MSVC)
  CMAKE_POLICY(SET CMP0008 NEW)
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "/D\"UDT_EXPORTS\"")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "/D \"UDT_STATIC\"")
  ADD_DEFINITIONS(-DWIN32 -D_UNICODE -DUNICODE)
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob1 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MD /Gy /W4 /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /EHsc /MDd /W4 /ZI /Gm")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "/EHsc /MD")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/EHsc /MD")
  # Given a link dir of "a/b/c", MSVC adds "a/b/c/" AND "a/b/c/CMAKE_BUILD_TYPE" as link dirs, so we
  # can't just use "LINK_DIRECTORIES" as some Google debug libs have the same name as the release version.
  FOREACH(LIBS_DIR ${TEST_LIBS_DIRS})
    STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
    SET(TEST_LINKER_LIBS_DIRS_RELEASE "${TEST_LINKER_LIBS_DIRS_RELEASE} /LIBPATH:\"${LIBS_DIR}\"")
  ENDFOREACH()
  FOREACH(LIBS_DIR ${TEST_LIBS_DIRS_DEBUG})
    STRING(REPLACE "\\" "\\\\" LIBS_DIR ${LIBS_DIR})
    SET(TEST_LINKER_LIBS_DIRS_DEBUG "${TEST_LINKER_LIBS_DIRS_DEBUG} /LIBPATH:\"${LIBS_DIR}\"")
  ENDFOREACH()
  SET_TARGET_PROPERTIES(udt_static PROPERTIES
                            COMPILE_FLAGS "/D \"UDT_STATIC\"")
  SET_TARGET_PROPERTIES(TESTudt PROPERTIES
                            COMPILE_FLAGS "/D \"UDT_STATIC\""
                            LINK_FLAGS_RELEASE "/OPT:REF /OPT:ICF /LTCG /INCREMENTAL:NO ${TEST_LINKER_LIBS_DIRS_RELEASE}"
                            LINK_FLAGS_DEBUG "${TEST_LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_RELWITHDEBINFO "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}"
                            LINK_FLAGS_MINSIZEREL "/LTCG ${TEST_LINKER_LIBS_DIRS_DEBUG}")
ENDIF()
