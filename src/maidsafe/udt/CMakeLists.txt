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


FILE(GLOB udt_SOURCES "${CMAKE_CURRENT_SOURCE_DIR}/*.cpp")
FILE(GLOB udt_HEADERS "${CMAKE_CURRENT_SOURCE_DIR}/*.h")

#ADD_LIBRARY(udt SHARED ${udt_SOURCES})
ADD_LIBRARY(udt_static STATIC ${udt_SOURCES})
#IF(NOT MSVC)
  SET_TARGET_PROPERTIES(udt_static PROPERTIES OUTPUT_NAME udt)
#ENDIF()

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

IF(APPLE)
  ADD_DEFINITIONS(-DOSX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -lgcov -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-w -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-fPIC -w -finline-functions ${OPT_FLAG}")
ELSEIF(UNIX AND NOT APPLE)
  ADD_DEFINITIONS(-DLINUX)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-w -pipe -finline-functions ${OPT_FLAG}")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-fPIC -w -pipe -finline-functions ${OPT_FLAG}")
ELSEIF(WIN32 AND NOT MSVC)
  ADD_DEFINITIONS(-D__MINGW__)
  SET(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -O0 -ggdb -pg -fprofile-arcs -ftest-coverage")
  SET(CMAKE_EXE_LINKER_FLAGS_DEBUG "${CMAKE_EXE_LINKER_FLAGS_DEBUG} -pg -fprofile-arcs -ftest-coverage")
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "-mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "-DDLL_EXPORTS  -mthreads -w -finline-functions ${OPT_FLAG} -D_WIN32_WINNT=0x0501")
ELSEIF(WIN32 AND MSVC)
  CMAKE_POLICY(SET CMP0008 NEW)
#  SET_TARGET_PROPERTIES(udt PROPERTIES COMPILE_FLAGS "/D\"UDT_EXPORTS\"")
  SET_TARGET_PROPERTIES(udt_static PROPERTIES COMPILE_FLAGS "/D \"UDT_STATIC\"")
  ADD_DEFINITIONS(-DWIN32 -D_UNICODE -DUNICODE)
  SET(CMAKE_CXX_FLAGS_RELEASE "/O2 /Ob1 /Ot /Oy /GL /D \"NDEBUG\" /EHsc /MD /Gy /W4 /Zi")
  SET(CMAKE_CXX_FLAGS_DEBUG "/Od /Ot /Oy /D \"_DEBUG\" /EHsc /MDd /W4 /ZI /Gm")
  SET(CMAKE_CXX_FLAGS_MINSIZEREL "/EHsc /MD")
  SET(CMAKE_CXX_FLAGS_RELWITHDEBINFO "/EHsc /MD")
ENDIF()
