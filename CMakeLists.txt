#==============================================================================#
#                                                                              #
#  Copyright (c) 2011 MaidSafe.net limited                                     #
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


SET(MS_PROJECT_NAME maidsafe_transport)

CMAKE_MINIMUM_REQUIRED(VERSION 2.8.4 FATAL_ERROR)
MESSAGE("================================================================================\n")

GET_FILENAME_COMPONENT(CMAKE_BUILD_TYPE_DIR ${CMAKE_BINARY_DIR} NAME)

# Variable MSVC is not set until after "PROJECT" command below
IF(CMAKE_BUILD_TYPE_DIR MATCHES "Win_MSVC")
  SET(CMAKE_BUILD_TYPE_DIR Release)
ELSEIF(CMAKE_BUILD_TYPE_DIR MATCHES "kdev")
  SET(CMAKE_BUILD_TYPE_DIR Debug)
  SET(KDEV 1)
ENDIF()

IF(NOT ${CMAKE_C_COMPILER_WORKS})
  MESSAGE(FATAL_ERROR "No generator previously specified.\nTo see a full list of generators, run:\n\tcmake --help\n")
ENDIF()

# This "PROJECT" command resets CMAKE_BUILD_TYPE, hence it's copied from CMAKE_BUILD_TYPE_DIR which is set above.
IF((CMAKE_BUILD_TYPE_DIR MATCHES "Release") OR (DEFINED ${KDEV}))
  PROJECT(${MS_PROJECT_NAME})
ELSE()
  STRING(TOLOWER ${CMAKE_BUILD_TYPE_DIR} MS_PROJECT_NAME_APPENDIX)
  PROJECT(${MS_PROJECT_NAME}_${MS_PROJECT_NAME_APPENDIX})
ENDIF()

SET(CMAKE_BUILD_TYPE ${CMAKE_BUILD_TYPE_DIR} CACHE INTERNAL "Except for MSVC, the build type is set by running cmake from the appropriate build subdirectory e.g. for a Debug build, \"cd build/Linux/Debug && cmake ../../..\"." FORCE)


###################################################################################################
# MaidSafe Common library search                                                                  #
###################################################################################################
SET(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${PROJECT_SOURCE_DIR}/build)
INCLUDE(maidsafe_find_common)


###################################################################################################
# Standard setup                                                                                  #
###################################################################################################
SET(PROTO_SOURCE_DIR ${PROJECT_SOURCE_DIR}/src)
SET(PROTO_FILES "maidsafe/transport/transport.proto")
INCLUDE(maidsafe_standard_setup)
HANDLE_VERSIONS(${PROJECT_SOURCE_DIR}/src/maidsafe/transport/version.h)


###################################################################################################
# Set up all files as GLOBs                                                                       #
###################################################################################################
####    CODE    ####
LIST(APPEND ALL_FILES_LIBUPNP_DIR
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/igd_desc_parse.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/minixml.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/minisoap.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/miniwget.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/upnpcommands.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/upnpreplyparse.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/upnperrors.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/miniupnpc.c
       ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/libupnp/minissdpc.c)
SOURCE_GROUP("libupnp Source Files" FILES ${ALL_FILES_LIBUPNP_DIR})

FILE(GLOB SOURCE_FILES_NATPMP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat-pmp/*.cc")
FILE(GLOB HEADER_FILES_NATPMP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat-pmp/*.h")
SET(ALL_FILES_NATPMP_DIR ${SOURCE_FILES_NATPMP_DIR} ${HEADER_FILES_NATPMP_DIR})
SOURCE_GROUP("NAT-PMP Source Files" FILES ${SOURCE_FILES_NATPMP_DIR})
SOURCE_GROUP("NAT-PMP Header Files" FILES ${HEADER_FILES_NATPMP_DIR})

FILE(GLOB SOURCE_FILES_TRANSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/*.cc")
FILE(GLOB HEADER_FILES_TRANSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/*.h")
SET(ALL_FILES_TRANSPORT_DIR ${SOURCE_FILES_TRANSPORT_DIR} ${HEADER_FILES_TRANSPORT_DIR})
SET(STYLE_TRANSPORT ${ALL_FILES_TRANSPORT_DIR})
LIST(REMOVE_ITEM STYLE_TRANSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/transport.pb.cc")
LIST(REMOVE_ITEM STYLE_TRANSPORT "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/transport.pb.h")
SOURCE_GROUP("Transport Source Files" FILES ${SOURCE_FILES_TRANSPORT_DIR})
SOURCE_GROUP("Transport Header Files" FILES ${HEADER_FILES_TRANSPORT_DIR})

FILE(GLOB SOURCE_FILES_TCP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tcp_*.cc")
FILE(GLOB HEADER_FILES_TCP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tcp_*.h")
SOURCE_GROUP("TCP Source Files" FILES ${SOURCE_FILES_TCP})
SOURCE_GROUP("TCP Header Files" FILES ${HEADER_FILES_TCP})

FILE(GLOB SOURCE_FILES_UDP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/udp_*.cc")
FILE(GLOB HEADER_FILES_UDP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/udp_*.h")
SOURCE_GROUP("UDP Source Files" FILES ${SOURCE_FILES_UDP})
SOURCE_GROUP("UDP Header Files" FILES ${HEADER_FILES_UDP})

FILE(GLOB SOURCE_FILES_RUDP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/rudp_*.cc")
FILE(GLOB HEADER_FILES_RUDP "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/rudp_*.h")
SOURCE_GROUP("RUDP Source Files" FILES ${SOURCE_FILES_RUDP})
SOURCE_GROUP("RUDP Header Files" FILES ${HEADER_FILES_RUDP})

FILE(GLOB SOURCE_FILES_NAT_DETECTION "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat_detection*.cc")
FILE(GLOB HEADER_FILES_NAT_DETECTION "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat_detection*.h")
SOURCE_GROUP("NAT Detection Source Files" FILES ${SOURCE_FILES_NAT_DETECTION})
SOURCE_GROUP("NAT Detection Header Files" FILES ${HEADER_FILES_NAT_DETECTION})

FILE(GLOB SOURCE_FILES_UPNP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/*.cc")
FILE(GLOB HEADER_FILES_UPNP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/*.h")
LIST(REMOVE_ITEM SOURCE_FILES_UPNP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/upnp_client_impl.cc")
LIST(REMOVE_ITEM HEADER_FILES_UPNP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/upnp_client_impl.h")
SET(ALL_FILES_UPNP_DIR ${SOURCE_FILES_UPNP_DIR} ${HEADER_FILES_UPNP_DIR})
SOURCE_GROUP("UPnP Source Files" FILES ${SOURCE_FILES_UPNP_DIR})
SOURCE_GROUP("UPnP Header Files" FILES ${HEADER_FILES_UPNP_DIR})

SET(ALL_FILES ${ALL_FILES_TRANSPORT_DIR} ${ALL_FILES_LIBUPNP_DIR} ${ALL_FILES_UPNP_DIR} ${ALL_FILES_NATPMP_DIR})

####    TESTS    ####
FILE(GLOB SOURCE_FILES_TEST_TRANSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tests/*.cc")
FILE(GLOB HEADER_FILES_TEST_TRANSPORT_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tests/*.h")
SET(ALL_FILES_TEST_TRANSPORT_DIR ${SOURCE_FILES_TEST_TRANSPORT_DIR} ${HEADER_FILES_TEST_TRANSPORT_DIR})
SOURCE_GROUP("Test Source Files" FILES ${SOURCE_FILES_TEST_TRANSPORT_DIR})
SOURCE_GROUP("Test Header Files" FILES ${HEADER_FILES_TEST_TRANSPORT_DIR})

# FILE(GLOB ALL_FILES_TEST_NATPMP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat-pmp/tests*.cc"
#                                     "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat-pmp/tests/*.h")
# FILE(GLOB ALL_FILES_TEST_UPNP_DIR "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/tests/*.cc"
#                                   "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/upnp/tests/*.h")


###################################################################################################
# Define MaidSafe libraries and executables                                                       #
###################################################################################################
MS_ADD_STATIC_LIBRARY(${MS_PROJECT_NAME} ${ALL_FILES})
MS_ADD_EXECUTABLE(TESTtransport Tests ${ALL_FILES_TEST_TRANSPORT_DIR})
# MS_ADD_EXECUTABLE(TESTnatpmp Tests ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_NATPMP_DIR})
# MS_ADD_EXECUTABLE(TESTupnp Tests ${ALL_FILES_TEST_MAIN} ${ALL_FILES_TEST_UPNP_DIR})

TARGET_LINK_LIBRARIES(maidsafe_transport_static
                        maidsafe_common_static
                        protobuf_static)
TARGET_LINK_LIBRARIES(TESTtransport maidsafe_transport_static gtest_static gmock_static)
# TARGET_LINK_LIBRARIES(TESTnatpmp maidsafe_transport_static gtest_static)
# TARGET_LINK_LIBRARIES(TESTupnp maidsafe_transport_static gtest_static)


###################################################################################################
# Set compiler and linker flags                                                                   #
###################################################################################################
INCLUDE(maidsafe_standard_flags)

IF(MSVC)
  # Warnings switched off for protocol buffer generated files and libupnp files
  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/transport/transport.pb.cc
                              ${ALL_FILES_LIBUPNP_DIR}
                                PROPERTIES COMPILE_FLAGS "/W0")
ELSEIF(UNIX)
  FILE(GLOB PROTO_SOURCE_FILES "${PROJECT_SOURCE_DIR}/src/maidsafe/transport/*.pb.cc")
#  SET_SOURCE_FILES_PROPERTIES(${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tcp_connection.cc
#                                PROPERTIES COMPILE_FLAGS "-Wno-effc++")
  SET_SOURCE_FILES_PROPERTIES(${PROTO_SOURCE_FILES} PROPERTIES COMPILE_FLAGS "-w")
ENDIF()




###################################################################################################
# Tests                                                                                           #
###################################################################################################
ADD_STYLE_TEST(${STYLE_TRANSPORT} ${ALL_FILES_TEST_TRANSPORT_DIR})
ADD_GTESTS(TESTtransport)
# ADD_GTESTS(TESTnatpmp)
# ADD_GTESTS(TESTupnp)
TEST_SUMMARY_OUTPUT()

# Remove files from coverage stats
ADD_COVERAGE_EXCLUDE(libupnp/)
ADD_COVERAGE_EXCLUDE(nat-pmp/)
ADD_COVERAGE_EXCLUDE(upnp/)
ADD_COVERAGE_EXCLUDE(transport.pb.cc)


###################################################################################################
# Install details                                                                                 #
###################################################################################################
FINAL_MESSAGE()
RENAME_OUTDATED_BUILT_EXES()

SET(MAIDSAFE_TRANSPORT_INSTALL_FILES
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/transport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/version.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/message_handler.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/contact.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/tcp_transport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/udp_transport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/rudp_transport.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/rudp_parameters.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/rudp_message_handler.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat_detection.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/nat_traversal.h
      ${PROJECT_SOURCE_DIR}/src/maidsafe/transport/utils.h)  # TODO - remove utils.h once NAT detection is implemented and this is not #included by node_container.h

MS_INSTALL_LIBS(maidsafe_transport_static)
MS_INSTALL_HEADERS(transport ${MAIDSAFE_TRANSPORT_INSTALL_FILES})
MS_INSTALL_EXPORT()
