/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_UTILS_H_
#define MAIDSAFE_TRANSPORT_UTILS_H_

#include <string>
#include <vector>
#include "maidsafe/transport/transport.h"

// TODO(Fraser#5#): 2011-08-30 - remove #include version.h and #if block once
//                  NAT detection is implemented and this is file is not
//                  #included by node_container.h

#include "maidsafe/transport/version.h"

#if MAIDSAFE_TRANSPORT_VERSION != 200
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-transport library.
#endif

namespace maidsafe {

namespace transport {

// Convert an IP in ASCII format to IPv4 or IPv6 bytes
std::string IpAsciiToBytes(const std::string &decimal_ip);

// Convert an IPv4 or IPv6 in bytes format to ASCII format
std::string IpBytesToAscii(const std::string &bytes_ip);

// Convert an internet network address into dotted string format.
void IpNetToAscii(uint32_t address, char *ip_buffer);

// Convert a dotted string format internet address into Ipv4 format.
uint32_t IpAsciiToNet(const char *buffer);

// Return all local addresses
std::vector<IP> GetLocalAddresses();

}  // namespace transport

}  // namespace maidsafe

#endif  // MAIDSAFE_TRANSPORT_UTILS_H_
