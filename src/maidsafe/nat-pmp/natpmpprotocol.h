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

Created by Julian Cain on 11/3/09.

*/

#ifndef MAIDSAFE_NAT_PMP_NATPMPPROTOCOL_H_
#define MAIDSAFE_NAT_PMP_NATPMPPROTOCOL_H_

#include <boost/asio.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>

namespace natpmp {

/**
  * Implements the NAT-PMP base protocol.
  */
class Protocol {
 public:

/**
  * NAT-PMP port.
  */
  enum { kPort = 5351 };

/**
  * Supported protocols.
  */
  enum { kTcp = 1, kUdp = 2 };

/**
  * Result opcodes.
  * 0 - Success
  * 1 - Unsupported Version
  * 2 - Not Authorized/Refused (e.g. box supports mapping, but user
  * has turned feature off)
  * 3 - Network Failure (e.g. NAT box itself has not obtained a
  * DHCP lease)
  * 4 - Out of resources
  (NAT box cannot create any more mappings at this time)
  * 5 - Unsupported opcode
  */
  enum ResultOpcodes {
    kResultSuccess = 0,
    kResultUnsupportedVersion = 1,
    kResultNotAuthorisedRefused = 2,
    kResultNetworkFailure = 3,
    kResultOutOfResources = 4,
    kResultUnsupportedOpcode = 5,
    kResultUndefined = 64
  };

/**
  * Error codes.
  */
  enum ErrorCodes {
    kErrorInvalidArgs = 1,
    kErrorSocketError = 2,
    kErrorConnect = 3,
    kErrorSend = 4,
    kErrorReceiveFrom = 5,
    kErrorSourceConflict = 6,
    kErrorCannotGetGateway = 7
  };

/**
  * Mapping request structure.
  */
  struct MappingRequest {
    bool operator == (const MappingRequest & other) const {
      return std::memcmp(buffer, other.buffer, sizeof(buffer)) == 0;
    }

    std::size_t length;
    char buffer[12];
    boost::uint8_t retry_count;
  };

/**
  * External ip address request structure.
  */
  struct ExternalAddressRequest {
    boost::uint16_t opcode;
  };

/**
  * Mapping response structure.
  */
  struct MappingResponse {
    bool operator == (const MappingResponse & other) const {
      return (private_port == other.private_port &&
              public_port == other.public_port);
    }

    boost::uint16_t type;
    boost::uint16_t result_code;
    boost::uint32_t epoch;
    boost::asio::ip::address public_address;
    boost::uint16_t private_port;
    boost::uint16_t public_port;
    boost::uint32_t lifetime;
  };

/**
  * Generates a string representation from an opcode
  * @param opcode
  */
  static const char * StringFromOpcode(unsigned int opcode);

 private:

  // ...

 protected:

  // ...
};

}  // namespace natpnp

#endif  // MAIDSAFE_NAT_PMP_NATPMPPROTOCOL_H_
