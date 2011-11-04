/* Copyright (c) 2010 maidsafe.net limited
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

// Author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/transport/rudp_packet.h"

namespace asio = boost::asio;

namespace maidsafe {

namespace transport {

RudpPacket::~RudpPacket() {
}

bool RudpPacket::DecodeDestinationSocketId(boost::uint32_t *id,
                                           const asio::const_buffer &data) {
  // Refuse to decode anything that's too short.
  if (asio::buffer_size(data) < 16)
    return false;

  DecodeUint32(id, asio::buffer_cast<const unsigned char*>(data) + 12);
  return true;
}

void RudpPacket::DecodeUint32(boost::uint32_t *n, const unsigned char *p) {
  *n = p[0];
  *n = ((*n << 8) | p[1]);
  *n = ((*n << 8) | p[2]);
  *n = ((*n << 8) | p[3]);
}

void RudpPacket::EncodeUint32(boost::uint32_t n, unsigned char *p) {
  p[0] = ((n >> 24) & 0xff);
  p[1] = ((n >> 16) & 0xff);
  p[2] = ((n >> 8) & 0xff);
  p[3] = (n & 0xff);
}

}  // namespace transport

}  // namespace maidsafe
