/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.maidsafe.net/licenses

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#include "maidsafe/rudp/packets/packet.h"

namespace maidsafe {

namespace rudp {

namespace detail {

Packet::~Packet() {}

bool Packet::DecodeDestinationSocketId(uint32_t* id, const boost::asio::const_buffer& data) {
  // Refuse to decode anything that's too short.
  if (boost::asio::buffer_size(data) < 16)
    return false;

  DecodeUint32(id, boost::asio::buffer_cast<const unsigned char*>(data) + 12);
  return true;
}

void Packet::DecodeUint32(uint32_t* n, const unsigned char* p) {
  *n = p[0];
  *n = ((*n << 8) | p[1]);
  *n = ((*n << 8) | p[2]);
  *n = ((*n << 8) | p[3]);
}

void Packet::EncodeUint32(uint32_t n, unsigned char* p) {
  p[0] = ((n >> 24) & 0xff);
  p[1] = ((n >> 16) & 0xff);
  p[2] = ((n >> 8) & 0xff);
  p[3] = (n & 0xff);
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
