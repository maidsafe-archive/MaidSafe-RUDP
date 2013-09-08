/*  Copyright 2012 MaidSafe.net limited

    This MaidSafe Software is licensed to you under (1) the MaidSafe.net Commercial License,
    version 1.0 or later, or (2) The General Public License (GPL), version 3, depending on which
    licence you accepted on initial access to the Software (the "Licences").

    By contributing code to the MaidSafe Software, or to this project generally, you agree to be
    bound by the terms of the MaidSafe Contributor Agreement, version 1.0, found in the root
    directory of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also
    available at: http://www.novinet.com/license

    Unless required by applicable law or agreed to in writing, the MaidSafe Software distributed
    under the GPL Licence is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS
    OF ANY KIND, either express or implied.

    See the Licences for the specific language governing permissions and limitations relating to
    use of the MaidSafe Software.                                                                 */

// Original author: Christopher M. Kohlhoff (chris at kohlhoff dot com)

#ifndef MAIDSAFE_RUDP_PACKETS_PACKET_H_
#define MAIDSAFE_RUDP_PACKETS_PACKET_H_

#include <cstdint>

#include "boost/asio/buffer.hpp"

namespace maidsafe {

namespace rudp {

namespace detail {

class Packet {
 public:
  // Get the destination socket id from an encoded packet.
  static bool DecodeDestinationSocketId(uint32_t* id, const boost::asio::const_buffer& data);

 protected:
  // Prevent deletion through this type.
  virtual ~Packet();

  // Helper functions for encoding and decoding integers.
  static void DecodeUint32(uint32_t* n, const unsigned char* p);
  static void EncodeUint32(uint32_t n, unsigned char* p);
};

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_PACKETS_PACKET_H_
