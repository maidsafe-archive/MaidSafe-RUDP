/* Copyright 2012 MaidSafe.net limited

This MaidSafe Software is licensed under the MaidSafe.net Commercial License, version 1.0 or later,
and The General Public License (GPL), version 3. By contributing code to this project You agree to
the terms laid out in the MaidSafe Contributor Agreement, version 1.0, found in the root directory
of this project at LICENSE, COPYING and CONTRIBUTOR respectively and also available at:

http://www.novinet.com/license

Unless required by applicable law or agreed to in writing, software distributed under the License is
distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
implied. See the License for the specific language governing permissions and limitations under the
License.
*/

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
