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

#include "maidsafe/rudp/packets/ack_of_ack_packet.h"

namespace asio = boost::asio;

namespace maidsafe {

namespace rudp {

namespace detail {

AckOfAckPacket::AckOfAckPacket() { SetType(kPacketType); }

uint32_t AckOfAckPacket::AckSequenceNumber() const { return AdditionalInfo(); }

void AckOfAckPacket::SetAckSequenceNumber(uint32_t n) { SetAdditionalInfo(n); }

bool AckOfAckPacket::IsValid(const asio::const_buffer& buffer) {
  return (IsValidBase(buffer, kPacketType) && (asio::buffer_size(buffer) == kPacketSize));
}

bool AckOfAckPacket::Decode(const asio::const_buffer& buffer) {
  return DecodeBase(buffer, kPacketType);
}

size_t AckOfAckPacket::Encode(const asio::mutable_buffer& buffer) const {
  return EncodeBase(buffer);
}

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
