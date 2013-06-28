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

#ifndef MAIDSAFE_RUDP_NAT_TYPE_H_
#define MAIDSAFE_RUDP_NAT_TYPE_H_

#include <string>


namespace maidsafe {

namespace rudp {

enum class NatType { kSymmetric, kOther, kUnknown };

template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const NatType &nat_type) {
  std::string nat_str;
  switch (nat_type) {
    case NatType::kSymmetric:
      nat_str = "symmetric NAT";
      break;
    case NatType::kOther:
      nat_str = "other NAT";
      break;
    case NatType::kUnknown:
      nat_str = "unknown NAT";
      break;
    default:
      nat_str = "Invalid NAT type";
      break;
  }

  for (auto& ch : nat_str)
    ostream << ostream.widen(ch);
  return ostream;
}

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_NAT_TYPE_H_
