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

#ifndef MAIDSAFE_RUDP_NAT_TYPE_H_
#define MAIDSAFE_RUDP_NAT_TYPE_H_

#include <string>

namespace maidsafe {

namespace rudp {

enum class nat_type : char {
  symmetric,
  other,
  unknown
};

template <typename Elem, typename Traits>
std::basic_ostream<Elem, Traits>& operator<<(std::basic_ostream<Elem, Traits>& ostream,
                                             const nat_type& nat_type) {
  std::string nat_str;
  switch (nat_type) {
    case nat_type::symmetric:
      nat_str = "symmetric NAT";
      break;
    case nat_type::other:
      nat_str = "other NAT";
      break;
    case nat_type::unknown:
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
