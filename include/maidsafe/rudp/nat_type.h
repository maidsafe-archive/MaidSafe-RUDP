/*******************************************************************************
 *  Copyright 2012 MaidSafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of MaidSafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the licence   *
 *  file licence.txt found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of MaidSafe.net. *
 ******************************************************************************/

#ifndef MAIDSAFE_RUDP_NAT_TYPE_H_
#define MAIDSAFE_RUDP_NAT_TYPE_H_

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

  for (std::string::iterator itr(nat_str.begin()); itr != nat_str.end(); ++itr)
    ostream << ostream.widen(*itr);
  return ostream;
}

}  // namespace rudp

}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_NAT_TYPE_H_
