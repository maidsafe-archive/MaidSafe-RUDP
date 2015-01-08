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

#ifndef MAIDSAFE_RUDP_BOOST_ASIO_CONVERSIONS_H_
#define MAIDSAFE_RUDP_BOOST_ASIO_CONVERSIONS_H_

namespace maidsafe { namespace rudp {

inline boost::asio::ip::address_v4 to_boost(const asio::ip::address_v4& addr) {
  return boost::asio::ip::address_v4(addr.to_ulong());
}

inline asio::ip::address_v4 from_boost(const boost::asio::ip::address_v4& addr) {
  return asio::ip::address_v4(addr.to_ulong());
}

inline boost::asio::ip::address_v6 to_boost(const asio::ip::address_v6& addr) {
  boost::asio::ip::address_v6::bytes_type target;

  auto source = addr.to_bytes();

  for (std::size_t i = 0; i < std::tuple_size<decltype(target)>::value; ++i)
    target.at(i) = source.at(i);

  return boost::asio::ip::address_v6(target, addr.scope_id());
}

inline asio::ip::address_v6 from_boost(const boost::asio::ip::address_v6& addr) {
  asio::ip::address_v6::bytes_type target;

  auto source = addr.to_bytes();

  for (std::size_t i = 0; i < std::tuple_size<decltype(source)>::value; ++i)
    target.at(i) = source.at(i);

  return asio::ip::address_v6(target, addr.scope_id());
}

inline boost::asio::ip::address to_boost(const asio::ip::address& addr) {
  if (addr.is_v4()) {
    return boost::asio::ip::address(to_boost(addr.to_v4()));
  } else if (addr.is_v6()) {
    return boost::asio::ip::address(to_boost(addr.to_v6()));
  } else {
    assert(0 && "Unknown IP version");
    return boost::asio::ip::address();
  }
}

inline asio::ip::address from_boost(const boost::asio::ip::address& addr) {
  if (addr.is_v4()) {
    return asio::ip::address(from_boost(addr.to_v4()));
  } else if (addr.is_v6()) {
    return asio::ip::address(from_boost(addr.to_v6()));
  } else {
    assert(0 && "Unknown IP version");
    return asio::ip::address();
  }
}

inline boost::asio::ip::udp::endpoint to_boost(const asio::ip::udp::endpoint& e) {
  return boost::asio::ip::udp::endpoint(to_boost(e.address()), e.port());
}

inline asio::ip::udp::endpoint from_boost(const boost::asio::ip::udp::endpoint& e) {
  return asio::ip::udp::endpoint(from_boost(e.address()), e.port());
}

}  // namespace rudp
}  // namespace maidsafe

#endif  // MAIDSAFE_RUDP_BOOST_ASIO_CONVERSIONS_H_
