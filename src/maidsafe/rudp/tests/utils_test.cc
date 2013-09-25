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

#include <algorithm>
#include <cstdlib>
#include <set>
#include "boost/scoped_array.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/common/log.h"
#include "maidsafe/rudp/utils.h"

namespace maidsafe {

namespace rudp {

typedef boost::asio::ip::udp::endpoint Endpoint;

namespace detail {

namespace test {

TEST(UtilsTest, BEH_EndpointIsValid) {
  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::address::from_string("1.1.1.1"), 1024)));
  EXPECT_TRUE(IsValid(Endpoint(boost::asio::ip::address::from_string("1.1.1.1"), 1025)));
  EXPECT_TRUE(IsValid(Endpoint(boost::asio::ip::address::from_string("1.1.1.1"), 49150)));
  EXPECT_TRUE(IsValid(Endpoint(boost::asio::ip::address::from_string("1.1.1.1"), 65535)));
  //  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::address::from_string("1.1.1.1"), 49151)));
  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::address::from_string("0.0.0.0"), 49150)));

  boost::system::error_code error_code;
  try {
    boost::asio::ip::address::from_string("Rubbish");
  }
  catch (const boost::system::system_error& system_error) {
    error_code = system_error.code();
  }
#ifdef WIN32
  const int kErrorCodeValue(10022);
#else
  const int kErrorCodeValue(22);
#endif
  EXPECT_EQ(error_code.value(), kErrorCodeValue);
  error_code.clear();

  try {
    boost::asio::ip::address::from_string("256.1.1.1");
  }
  catch (const boost::system::system_error& system_error) {
    error_code = system_error.code();
  }
  EXPECT_EQ(error_code.value(), kErrorCodeValue);
  error_code.clear();

  EXPECT_FALSE(IsValid(Endpoint()));
  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::udp::v4(), 1025)));
  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::udp::v6(), 1025)));
  EXPECT_FALSE(IsValid(Endpoint(boost::asio::ip::address(), 1025)));
}

}  // namespace test

}  // namespace detail

}  // namespace rudp

}  // namespace maidsafe
