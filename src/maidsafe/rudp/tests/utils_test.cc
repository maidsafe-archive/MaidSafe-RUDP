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
  catch(const boost::system::system_error& system_error) {
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
  catch(const boost::system::system_error& system_error) {
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
