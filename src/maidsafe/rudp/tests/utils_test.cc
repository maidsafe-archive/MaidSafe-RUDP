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

#include <algorithm>
#include <cstdlib>
#include <set>
#include "boost/scoped_array.hpp"
#include "maidsafe/common/test.h"
#include "maidsafe/transport/log.h"
#include "maidsafe/transport/utils.h"

namespace maidsafe {

namespace transport {

namespace test {

TEST(UtilsTest, BEH_BytesAndAscii) {
  std::string good_string_v4("71.111.111.100");
  std::string good_string_v6("2001:db8:85a3::8a2e:370:7334");
  std::string bad_string("Not an IP");
  EXPECT_EQ("Good", IpAsciiToBytes(good_string_v4));
  EXPECT_EQ(good_string_v4, IpBytesToAscii("Good"));
  std::string result_v6 = IpAsciiToBytes(good_string_v6);
  EXPECT_FALSE(result_v6.empty());
  EXPECT_EQ(good_string_v6, IpBytesToAscii(result_v6));
  EXPECT_TRUE(IpAsciiToBytes(bad_string).empty());
  EXPECT_TRUE(IpBytesToAscii(bad_string).empty());
}

TEST(UtilsTest, BEH_DecimalAndAscii) {
  std::string dotted("121.12.121.1");
  boost::scoped_array<char> ipbuf(new char[32]);
  uint32_t n = IpAsciiToNet(dotted.c_str());
  uint32_t g = 2030860545;
  EXPECT_EQ(g, n);
  IpNetToAscii(n, ipbuf.get());
  std::string reformed(ipbuf.get());
  EXPECT_EQ(dotted, reformed);
}

TEST(UtilsTest, BEH_NetworkInterfaces) {
  std::vector<IP> all_local_ips(GetLocalAddresses());
  EXPECT_FALSE(all_local_ips.empty());
  for (size_t n = 0; n < all_local_ips.size(); ++n)
    DLOG(INFO) << n << " - " << all_local_ips.at(n).to_string();
}

}  // namespace test

}  // namespace transport

}  // namespace maidsafe
