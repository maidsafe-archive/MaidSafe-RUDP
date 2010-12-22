/* Copyright (c) 2009 maidsafe.net limited
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

    * Redistributions of source code must retain the above copyright notice,
    this list of conditions and the following disclaimer.
    * Redistributions in binary form must reproduce the above copyright notice,
    this list of conditions and the following disclaimer in the documentation
    and/or other materials provided with the distribution.
    * Neither the name of the maidsafe.net limited nor the names of its
    contributors may be used to endorse or promote products derived from this
    software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED.  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include <gtest/gtest.h>
#include <boost/timer.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/progress.hpp>
#include <boost/thread.hpp>
#include <algorithm>
#include <cstdlib>
#include <set>
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"

namespace transport {

namespace test {

TEST(UtilsTest, BEH_BASE_BytesAndAscii) {
  std::string good_string_v4("71.111.111.100");
  std::string good_string_v6("2001:db8:85a3::8a2e:370:7334");
  std::string bad_string("Not an IP");
  EXPECT_EQ("Good", base::IpAsciiToBytes(good_string_v4));
  EXPECT_EQ(good_string_v4, base::IpBytesToAscii("Good"));
  std::string result_v6 = base::IpAsciiToBytes(good_string_v6);
  EXPECT_FALSE(result_v6.empty());
  EXPECT_EQ(good_string_v6, base::IpBytesToAscii(result_v6));
  EXPECT_TRUE(base::IpAsciiToBytes(bad_string).empty());
  EXPECT_TRUE(base::IpBytesToAscii(bad_string).empty());
}

TEST(UtilsTest, BEH_BASE_DecimalAndAscii) {
  std::string dotted("121.12.121.1");
  boost::scoped_array<char> ipbuf(new char[32]);
  boost::uint32_t n = base::IpAsciiToNet(dotted.c_str());
  boost::uint32_t g = 2030860545;
  EXPECT_EQ(g, n);
  base::IpNetToAscii(n, ipbuf.get());
  std::string reformed(ipbuf.get());
  EXPECT_EQ(dotted, reformed);
}

TEST(UtilsTest, BEH_BASE_NetworkInterfaces) {
  std::vector<base::DeviceStruct> alldevices;
  base::GetNetInterfaces(&alldevices);
  EXPECT_FALSE(alldevices.empty());
  for (size_t n = 0; n < alldevices.size(); ++n) {
    base::DeviceStruct ds = alldevices[n];
    DLOG(INFO) << n << " - " << ds.ip_address.to_string() << std::endl;
  }
}

}  // namespace test

}  // namespace transport
