/* Copyright (c) 2010 maidsafe.net limited
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

#include <boost/lexical_cast.hpp>
#include <gtest/gtest.h>
#include <maidsafe/base/utils.h>
#include <string>
#include "maidsafe/transport/transportutils.h"


namespace transport {

namespace test {

TEST(TransportUtilsTest, BEH_TRANS_ValidIp) {
  EXPECT_FALSE(ValidIP("Rubbish"));
  EXPECT_FALSE(ValidIP(
      "Llanfairpwllgwyngyllgogerychwyrndrobwllllantysiliogogogoch"));
  EXPECT_FALSE(ValidIP(""));
  const int kRepeats(1000);
  for (int n = 0; n < kRepeats; ++n) {
    std::string ip;
    for (int i = 0; i < 4; ++i)
      ip += boost::lexical_cast<std::string>((base::RandomInt32() % 256)) +
            (i < 3 ? "." : "");
    EXPECT_TRUE(ValidIP(ip)) << "IP " << ip << " is not valid";
  }
}

TEST(TransportUtilsTest, BEH_TRANS_ValidPort) {
  for (Port i = 0; i < 5001; ++i)
    EXPECT_FALSE(ValidPort(i)) << "Port " << i << " is valid";
  Port max_port(-1);
  for (Port j = 5001; j < max_port ; ++j)
    EXPECT_TRUE(ValidPort(j)) << "Port " << j << " is not valid";
  EXPECT_TRUE(ValidPort(max_port)) << "Port " << max_port << " is not valid";
}

}  // namespace test

}  // namespace transport
