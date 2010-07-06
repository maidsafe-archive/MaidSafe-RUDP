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
#include <list>
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"

namespace test_utils {

void GenerateRandomStrings(const int &string_count,
                           const size_t &string_size) {
  for (int i = 0; i < string_count; ++i)
    base::RandomString(string_size);
}

}  // namespace test_utils

TEST(UtilsTest, BEH_BASE_RandomStringMultiThread) {
  int thread_count(20);
  int string_count(1000);
  size_t string_size(4096);
  std::vector< boost::shared_ptr<boost::thread> > test_threads;
  for (int i = 0; i < thread_count; ++i) {
    test_threads.push_back(boost::shared_ptr<boost::thread>(new boost::thread(
        &test_utils::GenerateRandomStrings, string_count, string_size)));
  }
  for (int i = 0; i < thread_count; ++i) {
    test_threads.at(i)->join();
  }
}

TEST(UtilsTest, BEH_BASE_Stats) {
  {
    base::Stats<int> stats;
    EXPECT_EQ(0, stats.Size());
    EXPECT_EQ(0, stats.Min());
    EXPECT_EQ(0, stats.Max());
    EXPECT_EQ(0, stats.Sum());
    EXPECT_EQ(0, stats.Mean());

    stats.Add(1);
    stats.Add(2);
    stats.Add(4);
    stats.Add(5);

    EXPECT_EQ(4, stats.Size());
    EXPECT_EQ(1, stats.Min());
    EXPECT_EQ(5, stats.Max());
    EXPECT_EQ(12, stats.Sum());
    EXPECT_EQ(3, stats.Mean());
  }
  {
    base::Stats<float> stats;
    EXPECT_EQ(0, stats.Size());
    EXPECT_FLOAT_EQ(0.0, stats.Min());
    EXPECT_FLOAT_EQ(0.0, stats.Max());
    EXPECT_FLOAT_EQ(0.0, stats.Sum());
    EXPECT_FLOAT_EQ(0.0, stats.Mean());

    stats.Add(1.1);
    stats.Add(2.2);
    stats.Add(3.3);
    stats.Add(4.4);

    EXPECT_EQ(4, stats.Size());
    EXPECT_FLOAT_EQ(1.1, stats.Min());
    EXPECT_FLOAT_EQ(4.4, stats.Max());
    EXPECT_FLOAT_EQ(11.0, stats.Sum());
    EXPECT_FLOAT_EQ(2.75, stats.Mean());
  }
}

TEST(UtilsTest, BEH_BASE_IntegersAndStrings) {
  std::string p_str, n_str;
  int p = 1234567890;
  int n = -1234567890;
  p_str = "1234567890";
  n_str = "-1234567890";
  ASSERT_EQ(p, boost::lexical_cast<int>(base::IntToString(p))) <<
            "int -> string -> int failed for positive int.";
  ASSERT_EQ(n, boost::lexical_cast<int>(base::IntToString(n))) <<
            "int -> string -> int failed for negative int.";
  ASSERT_EQ(p_str, base::IntToString(boost::lexical_cast<int>(p_str))) <<
            "string -> int -> string failed for positive int.";
  ASSERT_EQ(n_str, base::IntToString(boost::lexical_cast<int>(n_str))) <<
            "string -> int -> string failed for negative int.";
}


TEST(UtilsTest, BEH_BASE_RandomStringSingleThread) {
  unsigned int length = 4096;
  std::string first = base::RandomString(length);
  std::string second = base::RandomString(length);
  ASSERT_EQ(length, first.length()) <<
            "Size of first string is not the requested size: " << length;
  ASSERT_EQ(length, second.length()) <<
            "Size of second string is not the requested size: " << length;
  ASSERT_NE(first, second) << "The two 'random' strings are the same.";
  for (int i = 0; i < static_cast<int>(length); i++) {
    ASSERT_GT(127, static_cast<int>(first[i]));
    ASSERT_GT(127, static_cast<int>(second[i]));
    // checking all characters are ascii characters
    ASSERT_TRUE(((47 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i] <  58))) ||
                ((64 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i] < 91))) ||
                ((96 < static_cast<int>(first[i])) &&
                 (static_cast<int>(first[i]) < 123)));
    ASSERT_TRUE(((47 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i] <  58))) ||
                ((64 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i] < 91))) ||
                ((96 < static_cast<int>(second[i])) &&
                 (static_cast<int>(second[i]) < 123)));
  }
}

TEST(UtilsTest, BEH_BASE_HexEncodeDecode) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (int i = 0; i < 1000; ++i) {
    std::string original = co.Hash(base::RandomString(200), "",
                                   crypto::STRING_STRING, false);
    std::string encoded = base::EncodeToHex(original);
    ASSERT_EQ(128U, encoded.size()) << "Encoding failed.";
    std::string decoded = base::DecodeFromHex(encoded);
    ASSERT_EQ(original, decoded) << "encoded -> decoded failed.";
  }
}

TEST(UtilsTest, BEH_BASE_Base64EncodeDecode) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (int i = 0; i < 1000; ++i) {
    std::string original = co.Hash(base::RandomString(200), "",
                                   crypto::STRING_STRING, false);
    std::string encoded = base::EncodeToBase64(original);
    ASSERT_EQ(88U, encoded.size()) << "Encoding failed.";
    std::string decoded = base::DecodeFromBase64(encoded);
    ASSERT_EQ(original, decoded) << "encoded -> decoded failed.";
  }
}

TEST(UtilsTest, BEH_BASE_Base32EncodeDecode) {
  crypto::Crypto co;
  co.set_hash_algorithm(crypto::SHA_512);
  for (int i = 0; i < 1000; ++i) {
    std::string original = co.Hash(base::RandomString(200), "",
                                   crypto::STRING_STRING, false);
    std::string encoded = base::EncodeToBase32(original);
    ASSERT_EQ(103U, encoded.size()) << "Encoding failed.";
    std::string decoded = base::DecodeFromBase32(encoded);
    ASSERT_EQ(original, decoded) << "encoded -> decoded failed.";
  }
}

TEST(UtilsTest, BEH_BASE_BytesAndAscii) {
  std::string good_string_v4("71.111.111.100");
  std::string good_string_v6("2001:db8:85a3::8a2e:370:7334");
  std::string bad_string("Not an IP");
  ASSERT_EQ("Good", base::IpAsciiToBytes(good_string_v4));
  ASSERT_EQ(good_string_v4, base::IpBytesToAscii("Good"));
  std::string result_v6 = base::IpAsciiToBytes(good_string_v6);
  ASSERT_FALSE(result_v6.empty());
  ASSERT_EQ(good_string_v6, base::IpBytesToAscii(result_v6));
  ASSERT_TRUE(base::IpAsciiToBytes(bad_string).empty());
  ASSERT_TRUE(base::IpBytesToAscii(bad_string).empty());
}

TEST(UtilsTest, BEH_BASE_DecimalAndAscii) {
  std::string dotted("121.12.121.1");
  char *ipbuf = new char[32];
  boost::uint32_t n = base::IpAsciiToNet(dotted.c_str());
  boost::uint32_t g = 2030860545;
  ASSERT_EQ(g, n) << "Conversion to decimal failed.";
  base::IpNetToAscii(n, ipbuf);
  std::string reformed(ipbuf);
  ASSERT_EQ(dotted, reformed) << "Conversion to ASCII failed.";
  delete []ipbuf;
}

TEST(UtilsTest, BEH_BASE_TimeFunctions) {
  boost::uint64_t s, ms, ns;
  ms = base::GetEpochMilliseconds();
  ns = base::GetEpochNanoseconds();
  s = base::GetEpochTime();

  // Within a second
  ASSERT_NEAR(s*1000, ms, 1000) << "s vs. ms failed.";
  // Within a second
  ASSERT_NEAR(s*1000000000, ns, 1000000000) << "s vs. ns failed.";
  // Within quarter of a second
  ASSERT_NEAR(ms*1000000, ns, 250000000) << "ms vs. ns failed.";
}

TEST(UtilsTest, BEH_BASE_NextTransactionId) {
  boost::uint32_t id1 = base::GenerateNextTransactionId(0);
  boost::uint32_t id2 = base::GenerateNextTransactionId(0);

  ASSERT_NE(static_cast<boost::uint32_t>(0), id1) <<
            "Transaction id1 came back as 0.";
  ASSERT_NE(static_cast<boost::uint32_t>(0), id2) <<
            "Transaction id2 came back as 0.";
  ASSERT_NE(id1, id2) << "Transaction id1 and id2 came back the same.";

  id1 = 2147483646;
  id2 = base::GenerateNextTransactionId(id1);
  ASSERT_EQ(static_cast<boost::uint32_t>(1), id2) <<
            "Transaction id2 came back different from 1: " << id2;
}

TEST(UtilsTest, BEH_BASE_NetworkInterfaces) {
  std::vector<base::DeviceStruct> alldevices;
  base::GetNetInterfaces(&alldevices);
  ASSERT_NE(static_cast<boost::uint32_t>(0), alldevices.size());
  for (unsigned int n = 0; n < alldevices.size(); n++) {
    base::DeviceStruct ds = alldevices[n];
    printf("%d - %s\n", n, ds.ip_address.to_string().c_str());
  }
}

TEST(UtilsTest, BEH_BASE_RandomNumberGen) {
  std::list<boost::uint32_t>uall_nums;
  std::list<boost::uint32_t>all_nums;
  int uall = 0;
  int uwith_random_removed = 0;
  int all = 0;
  int with_random_removed = 0;

  double finish = 1000;
  for (int i = 0;i < finish; ++i) {
    all_nums.push_front(base::RandomUint32());
    uall_nums.push_front(base::RandomInt32());
  }
  all = all_nums.size();
  uall = all_nums.size();
  all_nums.unique();
  with_random_removed = all_nums.size();
  uall_nums.unique();
  uwith_random_removed = uall_nums.size();
  // look for less than 1% duplicates
  ASSERT_EQ(finish, all);
  ASSERT_GT(finish * 0.01, all - with_random_removed);
  ASSERT_EQ(finish, uall);
  ASSERT_GT(finish * 0.01, uall - uwith_random_removed);
}
