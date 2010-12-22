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

namespace base {

namespace test {

void GenerateRandomStrings(const int &string_count,
                           const size_t &string_size) {
  for (int i = 0; i < string_count; ++i)
    RandomString(string_size);
}

TEST(UtilsTest, FUNC_BASE_RandomStringMultiThread) {
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
    Stats<int> stats;
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
    Stats<float> stats;
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

TEST(UtilsTest, BEH_BASE_IntToString) {
  EXPECT_EQ("1234567890", IntToString(1234567890));
  EXPECT_EQ("-1234567890", IntToString(-1234567890));
  EXPECT_EQ("0", IntToString(0));
  EXPECT_EQ("0", IntToString(-0));
}


TEST(UtilsTest, BEH_BASE_RandomStringSingleThread) {
  const size_t kStringSize = 4096;
  std::string test1 = RandomAlphaNumericString(kStringSize);
  std::string test2 = RandomAlphaNumericString(kStringSize);
  EXPECT_EQ(kStringSize, test1.size());
  EXPECT_EQ(kStringSize, test2.size());
  EXPECT_NE(test1, test2);
  const std::string kAlphaNumeric("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefgh"
                                  "ijklmnopqrstuvwxyz");
  for (size_t i = 0; i < kStringSize; ++i) {
    EXPECT_NE(std::string::npos, kAlphaNumeric.find(test1.at(i)));
    EXPECT_NE(std::string::npos, kAlphaNumeric.find(test2.at(i)));
  }
}

TEST(UtilsTest, BEH_BASE_HexEncodeDecode) {
  const std::string kKnownEncoded("0123456789abcdef");
  const std::string kKnownDecoded("\x1\x23\x45\x67\x89\xab\xcd\xef");
  EXPECT_EQ(kKnownEncoded, EncodeToHex(kKnownDecoded));
  EXPECT_EQ(kKnownDecoded, DecodeFromHex(kKnownEncoded));
  EXPECT_TRUE(EncodeToHex("").empty());
  EXPECT_TRUE(DecodeFromHex("").empty());
  EXPECT_TRUE(DecodeFromHex("{").empty());
  for (int i = 0; i < 1000; ++i) {
    std::string original = RandomString(100);
    std::string encoded = EncodeToHex(original);
    EXPECT_EQ(200U, encoded.size());
    std::string decoded = DecodeFromHex(encoded);
    EXPECT_EQ(original, decoded);
  }
}

TEST(UtilsTest, BEH_BASE_Base64EncodeDecode) {
  const std::string kKnownEncoded("BCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqr"
                                  "stuvwxyz0123456789+/A");
  const std::string kKnownDecoded("\x04\x20\xc4\x14\x61\xc8\x24\xa2\xcc\x34\xe3"
      "\xd0\x45\x24\xd4\x55\x65\xd8\x65\xa6\xdc\x75\xe7\xe0\x86\x28\xe4\x96\x69"
      "\xe8\xa6\xaa\xec\xb6\xeb\xf0\xc7\x2c\xf4\xd7\x6d\xf8\xe7\xae\xfc\xf7\xef"
      "\xc0");
  EXPECT_EQ(kKnownEncoded, EncodeToBase64(kKnownDecoded));
  EXPECT_EQ(kKnownDecoded, DecodeFromBase64(kKnownEncoded));
  EXPECT_TRUE(EncodeToBase64("").empty());
  EXPECT_TRUE(DecodeFromBase64("").empty());
  EXPECT_TRUE(DecodeFromBase64("{").empty());
  for (int i = 0; i < 1000; ++i) {
    std::string original = RandomString(100);
    std::string encoded = EncodeToBase64(original);
    EXPECT_EQ(136U, encoded.size()) << "Encoding failed.";
    std::string decoded = DecodeFromBase64(encoded);
    EXPECT_EQ(original, decoded) << "encoded -> decoded failed.";
  }
}

TEST(UtilsTest, BEH_BASE_Base32EncodeDecode) {
  const std::string kKnownEncoded("bcdefghijkmnpqrstuvwxyz23456789a");
  const std::string kKnownDecoded("\x08\x86\x42\x98\xe8\x4a\x96\xc6\xb9\xf0\x8c"
                                  "\xa7\x4a\xda\xf8\xce\xb7\xce\xfb\xe0");
  EXPECT_EQ(kKnownEncoded, EncodeToBase32(kKnownDecoded));
  EXPECT_EQ(kKnownDecoded, DecodeFromBase32(kKnownEncoded));
  EXPECT_TRUE(EncodeToBase32("").empty());
  EXPECT_TRUE(DecodeFromBase32("").empty());
  EXPECT_TRUE(DecodeFromBase32("{").empty());
  for (int i = 0; i < 1000; ++i) {
    std::string original = RandomString(100);
    std::string encoded = EncodeToBase32(original);
    EXPECT_EQ(160U, encoded.size()) << "Encoding failed.";
    std::string decoded = DecodeFromBase32(encoded);
    EXPECT_EQ(original, decoded) << "encoded -> decoded failed.";
  }
}

TEST(UtilsTest, BEH_BASE_TimeFunctions) {
  boost::uint64_t s, ms, ns;
  ms = GetEpochMilliseconds();
  ns = GetEpochNanoseconds();
  s = GetEpochTime();

  // Within a second
  EXPECT_NEAR(s*1000, ms, 1000) << "s vs. ms failed.";
  // Within a second
  EXPECT_NEAR(s*1000000000, ns, 1000000000) << "s vs. ns failed.";
  // Within quarter of a second
  EXPECT_NEAR(ms*1000000, ns, 250000000) << "ms vs. ns failed.";
}

TEST(UtilsTest, BEH_BASE_NextTransactionId) {
  boost::uint32_t id1 = GenerateNextTransactionId(0);
  boost::uint32_t id2 = GenerateNextTransactionId(0);
  EXPECT_NE(0U, id1);
  EXPECT_NE(0U, id2);
  EXPECT_NE(id1, id2);
  id1 = 2147483645;
  id2 = GenerateNextTransactionId(id1);
  EXPECT_EQ(1U, id2);
}

TEST(UtilsTest, BEH_BASE_RandomNumberGen) {
  std::set<boost::int32_t>random_ints;
  std::set<boost::uint32_t>random_uints;
  const size_t kCount(10000);
  // look for less than 0.01% duplicates
  const size_t kMaxDuplicates(kCount * 0.0001);
  for (size_t i = 0; i < kCount; ++i) {
    random_ints.insert(RandomInt32());
    random_uints.insert(RandomUint32());
  }
  EXPECT_GE(kMaxDuplicates, kCount - random_ints.size());
  EXPECT_GE(kMaxDuplicates, kCount - random_uints.size());
}

}  // namespace test

}  // namespace base
