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

#include "maidsafe-dht/common/utils.h"

#include <ctype.h>

#include <algorithm>
#include <limits>
#include <string>

#include "boost/lexical_cast.hpp"
#include "boost/scoped_array.hpp"
#include "boost/thread/mutex.hpp"
#include "boost/random/mersenne_twister.hpp"
#include "boost/random/uniform_int.hpp"
#include "boost/random/variate_generator.hpp"

#ifdef __MSVC__
#pragma warning(push)
#pragma warning(disable:4100 4127 4189 4244 4505 4512)
#endif
#include "maidsafe-dht/cryptopp/integer.h"
#include "maidsafe-dht/cryptopp/osrng.h"
#include "maidsafe-dht/cryptopp/base32.h"
#include "maidsafe-dht/cryptopp/base64.h"
#include "maidsafe-dht/cryptopp/hex.h"
#ifdef __MSVC__
#pragma warning(pop)
#endif
#include "maidsafe-dht/common/log.h"

namespace maidsafe {

static CryptoPP::AutoSeededX917RNG<CryptoPP::AES> g_srandom_number_generator;
static unsigned int g_last_random_number(0);
static boost::mt19937 g_random_number_generator(static_cast<unsigned int>(
    boost::posix_time::microsec_clock::universal_time().time_of_day().
    total_microseconds()) + g_last_random_number);
static boost::mutex g_srandom_number_generator_mutex;
static boost::mutex g_random_number_generator_mutex;

boost::int32_t SRandomInt32() {
  boost::int32_t result(0);
  bool success = false;
  while (!success) {
    boost::mutex::scoped_lock lock(g_srandom_number_generator_mutex);
    CryptoPP::Integer rand_num(g_srandom_number_generator, 32);
    if (rand_num.IsConvertableToLong()) {
      result = static_cast<boost::int32_t>(
               rand_num.AbsoluteValue().ConvertToLong());
      success = true;
    }
  }
  return result;
}

boost::int32_t RandomInt32() {
  boost::uniform_int<> uniform_distribution(0,
      boost::integer_traits<boost::int32_t>::const_max);
  boost::mutex::scoped_lock lock(g_random_number_generator_mutex);
  boost::variate_generator<boost::mt19937&, boost::uniform_int<>> uni(
      g_random_number_generator, uniform_distribution);
  return g_last_random_number = uni();
}

boost::uint32_t SRandomUint32() {
  return static_cast<boost::uint32_t>(SRandomInt32());
}

boost::uint32_t RandomUint32() {
  return static_cast<boost::uint32_t>(RandomInt32());
}

std::string SRandomString(const size_t &length) {
  std::string random_string;
  random_string.reserve(length);
  while (random_string.size() < length) {
#ifdef MAIDSAFE_APPLE
     size_t iter_length = (length - random_string.size()) < 65536U ?
                          (length - random_string.size()) : 65536U;
#else
    size_t iter_length = std::min(length - random_string.size(), size_t(65536));
#endif
    boost::scoped_array<byte> random_bytes(new byte[iter_length]);
    {
      boost::mutex::scoped_lock lock(g_srandom_number_generator_mutex);
      g_srandom_number_generator.GenerateBlock(random_bytes.get(), iter_length);
    }
    std::string random_substring;
    CryptoPP::StringSink string_sink(random_substring);
    string_sink.Put(random_bytes.get(), iter_length);
    random_string += random_substring;
  }
  return random_string;
}

std::string RandomString(const size_t &length) {
  boost::uniform_int<> uniform_distribution(0, 255);
  std::string random_string(length, 0);
  {
    boost::mutex::scoped_lock lock(g_random_number_generator_mutex);
    boost::variate_generator<boost::mt19937&, boost::uniform_int<>> uni(
        g_random_number_generator, uniform_distribution);
    std::generate(random_string.begin(), random_string.end(), uni);
    g_last_random_number = uni();
  }
  return random_string;
}

std::string RandomAlphaNumericString(const size_t &length) {
  static const char alpha_numerics[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
  boost::uniform_int<> uniform_distribution(0, 61);
  std::string random_string(length, 0);
  {
    boost::mutex::scoped_lock lock(g_random_number_generator_mutex);
    boost::variate_generator<boost::mt19937&, boost::uniform_int<>> uni(
        g_random_number_generator, uniform_distribution);
    for (auto it = random_string.begin(); it != random_string.end(); ++it)
      *it = alpha_numerics[uni()];
    g_last_random_number = uni();
  }
  return random_string;
}

std::string IntToString(const int &value) {
  return boost::lexical_cast<std::string>(value);
}

std::string EncodeToHex(const std::string &non_hex_input) {
  std::string hex_output;
  CryptoPP::StringSource(non_hex_input, true,
      new CryptoPP::HexEncoder(new CryptoPP::StringSink(hex_output), false));
  return hex_output;
}

std::string EncodeToBase64(const std::string &non_base64_input) {
  std::string base64_output;
  CryptoPP::StringSource(non_base64_input, true, new CryptoPP::Base64Encoder(
      new CryptoPP::StringSink(base64_output), false, 255));
  return base64_output;
}

std::string EncodeToBase32(const std::string &non_base32_input) {
  std::string base32_output;
  CryptoPP::StringSource(non_base32_input, true, new CryptoPP::Base32Encoder(
      new CryptoPP::StringSink(base32_output), false));
  return base32_output;
}

std::string DecodeFromHex(const std::string &hex_input) {
  std::string non_hex_output;
  CryptoPP::StringSource(hex_input, true,
      new CryptoPP::HexDecoder(new CryptoPP::StringSink(non_hex_output)));
  return non_hex_output;
}

std::string DecodeFromBase64(const std::string &base64_input) {
  std::string non_base64_output;
  CryptoPP::StringSource(base64_input, true,
      new CryptoPP::Base64Decoder(new CryptoPP::StringSink(non_base64_output)));
  return non_base64_output;
}

std::string DecodeFromBase32(const std::string &base32_input) {
  std::string non_base32_output;
  CryptoPP::StringSource(base32_input, true,
      new CryptoPP::Base32Decoder(new CryptoPP::StringSink(non_base32_output)));
  return non_base32_output;
}

boost::posix_time::time_duration GetDurationSinceEpoch() {
  return boost::posix_time::microsec_clock::universal_time() - kMaidSafeEpoch;
}

}  // namespace maidsafe
