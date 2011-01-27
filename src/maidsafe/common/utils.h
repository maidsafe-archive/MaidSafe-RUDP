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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_COMMON_UTILS_H_
#define MAIDSAFE_COMMON_UTILS_H_

#include <string>
#include "boost/cstdint.hpp"
#include "boost/date_time/posix_time/posix_time.hpp"

namespace maidsafe {

// 01 Jan 2000
const boost::posix_time::ptime kMaidSafeEpoch(
    boost::posix_time::from_iso_string("20000101T000000"));

/**
* @class Stats
* A simple class to determine statistical properties of a data set, computed
* without storing the values. Data type must be numerical.
*/
template <typename T>
class Stats {
 public:
  Stats() : size_(0), min_(0), max_(0), sum_(0) {}
  /**
  * Add a datum to the data set.
  * @param value The data value.
  */
  void Add(const T &value) {
    sum_ += value;
    ++size_;
    if (size_ == 1) {
      min_ = value;
      max_ = value;
    } else {
      if (value < min_)
        min_ = value;
      if (value > max_)
        max_ = value;
    }
  }
  /**
  * Get the size of the data set.
  * @return number of elements
  */
  boost::uint64_t Size() const { return size_; }
  /**
  * Get the smallest value in the set.
  * @return minimum
  */
  T Min() const { return min_; }
  /**
  * Get the biggest value in the set.
  * @return maximum
  */
  T Max() const { return max_; }
  /**
  * Get the sum of values in the set.
  * @return sum
  */
  T Sum() const { return sum_; }
  /**
  * Get the average of values in the set.
  * @return arithmetic mean
  */
  T Mean() const { return size_ > 0 ? sum_ / size_ : 0; }
 private:
  boost::uint64_t size_;
  T min_;
  T max_;
  T sum_;
};

// Generate a cryptographically-secure 32bit signed integer
boost::int32_t SRandomInt32();

// Generate a non-cryptographically-secure 32bit signed integer
boost::int32_t RandomInt32();

// Generate a cryptographically-secure 32bit unsigned integer
boost::uint32_t SRandomUint32();

// Generate a non-cryptographically-secure 32bit unsigned integer
boost::uint32_t RandomUint32();

// Generate a cryptographically-secure random string.
std::string SRandomString(const size_t &length);

// Generate a non-cryptographically-secure random string.
std::string RandomString(const size_t &length);

// Generate a non-cryptographically-secure random string containing only
// alphanumeric characters.
std::string RandomAlphaNumericString(const size_t &length);

// Convert from int to string.
std::string IntToString(const int &value);

// Encode a string to hex.
std::string EncodeToHex(const std::string &non_hex_input);

// Encode a string to Base64.
std::string EncodeToBase64(const std::string &non_base64_input);

// Encode a string to Base32.
std::string EncodeToBase32(const std::string &non_base32_input);

// Decode a string from hex.
std::string DecodeFromHex(const std::string &hex_input);

// Decode a string from Base64.
std::string DecodeFromBase64(const std::string &base64_input);

// Decode a string from Base32.
std::string DecodeFromBase32(const std::string &base32_input);

// Return the duration since kMaidsafeEpoch (1st January 2000).
boost::posix_time::time_duration GetDurationSinceEpoch();

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_UTILS_H_
