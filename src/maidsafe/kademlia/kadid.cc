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

#include "maidsafe/kademlia/kadid.h"
#include <bitset>
#include "maidsafe/base/log.h"
#include "maidsafe/base/utils.h"


namespace kad {

size_t BitToByteCount(const size_t &bit_count) {
  return static_cast<size_t>(0.999999 + static_cast<double>(bit_count) / 8);
}

KadId::KadId() : raw_id_(kZeroId) {}

KadId::KadId(const KadId &other) : raw_id_(other.raw_id_) {}

KadId::KadId(const KadIdType &type) : raw_id_(kKeySizeBytes, -1) {
  switch (type) {
    case kMaxId :
      break;  // already set
    case kRandomId :
      for (std::string::iterator it = raw_id_.begin(); it != raw_id_.end();
           ++it) {
        (*it) = base::RandomUint32();
      }
      break;
    default :
      break;
  }
}

KadId::KadId(const std::string &id) : raw_id_(id) {}

KadId::KadId(const std::string &id, const EncodingType &encoding_type)
    : raw_id_() {
  try {
    switch (encoding_type) {
      case kBinary : DecodeFromBinary(id);
        break;
      case kHex : raw_id_ = base::DecodeFromHex(id);
        break;
      case kBase32 : raw_id_ = base::DecodeFromBase32(id);
        break;
      case kBase64 : raw_id_ = base::DecodeFromBase64(id);
        break;
      default : raw_id_ = id;
    }
  }
  catch(const std::exception &e) {
    LOG(ERROR) << "KadId Ctor: " << e.what();
    raw_id_.clear();
    return;
  }
  if (!IsValid())
    raw_id_.clear();
}

KadId::KadId(const boost::uint16_t &power) : raw_id_(kZeroId) {
  if (power >= kKeySizeBits) {
    raw_id_.clear();
    return;
  }
  boost::uint16_t shift = power % 8;
  if (shift != 0) {
    raw_id_[kKeySizeBytes - BitToByteCount(power)] += 1 << shift;
  } else {
    raw_id_[kKeySizeBytes - BitToByteCount(power) - 1] = 1;
  }
}

KadId::KadId(const KadId &id1, const KadId &id2) : raw_id_(kZeroId) {
  if (!id1.IsValid() || !id2.IsValid()) {
    raw_id_.clear();
    return;
  }
  if (id1 == id2) {
    raw_id_ = id1.raw_id_;
    return;
  }
  std::string min_id(id1.raw_id_), max_id(id2.raw_id_);
  if (id1 > id2) {
    max_id = id1.raw_id_;
    min_id = id2.raw_id_;
  }
  bool less_than_upper_limit(false);
  bool greater_than_lower_limit(false);
  unsigned char max_id_char(0), min_id_char(0), this_char(0);
  for (size_t pos = 0; pos < kKeySizeBytes; ++pos) {
    if (!less_than_upper_limit) {
      max_id_char = max_id[pos];
      min_id_char = greater_than_lower_limit ? 0 : min_id[pos];
      if (max_id_char == 0) {
        raw_id_[pos] = 0;
      } else {
        raw_id_[pos] = (base::RandomUint32() % (max_id_char - min_id_char + 1))
                       + min_id_char;
        this_char = raw_id_[pos];
        less_than_upper_limit = (this_char < max_id_char);
        greater_than_lower_limit = (this_char > min_id_char);
      }
    } else if (!greater_than_lower_limit) {
      min_id_char = min_id[pos];
      raw_id_[pos] = (base::RandomUint32() % (256 - min_id_char)) + min_id_char;
      this_char = raw_id_[pos];
      greater_than_lower_limit = (this_char > min_id_char);
    } else {
      raw_id_[pos] = base::RandomUint32();
    }
  }
}

std::string KadId::EncodeToBinary() const {
  std::string binary;
  binary.reserve(kKeySizeBytes);
  for (size_t i = 0; i < kKeySizeBytes; ++i) {
    std::bitset<8> temp(static_cast<int>(raw_id_[i]));
    binary += temp.to_string();
  }
  return binary;
}

void KadId::DecodeFromBinary(const std::string &binary_id) {
  std::bitset<kKeySizeBits> binary_bitset(binary_id);
  if (!IsValid()) {
    raw_id_.assign(kKeySizeBytes, 0);
  }
  for (size_t i = 0; i < kKeySizeBytes; ++i) {
    std::bitset<8> temp(binary_id.substr(i * 8, 8));
    raw_id_[i] = temp.to_ulong();
  }
}

void KadId::SplitRange(const KadId &min_id, const KadId &max_id,
                       KadId *max_id1, KadId *min_id1) {
  if (max_id1 == NULL || min_id1 == NULL)
    return;
  if (!min_id.IsValid() || !max_id.IsValid() ||
      !max_id1->IsValid() || !min_id1->IsValid() || min_id >= max_id) {
    KadId fail_id;
    fail_id.raw_id_.clear();
    *max_id1 = fail_id;
    *min_id1 = fail_id;
  }
  size_t first_diff_bit(0);
  for (; first_diff_bit < kKeySizeBytes; ++first_diff_bit) {
    if (min_id.raw_id_[first_diff_bit] != max_id.raw_id_[first_diff_bit])
     break;
  }
  std::string max1_raw_id(max_id.raw_id_), min1_raw_id(min_id.raw_id_);
  unsigned char max1_diff_char(max1_raw_id[first_diff_bit]);
  unsigned char min1_diff_char(min1_raw_id[first_diff_bit]);
  max1_raw_id[first_diff_bit] = (max1_diff_char + min1_diff_char) >> 1;
  max1_diff_char = max1_raw_id[first_diff_bit];
  min1_raw_id[first_diff_bit] = max1_diff_char + 1;
  *max_id1 = KadId(max1_raw_id);
  *min_id1 = KadId(min1_raw_id);
}

bool KadId::CloserToTarget(const KadId &id1, const KadId &id2,
                           const KadId &target_id) {
  if (!id1.IsValid() || !id2.IsValid() || !target_id.IsValid())
    return false;
  std::string raw_id1(id1.raw_id_);
  std::string raw_id2(id2.raw_id_);
  std::string raw_id_target(target_id.raw_id_);
  for (boost::uint16_t i = 0; i < kKeySizeBytes; ++i) {
    unsigned char result1 = raw_id1[i] ^ raw_id_target[i];
    unsigned char result2 = raw_id2[i] ^ raw_id_target[i];
    if (result1 != result2)
      return result1 < result2;
  }
  return false;
}

const std::string KadId::String() const {
  return raw_id_;
}

const std::string KadId::ToStringEncoded(
    const EncodingType &encoding_type) const {
  if (!IsValid())
    return "";
  switch (encoding_type) {
    case kBinary : return EncodeToBinary();
    case kHex : return base::EncodeToHex(raw_id_);
    case kBase32 : return base::EncodeToBase32(raw_id_);
    case kBase64 : return base::EncodeToBase64(raw_id_);
    default : return raw_id_;
  }
}

bool KadId::IsValid() const {
  return raw_id_.size() == kKeySizeBytes;
}

bool KadId::operator == (const KadId &rhs) const {
  return raw_id_ == rhs.raw_id_;
}

bool KadId::operator != (const KadId &rhs) const {
  return raw_id_ != rhs.raw_id_;
}

bool KadId::operator < (const KadId &rhs) const {
  return raw_id_ < rhs.raw_id_;
}

bool KadId::operator > (const KadId &rhs) const {
  return raw_id_ > rhs.raw_id_;
}

bool KadId::operator <= (const KadId &rhs) const {
  return raw_id_ <= rhs.raw_id_;
}

bool KadId::operator >= (const KadId &rhs) const {
  return raw_id_ >= rhs.raw_id_;
}

KadId& KadId::operator = (const KadId &rhs) {
  this->raw_id_ = rhs.raw_id_;
  return *this;
}

const KadId KadId::operator ^ (const KadId &rhs) const {
  KadId result;
  std::string::const_iterator this_it = raw_id_.begin();
  std::string::const_iterator rhs_it = rhs.raw_id_.begin();
  std::string::iterator result_it = result.raw_id_.begin();
  for (; this_it != raw_id_.end(); ++this_it, ++rhs_it, ++result_it)
    *result_it = *this_it ^ *rhs_it;
  return result;
}
}
