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

#ifndef MAIDSAFE_KADEMLIA_KADID_H_
#define MAIDSAFE_KADEMLIA_KADID_H_

#include <boost/cstdint.hpp>
#include <maidsafe/maidsafe-dht_config.h>
#include <string>
#include <vector>

namespace kad {

/**
* The size of DHT keys and node IDs in bits.
**/
const boost::uint16_t kKeySizeBits = 8 * kKeySizeBytes;

const std::string kZeroId(kKeySizeBytes, 0);
const std::string kClientId(kZeroId);

size_t BitToByteCount(const size_t &bit_count);

/**
* @class KadId
* Class used to contain a valid kademlia id in the range [0, 2 ^ kKeySizeBits)
*/

class KadId {
 public:
  enum KadIdType { kMaxId, kRandomId };
  enum EncodingType { kBinary, kHex, kBase32, kBase64 };
  /**
  * Default Constructor.  Creates an id equal to 0.
  **/
  KadId();

  /**
  * Copy contructor.
  * @param rhs a KadId object.
  */
  KadId(const KadId &other);

  /**
  * Constructor.  Creates an id = (2 ^ kKeySizeBits) - 1 or a random id in the
  * interval [0, 2 ^ kKeySizeBits).
  * @param type Type of id to be created (kMaxId or kRandomId).
  */
  explicit KadId(const KadIdType &type);

  /**
  * Constructor.  Creates a KadId from a raw (decoded) string.
  * @param id string representing the decoded kademlia id.
  */
  explicit KadId(const std::string &id);

  /**
  * Constructor.  Creates a KadId from an encoded string.
  * @param id string representing the kademlia id.
  * @param encoding_type Type of encoding to use.
  */
  KadId(const std::string &id, const EncodingType &encoding_type);

  /**
  * Constructor.  Creates a KadId equal to 2 ^ power.
  * @param power < kKeySizeBytes.
  */
  explicit KadId(const boost::uint16_t &power);

  /**
  * Constructor.  Creates a random KadId in range [lower ID, higher ID]
  * Prefer to pass lower ID as id1.
  * @param id1 ID upper or lower limit.
  * @param id2 ID upper or lower limit.
  */
  KadId(const KadId &id1, const KadId &id2);

  /**
  * Splits a range [min_id, max_id] to [min_id, max_id1] and [min_id1, max_id]
  * it is assumed that min_id = 2 ^ n or 0 and max_id = 2 ^ m - 1 and 
  * min_id < max_id.
  * min_id1 = ((max_id + min_id) / 2) + 1 and max_id1 = (max_id + min_id) / 2.
  * @param min_id lower limit of original interval.
  * @param max_id upper limit of original interval.
  * @param min_id1 lower limit of new higher interval.
  * @param max_id upper limit of new lower interval.
  */
  static void SplitRange(const KadId &min_id, const KadId &max_id,
                         KadId *max_id1, KadId *min_id1);

  /**
  * Checks if id1 is closer in XOR distance to target_id than id2.
  * @param id1 KadId object.
  * @param id2 KadId object.
  * @param target_id KadId object to which id1 and id2 distance is computed to
  * be compared.
  * @return True if id1 is closer to target_id than id2, otherwise false.
  */
  static bool CloserToTarget(const KadId &id1, const KadId &id2,
                             const KadId &target_id);

  /** Decoded representation of the kademlia id.
  * @return A decoded string representation of the kademlia id.
  */
  const std::string String() const;

  /** Encoded representation of the kademlia id.
  * @param encoding_type Type of encoding to use.
  * @return An encoded string representation of the kademlia id.
  */
  const std::string ToStringEncoded(const EncodingType &encoding_type) const;

  /**
  * Checks that raw_id_ has size kKeySizeBytes.
  */
  bool IsValid() const;

  bool operator == (const KadId &rhs) const;
  bool operator != (const KadId &rhs) const;
  bool operator < (const KadId &rhs) const;
  bool operator > (const KadId &rhs) const;
  bool operator <= (const KadId &rhs) const;
  bool operator >= (const KadId &rhs) const;
  KadId& operator = (const KadId &rhs);

  /**
  * XOR distance between two kademlia IDs.  XOR bit to bit.
  * @param rhs KadId to which this is XOR
  * @return a KadId object that is equal to this XOR rhs
  */
  const KadId operator ^ (const KadId &rhs) const;
 private:
  std::string EncodeToBinary() const;
  void DecodeFromBinary(const std::string &binary_id);
  std::string raw_id_;
};

}  // namespace kad

#endif  // MAIDSAFE_KADEMLIA_KADID_H_
