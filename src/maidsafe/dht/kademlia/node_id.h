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

#ifndef MAIDSAFE_DHT_KADEMLIA_NODE_ID_H_
#define MAIDSAFE_DHT_KADEMLIA_NODE_ID_H_

#include <cstdint>
#include <string>
#include <vector>
#include "boost/serialization/nvp.hpp"
#include "maidsafe/common/platform_config.h"
#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace maidsafe {

namespace dht {

namespace kademlia {

/**
* The size of DHT keys and node IDs in bits.
**/
const uint16_t kKeySizeBits = 8 * kKeySizeBytes;

const std::string kZeroId(kKeySizeBytes, 0);

size_t BitToByteCount(const size_t &bit_count);

/**
* @class NodeId
* Class used to contain a valid kademlia id in the range [0, 2 ^ kKeySizeBits)
*/

class NodeId {
 public:
  enum KadIdType { kMaxId, kRandomId };
  enum EncodingType { kBinary, kHex, kBase32, kBase64 };
  /**
  * Default Constructor.  Creates an id equal to 0.
  **/
  NodeId();

  /**
  * Copy contructor.
  * @param rhs a NodeId object.
  */
  NodeId(const NodeId &other);

  /**
  * Constructor.  Creates an id = (2 ^ kKeySizeBits) - 1 or a random id in the
  * interval [0, 2 ^ kKeySizeBits).
  * @param type Type of id to be created (kMaxId or kRandomId).
  */
  explicit NodeId(const KadIdType &type);

  /**
  * Constructor.  Creates a NodeId from a raw (decoded) string.
  * @param id string representing the decoded kademlia id.
  */
  explicit NodeId(const std::string &id);

  /**
  * Constructor.  Creates a NodeId from an encoded string.
  * @param id string representing the kademlia id.
  * @param encoding_type Type of encoding to use.
  */
  NodeId(const std::string &id, const EncodingType &encoding_type);

  /**
  * Constructor.  Creates a NodeId equal to 2 ^ power.
  * @param power < kKeySizeBytes.
  */
  explicit NodeId(const uint16_t &power);

  /**
  * Constructor.  Creates a random NodeId in range [lower ID, higher ID]
  * Prefer to pass lower ID as id1.
  * @param id1 ID upper or lower limit.
  * @param id2 ID upper or lower limit.
  */
  NodeId(const NodeId &id1, const NodeId &id2);

  /**
  * Checks if id1 is closer in XOR distance to target_id than id2.
  * @param id1 NodeId object.
  * @param id2 NodeId object.
  * @param target_id NodeId object to which id1 and id2 distance is computed to
  * be compared.
  * @return True if id1 is closer to target_id than id2, otherwise false.
  */
  static bool CloserToTarget(const NodeId &id1,
                             const NodeId &id2,
                             const NodeId &target_id);

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

  bool operator == (const NodeId &rhs) const;
  bool operator != (const NodeId &rhs) const;
  bool operator < (const NodeId &rhs) const;
  bool operator > (const NodeId &rhs) const;
  bool operator <= (const NodeId &rhs) const;
  bool operator >= (const NodeId &rhs) const;
  NodeId& operator = (const NodeId &rhs);

  /**
  * XOR distance between two kademlia IDs.  XOR bit to bit.
  * @param rhs NodeId to which this is XOR
  * @return a NodeId object that is equal to this XOR rhs
  */
  const NodeId operator ^ (const NodeId &rhs) const;

 private:
  std::string EncodeToBinary() const;
  void DecodeFromBinary(const std::string &binary_id);
  std::string raw_id_;
};

/** Returns an abbreviated hex representation of node_id */
std::string DebugId(const NodeId &node_id);

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe



namespace mk = maidsafe::dht::kademlia;

namespace boost {

namespace serialization {

#ifdef __MSVC__
#  pragma warning(disable: 4127)
#endif
template <typename Archive>
void serialize(Archive &archive,                              // NOLINT (Fraser)
               mk::NodeId &node_id,
               const unsigned int& /*version*/) {
  std::string node_id_local;
  if (Archive::is_saving::value) {
    node_id_local = (node_id.ToStringEncoded(mk::NodeId::kBase64));
  }
  archive& boost::serialization::make_nvp("node_id", node_id_local);
  if (Archive::is_loading::value) {
    node_id = mk::NodeId(node_id_local, mk::NodeId::kBase64);
  }
#ifdef __MSVC__
#  pragma warning(default: 4127)
#endif
}

}  // namespace serialization

}  // namespace boost

#endif  // MAIDSAFE_DHT_KADEMLIA_NODE_ID_H_
