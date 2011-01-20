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

#ifndef MAIDSAFE_KADEMLIA_DATASTORE_H_
#define MAIDSAFE_KADEMLIA_DATASTORE_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/mem_fun.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <string>
#include <vector>
#include <set>
#include <utility>

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace kademlia {
// This class implements physical storage (for data published and fetched via
// the RPCs) for the Kademlia DHT.

enum DeleteStatus {
  kNotDeleted,
  kMarkedForDeletion,
  kDeleted
};

struct KeyValueSignature {
  KeyValueSignature(const std::string &key,
                    const std::string &value,
                    const std::string &signature)
      : key(key),
        value(value),
        signature(signature) {}
  std::string key;
  std::string value;
  std::string signature;
};

struct RefreshValue {
  RefreshValue(const KeyValueSignature &key_value_signature,
               const bptime::seconds &ttl)
      : key_value_signature(key_value_signature),
        ttl(ttl),
        delete_status(kNotDeleted) {}
  RefreshValue(const KeyValueSignature &key_value_signature,
               const DeleteStatus &delete_status)
      : key_value_signature(key_value_signature),
        ttl(0),
        delete_status(delete_status) {}
  KeyValueSignature key_value_signature;
  bptime::seconds ttl;
  DeleteStatus delete_status;
};

struct KeyValueTuple {
  KeyValueTuple(const KeyValueSignature &key_value_signature,
                const bptime::ptime &last_refresh_time,
                const bptime::ptime &expire_time,
                const bptime::seconds &ttl,
                const bool &hashable)
      : key_value_signature(key_value_signature),
        serialized_delete_request(),
        last_refresh_time(last_refresh_time),
        expire_time(ttl.is_pos_infinity() ? bptime::pos_infin : expire_time),
        ttl(ttl),
        hashable(hashable),
        delete_status(kNotDeleted) {}
  KeyValueTuple(const KeyValueSignature &key_value_signature,
                const bptime::ptime &last_refresh_time)
      : key_value_signature(key_value_signature),
        serialized_delete_request(),
        last_refresh_time(last_refresh_time),
        expire_time(bptime::pos_infin),
        ttl(bptime::pos_infin),
        hashable(true),
        delete_status(kNotDeleted) {}
  const std::string &key() const {
    return key_value_signature.key;
  }
  const std::string &value() const {
    return key_value_signature.value;
  }
  KeyValueSignature key_value_signature;
  std::string serialized_delete_request;
  bptime::ptime last_refresh_time, expire_time;
  bptime::seconds ttl;
  bool hashable;
  DeleteStatus delete_status;
};

struct TagKey {};
struct TagKeyValue {};
struct TagLastRefreshTime {};
struct TagExpireTime {};

typedef boost::multi_index::multi_index_container<
  KeyValueTuple,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagKey>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(KeyValueTuple, const std::string&, key)
    >,
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<TagKeyValue>,
      boost::multi_index::composite_key<
        KeyValueTuple,
        BOOST_MULTI_INDEX_CONST_MEM_FUN(KeyValueTuple, const std::string&, key),
        BOOST_MULTI_INDEX_CONST_MEM_FUN(KeyValueTuple, const std::string&,
                                        value)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagLastRefreshTime>,
      BOOST_MULTI_INDEX_MEMBER(KeyValueTuple, bptime::ptime, last_refresh_time)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagExpireTime>,
      BOOST_MULTI_INDEX_MEMBER(KeyValueTuple, bptime::ptime, expire_time)
    >
  >
> KeyValueIndex;

class DataStore {
 public:
  explicit DataStore(const bptime::seconds &mean_refresh_interval);
  ~DataStore();
  bool HasKey(const std::string &key);
  // Infinite ttl is indicated by bptime::pos_infin.
  bool StoreValue(const KeyValueSignature &key_value_signature,
                  const bptime::seconds &ttl,
                  const bool &hashable);
  bool GetValues(const std::string &key,
                 std::vector<std::pair<std::string, std::string>> *values);
  bool DeleteValue(const std::string &key, const std::string &value);

  // These functions are commented only to make sure whether required or not
  /* bool DeleteKey(const std::string &key);
  void DeleteExpiredValues();
  boost::uint32_t LastRefreshTime(const std::string &key,
                                  const std::string &value);
  boost::uint32_t ExpireTime(const std::string &key, const std::string &value);
  std::vector<RefreshValue> ValuesToRefresh();
  boost::int32_t TimeToLive(const std::string &key, const std::string &value);
  void Clear(); */
  std::vector<std::pair<std::string, bool>> LoadKeyAppendableAttr(
      const std::string &key);

  bool RefreshKeyValue(const KeyValueSignature &key_value_signature,
                       std::string *serialized_delete_request);
  // If key, value pair does not exist, then it returns false
  bool MarkForDeletion(const KeyValueSignature &key_value_signature,
                       const std::string &serialized_delete_request);
  
  // If key, value pair does not exist or its status is not kMarkedForDeletion,
  // then it returns false
  // bool MarkAsDeleted(const std::string &key, const std::string &value);

  // Infinite ttl is indicated by bptime::pos_infin.
  bool UpdateValue(const KeyValueSignature &old_key_value_signature,
                   const KeyValueSignature &new_key_value_signature,
                   const bptime::seconds &ttl,
                   const bool &hashable);
  bptime::seconds refresh_interval() const;
 private:
  KeyValueIndex key_value_index_;
  const bptime::seconds refresh_interval_;
  boost::mutex mutex_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_KADEMLIA_DATASTORE_H_
