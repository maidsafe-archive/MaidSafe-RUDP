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

#ifndef MAIDSAFE_DHT_KADEMLIA_DATASTORE_H_
#define MAIDSAFE_DHT_KADEMLIA_DATASTORE_H_

#include <string>
#include <vector>
#include <utility>
#include "boost/date_time/posix_time/posix_time_types.hpp"
#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/mem_fun.hpp"
#include "boost/multi_index/composite_key.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

namespace test {
  class DataStoreTest;
  class ServicesTest;
  class RpcsTest;
}

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

typedef std::pair<std::string, std::string> RequestAndSignature;

struct KeyValueTuple {
  KeyValueTuple(const KeyValueSignature &key_value_signature,
                const bptime::ptime &expire_time,
                const bptime::ptime &refresh_time,
                const RequestAndSignature &request_and_signature,
                bool deleted);
  const std::string &key() const;
  const std::string &value() const;
  void set_refresh_time(const bptime::ptime &new_refresh_time);
  void UpdateStatus(const bptime::ptime &new_expire_time,
                    const bptime::ptime &new_refresh_time,
                    const bptime::ptime &new_confirm_time,
                    const RequestAndSignature &new_request_and_signature,
                    bool new_deleted);
  KeyValueSignature key_value_signature;
  bptime::ptime expire_time, refresh_time, confirm_time;
  RequestAndSignature request_and_signature;
  bool deleted;
};

struct TagKey {};
struct TagKeyValue {};
struct TagExpireTime {};
struct TagRefreshTime {};
struct TagConfirmTime {};

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
      boost::multi_index::tag<TagExpireTime>,
      BOOST_MULTI_INDEX_MEMBER(KeyValueTuple, bptime::ptime, expire_time)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagRefreshTime>,
      BOOST_MULTI_INDEX_MEMBER(KeyValueTuple, bptime::ptime, refresh_time)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagConfirmTime>,
      BOOST_MULTI_INDEX_MEMBER(KeyValueTuple, bptime::ptime, confirm_time)
    >
  >
> KeyValueIndex;

// The time during which an amendment is marked as not confirmed.
const bptime::hours kPendingConfirmDuration(2);


// This class implements physical storage (for data published and fetched via
// the RPCs) for the Kademlia DHT.
// Generally, when a key,value entry is modified, the confirm time for that
// entry is set, and while the confirm time > now, further modifications
// to that key,value can only be made by the holder(s) of the private key used
// to sign the original store request.
class DataStore {
 public:
  explicit DataStore(const bptime::seconds &mean_refresh_interval);
  // Returns whether the key exists in the datastore or not.  This returns true
  // even if the value(s) are marked as deleted.
  bool HasKey(const std::string &key);
  // Stores the key, value, signature and marks the expire time as ttl from
  // time of insertion.  Infinite ttl is indicated by bptime::pos_infin.
  // If the key doesn't already exist, the k,v,s is added and the method returns
  // kSuccess.
  // If the key already exists, but the value doesn't, the k,v,s is added iff
  // the signer of this attempt is the same as that of the previously stored
  // value(s) under that key.  Method returns kSuccess if the value was added.
  // If the key and value already exists, is not marked as deleted, and
  // is_refresh is true, the method resets the value's refresh time only (ttl is
  // ignored) and returns kSuccess.
  // If the key and value already exists, is not marked as deleted, and
  // is_refresh is false, the method resets the value's refresh time and ttl and
  // returns kSuccess.
  // If the key and value already exists, is marked as deleted, and is_refresh
  // is true, the method doesn't modify anything and returns kMarkedForDeletion.
  // If the key and value already exists, is marked as deleted, and is_refresh
  // is false, the method sets deleted to false, resets the confirm time and
  // returns kSuccess.
  int StoreValue(const KeyValueSignature &key_value_signature,
                 const bptime::time_duration &ttl,
                 const RequestAndSignature &store_request_and_signature,
                 const std::string &public_key,
                 bool is_refresh);
  // Marks the key, value, signature as deleted.
  // If the key and value doesn't already exist, the method returns true.
  // If the key and value already exists and is marked as deleted, the method
  // resets the value's refresh time only and returns true.
  // If the key and value already exists, is not marked as deleted, confirm time
  // has not expired and is_refresh is true, the method doesn't modify anything
  // and returns false.
  // If the key and value already exists, is not marked as deleted, and
  // is_refresh is false or confirm time has expired, the method sets deleted to
  // true, resets the confirm time and returns true.
  bool DeleteValue(const KeyValueSignature &key_value_signature,
                   const RequestAndSignature &delete_request_and_signature,
                   bool is_refresh);
  // If any values exist under key and are not marked as deleted, they are added
  // along with the signatures to the vector of pairs and the method returns
  // true.
  bool GetValues(const std::string &key,
                 std::vector<std::pair<std::string, std::string>> *values);
  // Refreshes datastore.  Values which have expired confirm times and which are
  // marked as deleted are removed from the datastore.  Values with expired
  // expire times are marked as deleted.  All values with expired refresh times
  // (whether marked as deleted or not) are returned.
  void Refresh(std::vector<KeyValueTuple> *key_value_tuples);
  bptime::seconds refresh_interval() const;
  void set_debug_name(const std::string &debug_name) {
    debug_name_ = debug_name;
  }
  friend class test::DataStoreTest;
  friend class test::ServicesTest;
  friend class test::RpcsTest;
 private:
  typedef boost::shared_lock<boost::shared_mutex> SharedLock;
  typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
  typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
  typedef boost::upgrade_to_unique_lock<boost::shared_mutex>
      UpgradeToUniqueLock;
  std::shared_ptr<KeyValueIndex> key_value_index_;
  const bptime::seconds refresh_interval_;
  boost::shared_mutex shared_mutex_;
  std::string debug_name_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_DATASTORE_H_
