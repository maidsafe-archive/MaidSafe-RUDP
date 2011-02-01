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

#include "maidsafe-dht/kademlia/datastore.h"
#include <exception>
#include "maidsafe-dht/common/utils.h"

namespace bptime = boost::posix_time;

namespace maidsafe {

namespace kademlia {

KeyValueTuple::KeyValueTuple(const KeyValueSignature &key_value_signature,
                             const bptime::ptime &expire_time,
                             const bptime::ptime &refresh_time,
                             const bool &hashable,
                             const std::string &serialised_delete_request,
                             DeleteStatus delete_status)
    : key_value_signature(key_value_signature),
      expire_time(expire_time),
      refresh_time(refresh_time),
      hashable(hashable),
      serialised_delete_request(serialised_delete_request),
      delete_status(delete_status) {}

KeyValueTuple::KeyValueTuple(const KeyValueSignature &key_value_signature,
                             const bptime::ptime &expire_time,
                             const bptime::ptime &refresh_time,
                             const bool &hashable)
    : key_value_signature(key_value_signature),
      expire_time(expire_time),
      refresh_time(refresh_time),
      hashable(hashable),
      serialised_delete_request(),
      delete_status(kNotDeleted) {}

const std::string &KeyValueTuple::key() const {
  return key_value_signature.key;
}

const std::string &KeyValueTuple::value() const {
  return key_value_signature.value;
}

void KeyValueTuple::UpdateKeyValueSignature(
    const KeyValueSignature &new_key_value_signature,
    const bptime::ptime &new_expire_time,
    const bptime::ptime &new_refresh_time) {
  key_value_signature = new_key_value_signature;
  expire_time = new_expire_time;
  refresh_time = new_refresh_time;
}

void KeyValueTuple::set_refresh_time(const bptime::ptime &new_refresh_time) {
  refresh_time = new_refresh_time;
}

void KeyValueTuple::UpdateDeleteStatus(
    const DeleteStatus &new_delete_status,
    const bptime::ptime &new_refresh_time,
    const std::string &serialised_delete_request) {
  delete_status = new_delete_status;
  refresh_time = new_refresh_time;
}


DataStore::DataStore(const bptime::seconds &mean_refresh_interval)
    : key_value_index_(),
      refresh_interval_(mean_refresh_interval.total_seconds() +
                        (RandomInt32() % 30)),
      shared_mutex_() {}

DataStore::~DataStore() {
  UniqueLock unique_lock(shared_mutex_);
  key_value_index_.clear();
}

/*bool DataStore::GetKeys(boost::shared_ptr<std::set<std::string>> keys) {
  keys->clear();
  std::pair<KeyValueIndex::iterator,bool> p;
  boost::mutex::scoped_lock guard(mutex_);
  for (KeyValueIndex::iterator it = key_value_index_.begin();
       it != key_value_index_.end(); ++it) {
    p = keys->insert((*it).key);
   // if (!p.second)
   //   return p.second ;
  }
  return true;
}*/

bool DataStore::HasKey(const std::string &key) {
  if (key.empty())
    return false;

  SharedLock shared_lock(shared_mutex_);
  auto p = key_value_index_.equal_range(key);

  if (p.first == p.second)
    return false;

  bptime::ptime now = bptime::microsec_clock::universal_time();
  while (p.first != p.second) {
    if ((p.first->expire_time > now) && (p.first->delete_status == kNotDeleted))
      return true;
    ++p.first;
  }
  return false;
}

bool DataStore::StoreValue(const KeyValueSignature &key_value_signature,
                           const bptime::time_duration &ttl,
                           const bool &hashable) {
  if (key_value_signature.key.empty() || key_value_signature.value.empty() ||
      key_value_signature.signature.empty() || ttl == bptime::seconds(0))
    return false;

  bptime::ptime now(bptime::microsec_clock::universal_time());
  KeyValueTuple tuple(key_value_signature, now + ttl, now + refresh_interval_,
                      hashable);
  UniqueLock unique_lock(shared_mutex_);
  auto p = key_value_index_.insert(tuple);

  if (!p.second) {
    if ((p.first->delete_status == kNotDeleted) ||
        (p.first->expire_time < tuple.expire_time)) {
      key_value_index_.replace(p.first, tuple);
    } else {
      return false;
    }
  }
  return true;
}

bool DataStore::GetValues(
    const std::string &key,
    std::vector<std::pair<std::string, std::string>> *values) {
  values->clear();
  SharedLock shared_lock(shared_mutex_);
  auto p = key_value_index_.equal_range(key);
  if (p.first == p.second)
    return false;

  bptime::ptime now = bptime::microsec_clock::universal_time();
  while (p.first != p.second) {
    if ((p.first->expire_time > now) && (p.first->delete_status == kNotDeleted))
      values->push_back(std::make_pair(p.first->key_value_signature.value,
                                       p.first->key_value_signature.signature));
    ++p.first;
  }
  return (!values->empty());
}

bool DataStore::DeleteValue(const std::string &key, const std::string &value) {
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_.get<TagKeyValue>();
  UpgradeLock upgrade_lock(shared_mutex_);
  auto it = index_by_key_value.find(boost::make_tuple(key, value));

  if (it == index_by_key_value.end())
    return false;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  index_by_key_value.erase(it);
  return true;
}

/*
bool DataStore::DeleteKey(const std::string &key) {
  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, KeyValueIndex::iterator> p =
      key_value_index_.equal_range(boost::make_tuple(key));
  if (p.first == p.second)
    return false;
  key_value_index_.erase(p.first, p.second);
  return true;
}

void DataStore::DeleteExpiredValues() { 
  KeyValueIndex::index<TagExpireTime>::type::iterator up_limit,
    down_limit, it;
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::index<TagExpireTime>::type& indx =
      key_value_index_.get<TagExpireTime>();
  boost::uint32_t now = GetEpochTime();
  up_limit = indx.lower_bound(now);
  down_limit = indx.upper_bound(0);
  indx.erase(down_limit, up_limit);
}

boost::uint32_t DataStore::LastRefreshTime(const std::string &key,
                                           const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return (*it).last_refresh_time;
}

boost::uint32_t DataStore::ExpireTime(const std::string &key,
                                      const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return (*it).expire_time;
}

std::vector<RefreshValue> DataStore::ValuesToRefresh() { 
  std::vector<RefreshValue> values;
  KeyValueIndex::index<TagLastRefreshTime>::type::iterator it,
    up_limit;
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::index<TagLastRefreshTime>::type& indx =
      key_value_index_.get<TagLastRefreshTime>();
  boost::uint32_t now = GetEpochTime();
  boost::uint32_t time_limit = now - refresh_time_;
  up_limit = indx.upper_bound(time_limit);
  for (it = indx.begin(); it != up_limit; ++it) {
    if ((*it).ttl == -1 && (*it).delete_status == kNotDeleted) {
      values.push_back(RefreshKeyValue((*it).key, (*it).value, (*it).ttl));
    } else {
      boost::int32_t ttl_remaining = (*it).expire_time - now;
      if (ttl_remaining > 0 && (*it).delete_status == kNotDeleted)
        values.push_back(RefreshValue((*it).key, (*it).value, ttl_remaining));
      else if ((*it).delete_status != kNotDeleted)
        values.push_back(RefreshValue((*it).key, (*it).value,
                                      (*it).delete_status));
    }
  }
  return values;
}

boost::int32_t DataStore::TimeToLive(const std::string &key,
                                     const std::string &value) { 
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return (*it).ttl;
}

void DataStore::Clear() {  // Not used
  boost::mutex::scoped_lock guard(mutex_);
  key_value_index_.clear();
}
*/

std::vector<std::pair<std::string, bool>> DataStore::LoadKeyAppendableAttr(
    const std::string &key) {
  std::vector<std::pair<std::string, bool>> result;
  SharedLock shared_lock(shared_mutex_);
  auto p = key_value_index_.equal_range(key);

  while (p.first != p.second) {
    result.push_back(std::make_pair(p.first->key_value_signature.value,
                                    p.first->hashable));
    ++p.first;
  }
  return result;
}

bool DataStore::RefreshKeyValue(const KeyValueSignature &key_value_signature,
                                std::string *serialised_delete_request) {
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_.get<TagKeyValue>();
  UpgradeLock upgrade_lock(shared_mutex_);
  auto it = index_by_key_value.find(boost::make_tuple(
      key_value_signature.key, key_value_signature.value));
  if ((it == index_by_key_value.end()) ||
      ((*it).key_value_signature.signature != key_value_signature.signature))
    return false;

  if ((*it).delete_status != kNotDeleted) {
    serialised_delete_request->clear();
    *serialised_delete_request = (*it).serialised_delete_request;
    return false;
  }

  bptime::ptime now(bptime::microsec_clock::universal_time());
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  return index_by_key_value.modify(it,
      boost::bind(&KeyValueTuple::set_refresh_time, _1,
                  now + refresh_interval_));
}

bool DataStore::MarkForDeletion(const KeyValueSignature &key_value_signature,
                                const std::string &serialised_delete_request) {
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_.get<TagKeyValue>();
  UpgradeLock upgrade_lock(shared_mutex_);
  auto it = index_by_key_value.find(boost::make_tuple(
      key_value_signature.key, key_value_signature.value));
  if (it == index_by_key_value.end())
    return false;
  // Check if already deleted or marked as deleted
  if ((*it).delete_status != kNotDeleted)
    return true;

  bptime::ptime now(bptime::microsec_clock::universal_time());
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  return index_by_key_value.modify(it,
      boost::bind(&KeyValueTuple::UpdateDeleteStatus, _1, kMarkedForDeletion,
                  now + refresh_interval_, serialised_delete_request));
}

/*
bool DataStore::MarkAsDeleted(const std::string &key,
                              const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end() || (*it).delete_status != kMarkedForDeletion)
    return false;
  KeyValueTuple tuple(key, value, 0);
  tuple.ttl = (*it).ttl;
  tuple.expire_time = (*it).expire_time;
  tuple.hashable = (*it).hashable;
  tuple.last_refresh_time = (*it).last_refresh_time;
  tuple.serialised_delete_request = (*it).serialised_delete_request;
  tuple.delete_status = kDeleted;

  return key_value_index_.replace(it, tuple);
} */

bool DataStore::UpdateValue(const KeyValueSignature &old_key_value_signature,
                            const KeyValueSignature &new_key_value_signature,
                            const bptime::time_duration &ttl,
                            const bool &hashable) {
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_.get<TagKeyValue>();
  UpgradeLock upgrade_lock(shared_mutex_);
  if (new_key_value_signature.value.empty()||
      new_key_value_signature.signature.empty()||
      (old_key_value_signature.key != new_key_value_signature.key))
    return false;
  auto it = index_by_key_value.find(boost::make_tuple(
      old_key_value_signature.key, old_key_value_signature.value));
  if (it == index_by_key_value.end() ||
      (*it).delete_status == kMarkedForDeletion ||
      (*it).delete_status == kDeleted)
    return false;

  bptime::ptime now(bptime::microsec_clock::universal_time());
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  // ignoring the return value of modify to return true for cases updating
  // existing values
  index_by_key_value.modify(it,
      boost::bind(&KeyValueTuple::UpdateKeyValueSignature, _1,
                  new_key_value_signature, now + ttl, now + refresh_interval_));
  
  return true;
}

bptime::seconds DataStore::refresh_interval() const {
  return refresh_interval_;
}

}  // namespace kademlia

}  // namespace maidsafe
