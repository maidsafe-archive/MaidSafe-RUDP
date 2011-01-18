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

#include "maidsafe/kademlia/datastore.h"
#include <exception>
#include "maidsafe/base/utils.h"


namespace kademlia {

DataStore::DataStore(const boost::uint32_t &refresh_time)
    : key_value_index_(), refresh_time_(0), mutex_() {
  refresh_time_ = refresh_time + (base::RandomUint32() % 5);
}

DataStore::~DataStore() {
  key_value_index_.clear();
}

bool DataStore::Keys(std::set<std::string> *keys) {
  keys->clear();
  boost::mutex::scoped_lock guard(mutex_);
  for (KeyValueIndex::iterator it = key_value_index_.begin();
       it != key_value_index_.end(); ++it)
    keys->insert(it->key);
  return true;
}

bool DataStore::HasItem(const std::string &key) {
  if (key.empty())
    return false;

  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, KeyValueIndex::iterator> p =
      key_value_index_.equal_range(boost::make_tuple(key));
  if (p.first == p.second)
    return false;

  boost::uint32_t now = base::GetEpochTime();
  while (p.first != p.second) {
    boost::int32_t ttl_remaining = p.first->expire_time - now;
    if ((ttl_remaining > 0 || p.first->ttl == -1) &&
        (p.first->delete_status == kNotDeleted))
      return true;
    ++p.first;
  }

  return false;
}

bool DataStore::StoreItem(const std::string &key, const std::string &value,
                          const boost::int32_t &ttl,
                          const bool &hashable) {
  if (key.empty() || value.empty() || ttl == 0)
    return false;

  boost::uint32_t time_stamp = base::GetEpochTime();
  KeyValueTuple tuple(key, value, time_stamp,
      ttl + time_stamp, ttl, hashable);
  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, bool> p = key_value_index_.insert(tuple);

  if (!p.second) {
    if ((p.first->delete_status == kNotDeleted) ||
        (tuple.ttl == -1) ||
        (p.first->expire_time < tuple.expire_time && p.first->ttl != -1)) {
      key_value_index_.replace(p.first, tuple);
    } else {
      return false;
    }
  }
  return true;
}

bool DataStore::LoadItem(const std::string &key,
                         std::vector<std::string> *values) {
  values->clear();
  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, KeyValueIndex::iterator> p =
      key_value_index_.equal_range(boost::make_tuple(key));
  if (p.first == p.second)
    return false;
  boost::uint32_t now = base::GetEpochTime();
  while (p.first != p.second) {
    boost::int32_t ttl_remaining = p.first->expire_time - now;
    if ((ttl_remaining > 0 || p.first->ttl == -1) &&
        (p.first->delete_status == kNotDeleted))
      values->push_back(p.first->value);
    ++p.first;
  }
  if (values->empty())
    return false;
  return true;
}

bool DataStore::DeleteItem(const std::string &key, const std::string &value) {
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  boost::mutex::scoped_lock guard(mutex_);
  if (it == key_value_index_.end())
    return false;
  key_value_index_.erase(it);
  return true;
}

bool DataStore::DeleteKey(const std::string &key) {
  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, KeyValueIndex::iterator> p =
      key_value_index_.equal_range(boost::make_tuple(key));
  if (p.first == p.second)
    return false;
  key_value_index_.erase(p.first, p.second);
  return true;
}

boost::uint32_t DataStore::LastRefreshTime(const std::string &key,
                                           const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return it->last_refresh_time;
}

boost::uint32_t DataStore::ExpireTime(const std::string &key,
                                      const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return it->expire_time;
}

std::vector<RefreshValue> DataStore::ValuesToRefresh() {
  std::vector<RefreshValue> values;
  KeyValueIndex::index<kademlia::TagLastRefreshTime>::type::iterator it,
    up_limit;
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::index<kademlia::TagLastRefreshTime>::type& indx =
      key_value_index_.get<kademlia::TagLastRefreshTime>();
  boost::uint32_t now = base::GetEpochTime();
  boost::uint32_t time_limit = now - refresh_time_;
  up_limit = indx.upper_bound(time_limit);
  for (it = indx.begin(); it != up_limit; ++it) {
    if (it->ttl == -1 && it->delete_status == kNotDeleted) {
      values.push_back(RefreshValue(it->key, it->value, it->ttl));
    } else {
      boost::int32_t ttl_remaining = it->expire_time - now;
      if (ttl_remaining > 0 && it->delete_status == kNotDeleted)
        values.push_back(RefreshValue(it->key, it->value, ttl_remaining));
      else if (it->delete_status != kNotDeleted)
        values.push_back(RefreshValue(it->key, it->value, it->delete_status));
    }
  }
  return values;
}

void DataStore::DeleteExpiredValues() {
  KeyValueIndex::index<kademlia::TagExpireTime>::type::iterator up_limit,
    down_limit, it;
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::index<kademlia::TagExpireTime>::type& indx =
      key_value_index_.get<kademlia::TagExpireTime>();
  boost::uint32_t now = base::GetEpochTime();
  up_limit = indx.lower_bound(now);
  down_limit = indx.upper_bound(0);
  indx.erase(down_limit, up_limit);
}

void DataStore::Clear() {
  boost::mutex::scoped_lock guard(mutex_);
  key_value_index_.clear();
}

boost::int32_t DataStore::TimeToLive(const std::string &key,
                                     const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return 0;
  return it->ttl;
}

boost::uint32_t DataStore::RefreshTime() const {
  return refresh_time_;
}

std::vector<std::pair<std::string, bool> > DataStore::LoadKeyAppendableAttr(
    const std::string &key) {
  std::vector< std::pair<std::string, bool> > result;
  boost::mutex::scoped_lock guard(mutex_);
  std::pair<KeyValueIndex::iterator, KeyValueIndex::iterator> p =
      key_value_index_.equal_range(boost::make_tuple(key));
  while (p.first != p.second) {
    result.push_back(std::pair<std::string, bool>(p.first->value,
        p.first->hashable));
    ++p.first;
  }
  return result;
}

bool DataStore::RefreshItem(const std::string &key,
                            const std::string &value,
                            std::string *stored_delete_request) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end()) {
    return false;
  }
  if (it->delete_status != kNotDeleted) {
    stored_delete_request->clear();
    *stored_delete_request = it->serialized_delete_request;
    return false;
  }
  boost::uint32_t time_stamp = base::GetEpochTime();
  KeyValueTuple tuple(key, value, time_stamp);
  tuple.ttl = it->ttl;
  tuple.expire_time = it->expire_time;
  tuple.hashable = it->hashable;

  return key_value_index_.replace(it, tuple);
}

bool DataStore::MarkForDeletion(const std::string &key,
                                const std::string &value,
                                const std::string &serialized_delete_request) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end())
    return false;
  // Check if already deleted or marked as deleted
  if (it->delete_status != kNotDeleted)
    return true;
  KeyValueTuple tuple(key, value, 0);
  tuple.ttl = it->ttl;
  tuple.expire_time = it->expire_time;
  tuple.hashable = it->hashable;
  tuple.last_refresh_time = it->last_refresh_time;
  tuple.serialized_delete_request = serialized_delete_request;
  tuple.delete_status = kMarkedForDeletion;

  return key_value_index_.replace(it, tuple);
}

bool DataStore::MarkAsDeleted(const std::string &key,
                              const std::string &value) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(key,
                                                                       value));
  if (it == key_value_index_.end() || it->delete_status != kMarkedForDeletion)
    return false;
  KeyValueTuple tuple(key, value, 0);
  tuple.ttl = it->ttl;
  tuple.expire_time = it->expire_time;
  tuple.hashable = it->hashable;
  tuple.last_refresh_time = it->last_refresh_time;
  tuple.serialized_delete_request = it->serialized_delete_request;
  tuple.delete_status = kDeleted;

  return key_value_index_.replace(it, tuple);
}

bool DataStore::UpdateItem(const std::string &key,
                           const std::string &old_value,
                           const std::string &new_value,
                           const boost::int32_t &ttl,
                           const bool &hashable) {
  boost::mutex::scoped_lock guard(mutex_);
  KeyValueIndex::iterator it = key_value_index_.find(boost::make_tuple(
      key, old_value));
  if (it == key_value_index_.end() || it->delete_status == kMarkedForDeletion ||
      it->delete_status == kDeleted)
    return false;

  KeyValueTuple tuple(key, new_value, 0);
  boost::uint32_t now(base::GetEpochTime());
  tuple.ttl = ttl;
  tuple.expire_time = now + ttl;
  tuple.last_refresh_time = now;
  tuple.delete_status = kNotDeleted;
  tuple.hashable = hashable;
  return key_value_index_.replace(it, tuple);
}

}  // namespace kademlia
