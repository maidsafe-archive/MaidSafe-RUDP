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

#include "maidsafe/dht/kademlia/data_store.h"
#include <algorithm>
#include "maidsafe/common/crypto.h"
#include "maidsafe/common/utils.h"
#include "maidsafe/dht/log.h"
#include "maidsafe/dht/kademlia/return_codes.h"
#include "maidsafe/dht/kademlia/securifier.h"

namespace arg = std::placeholders;
namespace bptime = boost::posix_time;

namespace maidsafe {

namespace dht {

namespace kademlia {

KeyValueTuple::KeyValueTuple(const KeyValueSignature &key_value_signature,
                             const bptime::ptime &expire_time,
                             const bptime::ptime &refresh_time,
                             const RequestAndSignature &request_and_signature,
                             bool deleted)
    : key_value_signature(key_value_signature),
      expire_time(expire_time),
      refresh_time(refresh_time),
      confirm_time(bptime::microsec_clock::universal_time() +
                   kPendingConfirmDuration),
      request_and_signature(request_and_signature),
      deleted(deleted) {}

const std::string &KeyValueTuple::key() const {
  return key_value_signature.key;
}

const std::string &KeyValueTuple::value() const {
  return key_value_signature.value;
}

void KeyValueTuple::set_refresh_time(const bptime::ptime &new_refresh_time) {
  refresh_time = new_refresh_time;
}

void KeyValueTuple::UpdateStatus(
    const bptime::ptime &new_expire_time,
    const bptime::ptime &new_refresh_time,
    const bptime::ptime &new_confirm_time,
    const RequestAndSignature &new_request_and_signature,
    bool new_deleted) {
  expire_time = new_expire_time;
  refresh_time = new_refresh_time;
  confirm_time = new_confirm_time;
  request_and_signature = new_request_and_signature;
  deleted = new_deleted;
}


DataStore::DataStore(const bptime::seconds &mean_refresh_interval)
    : key_value_index_(new KeyValueIndex),
      kRefreshInterval_(mean_refresh_interval.total_seconds() +
                        (RandomInt32() % 120)),
      shared_mutex_(),
      debug_id_("Uninitialised Debug ID") {}

bool DataStore::HasKey(const std::string &key) const {
  if (key.empty())
    return false;
  SharedLock shared_lock(shared_mutex_);
  auto itr(key_value_index_->get<TagKey>().find(key));
  DLOG(INFO) << debug_id_ << ": HasKey " << EncodeToHex(key).substr(0, 10)
             << ": " << std::boolalpha
             << (itr != key_value_index_->get<TagKey>().end());
  return (itr != key_value_index_->get<TagKey>().end());
}

int DataStore::StoreValue(
    const KeyValueSignature &key_value_signature,
    const bptime::time_duration &ttl,
    const RequestAndSignature &store_request_and_signature,
    bool is_refresh) {
  // Assumes that check on signature of request and signature of value using
  // the public key has already been done.  Also assumes that if the key
  // pre-exists, a check has been made to ensure that the same private key was
  // used to sign all pre-existing values under that key.
  if (key_value_signature.key.empty()) {
    DLOG(WARNING) << debug_id_ << ": Key empty.";
    return kEmptyKey;
  }
  if (ttl == bptime::seconds(0)) {
    DLOG(WARNING) << debug_id_ << ": Zero TTL.";
    return kZeroTTL;
  }

  bptime::ptime now(bptime::microsec_clock::universal_time());
  KeyValueTuple tuple(key_value_signature, now + ttl, now + kRefreshInterval_,
                      store_request_and_signature, false);

  // Try to insert key,value
  UniqueLock unique_lock(shared_mutex_);
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_->get<TagKeyValue>();
  auto insertion_result = index_by_key_value.insert(tuple);

  // If the insertion succeeded, we're done.  If not, the key,value pre-existed.
  if (insertion_result.second) {
    DLOG(INFO) << debug_id_ << ": Stored key "
               << EncodeToHex(key_value_signature.key).substr(0, 10);
    return kSuccess;
  }

  // Allow original signer to modify it.
  if (!is_refresh) {
    if (index_by_key_value.modify(insertion_result.first,
        std::bind(&KeyValueTuple::UpdateStatus, arg::_1, now + ttl,
                  now + kRefreshInterval_, now + kPendingConfirmDuration,
                  store_request_and_signature, false))) {
      DLOG(INFO) << debug_id_ << ": Successfully modified value for key "
                 << EncodeToHex(key_value_signature.key).substr(0, 10);
      return kSuccess;
    } else {
      DLOG(WARNING) << debug_id_ << ": Failed to modify value for key "
                    << EncodeToHex(key_value_signature.key).substr(0, 10);
      return kFailedToModifyKeyValue;
    }
  }

  // For refreshing, only the refresh time can be reset, and only for
  // non-deleted values.
  if ((*insertion_result.first).deleted) {
    DLOG(WARNING) << debug_id_ << ": Failed to refresh key "
                  << EncodeToHex(key_value_signature.key).substr(0, 10)
                  << " - marked for deletion.";
    return kMarkedForDeletion;
  }
  if (index_by_key_value.modify(insertion_result.first,
      std::bind(&KeyValueTuple::set_refresh_time, arg::_1,
                now + kRefreshInterval_))) {
    DLOG(INFO) << debug_id_ << ": Successfully refreshed key "
               << EncodeToHex(key_value_signature.key).substr(0, 10);
    return kSuccess;
  } else {
    DLOG(WARNING) << debug_id_ << ": Failed to refresh key "
                  << EncodeToHex(key_value_signature.key).substr(0, 10)
                  << " - modify failed.";
    return kFailedToModifyKeyValue;
  }
}

bool DataStore::DeleteValue(
    const KeyValueSignature &key_value_signature,
    const RequestAndSignature &delete_request_and_signature,
    bool is_refresh) {
  KeyValueIndex::index<TagKeyValue>::type& index_by_key_value =
      key_value_index_->get<TagKeyValue>();
  UpgradeLock upgrade_lock(shared_mutex_);

  // If the key and value doesn't exist, return true unless is_refresh is true,
  // in which case, add the data and mark it as deleted.
  auto it = index_by_key_value.find(boost::make_tuple(key_value_signature.key,
                                    key_value_signature.value));
  bptime::ptime now(bptime::microsec_clock::universal_time());
  if (it == index_by_key_value.end()) {
    if (is_refresh) {
      // Assumes that check on signature of request and signature of value using
      // the public key has already been done.  Also assumes that if the key
      // pre-exists, a check has been made to ensure that the same private key
      // was used to sign all pre-existing values under that key.
      if (key_value_signature.key.empty()) {
        DLOG(WARNING) << debug_id_ << ": Key empty.";
        return false;
      }
      KeyValueTuple tuple(key_value_signature, now, now + kRefreshInterval_,
                          delete_request_and_signature, true);

      // Try to insert key,value
      UpgradeToUniqueLock unique_lock(upgrade_lock);
      auto insertion_result = index_by_key_value.insert(tuple);
#ifdef DEBUG
      if (!insertion_result.second) {
        DLOG(WARNING) << debug_id_ << ": Failed to insert deleted key "
                      << EncodeToHex(key_value_signature.key).substr(0, 10);
      }
#endif
      return insertion_result.second;
    } else {
      return true;
    }
  }

  // If the value is already marked as deleted, allow refresh to reset the
  // refresh time.
  if (is_refresh && (*it).deleted) {
    UpgradeToUniqueLock unique_lock(upgrade_lock);
    return index_by_key_value.modify(it,
        std::bind(&KeyValueTuple::set_refresh_time, arg::_1,
                  now + kRefreshInterval_));
  }

  // Allow original signer to modify it or if value isn't marked as deleted, but
  // confirm time has expired, also allow refreshes to modify it.
  if (!is_refresh || ((*it).confirm_time < now)) {
    UpgradeToUniqueLock unique_lock(upgrade_lock);
    return index_by_key_value.modify(it,
        std::bind(&KeyValueTuple::UpdateStatus, arg::_1, (*it).expire_time,
                  now + kRefreshInterval_, now + kPendingConfirmDuration,
                  delete_request_and_signature, true));
  } else {
    return false;
  }
}

bool DataStore::GetValues(
    const std::string &key,
    std::vector<ValueAndSignature> *values_and_signatures) const {
  if (!values_and_signatures)
    return false;
  values_and_signatures->clear();

  KeyValueIndex::index<TagKey>::type& index_by_key =
      key_value_index_->get<TagKey>();
  SharedLock shared_lock(shared_mutex_);
  auto itr_pair = index_by_key.equal_range(key);
  if (itr_pair.first == itr_pair.second)
    return false;

  bptime::ptime now = bptime::microsec_clock::universal_time();
  while (itr_pair.first != itr_pair.second) {
    if (((*itr_pair.first).expire_time > now) && !(*itr_pair.first).deleted)
      values_and_signatures->push_back(std::make_pair(
          (*itr_pair.first).key_value_signature.value,
          (*itr_pair.first).key_value_signature.signature));
    ++itr_pair.first;
  }
  DLOG(INFO) << debug_id_ << ": Found key " << EncodeToHex(key).substr(0, 10)
             << " with " << values_and_signatures->size() << " values.";
  return (!values_and_signatures->empty());
}

void DataStore::Refresh(std::vector<KeyValueTuple> *key_value_tuples) {
  KeyValueIndex::index<TagExpireTime>::type& index_by_expire_time =
      key_value_index_->get<TagExpireTime>();
  KeyValueIndex::index<TagRefreshTime>::type& index_by_refresh_time =
      key_value_index_->get<TagRefreshTime>();
  KeyValueIndex::index<TagConfirmTime>::type& index_by_confirm_time =
      key_value_index_->get<TagConfirmTime>();

  // Remove expired values.
  UniqueLock unique_lock(shared_mutex_);
  bptime::ptime now(bptime::microsec_clock::universal_time());
  auto it = index_by_confirm_time.begin();
  auto it_confirm_upper_bound = index_by_confirm_time.upper_bound(now);
  while (it != it_confirm_upper_bound)
    (*it).deleted ? index_by_confirm_time.erase(it++) : ++it;

  // Mark expired values as deleted.
  auto it_expire = index_by_expire_time.begin();
  auto it_expire_upper_bound = index_by_expire_time.upper_bound(now);
  while (it_expire != it_expire_upper_bound) {
    if (!(*it_expire).deleted) {
      index_by_expire_time.modify(it_expire,
           std::bind(&KeyValueTuple::UpdateStatus, arg::_1,
                     (*it_expire).expire_time, (*it_expire).refresh_time,
                     now + kPendingConfirmDuration,
                     (*it_expire).request_and_signature, true));
    }
    ++it_expire;
  }

  // Fill vector with all entries which have expired refresh times.
  if (!key_value_tuples)
    return;
  auto itr(index_by_refresh_time.begin()),
       upper_bound_itr(index_by_refresh_time.upper_bound(now));
  key_value_tuples->assign(itr, upper_bound_itr);

  // Update refresh times for expired ones.
  if (itr != upper_bound_itr) {
    --(upper_bound_itr);  // Avoid potentially updating entries twice.
    for (;;) {
      bool end(itr == upper_bound_itr);
      if (index_by_refresh_time.modify(itr++,
          std::bind(&KeyValueTuple::set_refresh_time, arg::_1,
                    now + kRefreshInterval_))) {
        DLOG(INFO) << debug_id_ << ": Successfully refreshed key "
                   << EncodeToHex((*itr).key_value_signature.key).substr(0, 10);
      } else {
        DLOG(WARNING) << debug_id_ << ": Failed to refresh key "
            << EncodeToHex((*itr).key_value_signature.key).substr(0, 10)
            << " - modify failed.";
      }
      if (end)
        break;
    }
  }
}

bool DataStore::DifferentSigner(
    const KeyValueSignature &key_value_signature,
    const std::string &public_key,
    std::shared_ptr<Securifier> securifier) const {
  SharedLock shared_lock(shared_mutex_);
  auto it(key_value_index_->get<TagKey>().find(key_value_signature.key));

  if (it == key_value_index_->get<TagKey>().end())
    return false;

  if ((*it).key_value_signature.signature == key_value_signature.signature)
    return false;

  return !securifier->Validate((*it).key_value_signature.value,
                               (*it).key_value_signature.signature, "",
                               public_key, "", "");
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
