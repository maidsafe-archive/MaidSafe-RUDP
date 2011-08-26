/* Copyright (c) 2011 maidsafe.net limited
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

#include "maidsafe/dht/kademlia/sender_task.h"
#include "maidsafe/dht/log.h"

namespace maidsafe {

namespace dht {

namespace kademlia {

Task::Task(const KeyValueSignature &key_value_signature,
           const transport::Info &info,
           const RequestAndSignature &request_signature,
           const std::string &public_key_id,
           TaskCallback ops_callback)
    : key_value_signature(key_value_signature),
      info(info),
      request_signature(request_signature),
      public_key_id(public_key_id),
      ops_callback(ops_callback) {}

const std::string& Task::key() const {
  return key_value_signature.key;
}

const std::string& Task::get_public_key_id() const {
  return public_key_id;
}

SenderTask::SenderTask()
    : task_index_(new TaskIndex),
      shared_mutex_() {}

SenderTask::~SenderTask() {}

bool SenderTask::AddTask(const KeyValueSignature &key_value_signature,
                         const transport::Info &info,
                         const RequestAndSignature &request_signature,
                         const std::string &public_key_id,
                         TaskCallback ops_callback,
                         bool *is_new_id) {
  if (key_value_signature.key.empty()) {
    DLOG(WARNING) << "Empty key.";
    return false;
  }
  if (key_value_signature.value.empty()) {
    DLOG(WARNING) << "Empty value.";
    return false;
  }
  if (key_value_signature.signature.empty()) {
    DLOG(WARNING) << "Empty signature.";
    return false;
  }
  if (public_key_id.empty()) {
    DLOG(WARNING) << "Empty public_key_id.";
    return false;
  }
  if (request_signature.first.empty()) {
    DLOG(WARNING) << "Empty request.";
    return false;
  }
  if (!ops_callback) {
    DLOG(WARNING) << "Invalid callback.";
    return false;
  }

  Task task(key_value_signature, info, request_signature, public_key_id,
            ops_callback);
  UpgradeLock upgrade_lock(shared_mutex_);
  TaskIndex::index<TagPublicKeyId>::type& index_by_public_key_id =
      task_index_->get<TagPublicKeyId>();

  auto it = index_by_public_key_id.find(public_key_id);
  *is_new_id = (it == index_by_public_key_id.end());

  TaskIndex::index<TagTaskKey>::type& index_by_key =
      task_index_->get<TagTaskKey>();
  auto itr = index_by_key.find(key_value_signature.key);
  if (itr != index_by_key.end()) {
    if ((*itr).public_key_id != public_key_id) {
      DLOG(WARNING) << "Stored key is associated with different public_key_id.";
      return false;
    }
  }
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  auto itr_return = index_by_public_key_id.insert(task);
#ifdef DEBUG
  if (!itr_return.second)
      DLOG(WARNING) << "Task already exists.";
#endif
  return itr_return.second;
}

void SenderTask::SenderTaskCallback(std::string public_key_id,
                                    std::string public_key,
                                    std::string public_key_validation) {
  if (public_key_id.empty()) {
    DLOG(WARNING) << "Empty public_key_id.";
    return;
  }
  UpgradeLock upgrade_lock(shared_mutex_);
  TaskIndex::index<TagPublicKeyId>::type& index_by_public_key_id =
      task_index_->get<TagPublicKeyId>();
  auto itr_pair = index_by_public_key_id.equal_range(public_key_id);
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  while (itr_pair.first != itr_pair.second) {
    TaskCallback call_back = (*itr_pair.first).ops_callback;
    call_back((*itr_pair.first).key_value_signature, (*itr_pair.first).info,
              (*itr_pair.first).request_signature, public_key,
              public_key_validation);
    // Remove entry from multi index
    index_by_public_key_id.erase(itr_pair.first++);
  }
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
