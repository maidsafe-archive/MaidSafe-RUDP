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

#ifndef MAIDSAFE_DHT_KADEMLIA_SENDER_TASK_H_
#define MAIDSAFE_DHT_KADEMLIA_SENDER_TASK_H_

#include <functional>
#include <string>

#include "maidsafe/dht/kademlia/datastore.h"
#include "maidsafe/dht/transport/transport.h"

namespace maidsafe  {

namespace dht {

namespace kademlia {

namespace test {
class SenderTaskTest;
class ServicesTest;
class SenderTaskTest_BEH_AddTask_Test;
class SenderTaskTest_FUNC_SenderTaskCallback_Test;
class SenderTaskTest_FUNC_SenderTaskCallbackMultiThreaded_Test;
}

class Service;

typedef std::function<void(const KeyValueSignature, transport::Info,
                           RequestAndSignature, std::string, std::string)>
        TaskCallback;

struct Task {
  Task(const KeyValueSignature &key_value_signature,
       const transport::Info &info,
       const RequestAndSignature &request_signature,
       const std::string &public_key_id,
       TaskCallback ops_callback);

  const std::string& key() const;
  const std::string& get_public_key_id() const;

  KeyValueSignature key_value_signature;
  transport::Info info;
  RequestAndSignature request_signature;
  std::string public_key_id;
  TaskCallback ops_callback;
};

struct TagPublicKeyId {};
struct TagTaskKey {};

typedef boost::multi_index::multi_index_container<
  Task,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagTaskKey>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(Task, const std::string&, key)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagPublicKeyId>,
      BOOST_MULTI_INDEX_CONST_MEM_FUN(Task, const std::string&,
                                      get_public_key_id)
    >
  >
> TaskIndex;
// This class temporarily holds the tasks of Service and reduces the number of
// network lookup for same requester.
class SenderTask  {
 public:
  SenderTask();

  ~SenderTask();
  // Adds a task into the multi index and executes it when the
  // SenderTaskCallback() is called after network lookup for a given sender.
  // Dosen't store task if provided key is already stored and is associated
  // with different public_key_id.
  // Modifies is_new_id to true if it is a task by the sender whose
  // public_key_id is not present in the  multi index.
  // Returns false if stored key is associated with different public_key_id.
  // Returns true if successfully added into the multi index or false otherwise.
  bool AddTask(const KeyValueSignature &key_value_signature,
               const transport::Info &info,
               const RequestAndSignature &request_signature,
               const std::string &public_key_id,
               TaskCallback ops_callback,
               bool *is_new_id);

 private:
  friend class Service;
  friend class test::SenderTaskTest;
  friend class test::ServicesTest;
  friend class test::SenderTaskTest_BEH_AddTask_Test;
  friend class test::SenderTaskTest_FUNC_SenderTaskCallback_Test;
  friend class test::SenderTaskTest_FUNC_SenderTaskCallbackMultiThreaded_Test;

  typedef boost::shared_lock<boost::shared_mutex> SharedLock;
  typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
  typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
  typedef boost::upgrade_to_unique_lock<boost::shared_mutex>
          UpgradeToUniqueLock;

  // Executes all the tasks present in the multi index under given
  // public_key_id and delete them from the multi index after the execution.
  // Does nothing if the public_key_id is empty or task for given public_key_id
  // is not present in the multi index.
  void SenderTaskCallback(std::string public_key_id,
                          std::string public_key,
                          std::string public_key_validation);

  /**  Multi_index container of sender tasks */
  std::shared_ptr<TaskIndex> task_index_;
  /** Thread safe shared mutex */
  boost::shared_mutex shared_mutex_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_SENDER_TASK_H_
