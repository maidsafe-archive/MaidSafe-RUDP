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

#ifndef MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_
#define MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_

#include <boost/shared_ptr.hpp>
#include <boost/thread/mutex.hpp>

#include <map>
#include <string>
#include <utility>
#include <vector>

namespace base {
class CallLaterTimer;
}  // namespace base

namespace kad {
class KNode;
class SignedValue;
class SignedRequest;
}  // namespace kad

namespace net_client {

class MySqlppWrap;

class Operator {
  typedef std::pair<kad::SignedValue, int> ValueStatus;
  typedef std::pair<std::string, ValueStatus> ValuesMapPair;
  typedef std::multimap<std::string, ValueStatus> ValuesMap;

 public:
  Operator(boost::shared_ptr<kad::KNode> knode, const std::string &public_key,
           const std::string &private_key);
  void Run();
  void Halt();

 private:
  Operator(const Operator&);
  Operator &operator=(const Operator&);

  int ChooseOperation();
  void ExecuteOperation();
  void GenerateValues(int size);
  void ScheduleInitialOperations();

  // Operations
  void StoreValue(const std::string &key, const kad::SignedValue &sv);
  void FindValue(const std::string &key,
                 const std::vector<kad::SignedValue> &values,
                 bool mine);

  // Operation Callbacks
  void StoreCallback(const std::string &key, const kad::SignedValue &sv,
                     const std::string &ser_result);
  void FindValueCallback(const std::string &ser_result,
                         const std::string &key,
                         const std::vector<kad::SignedValue> &values,
                         bool mine);

  // Miscellaneous
  void CreateRequestSignature(const std::string &key,
                              kad::SignedRequest *request);

  boost::shared_ptr<kad::KNode> knode_;
  boost::shared_ptr<MySqlppWrap> wrap_;
  volatile bool halt_request_;
  int operation_index_;
  std::map<int, std::string> operation_map_;
  ValuesMap values_map_;
  boost::mutex op_map_mutex_, values_map_mutex_;
  boost::shared_ptr<base::CallLaterTimer> timer_;
  std::string public_key_, private_key_, public_key_signature_;
};

}  // namespace net_client

#endif  // MAIDSAFE_DISTRIBUTED_NETWORK_OPERATOR_H_
