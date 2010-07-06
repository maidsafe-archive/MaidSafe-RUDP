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

#ifndef MAIDSAFE_TESTS_KADEMLIA_FAKE_CALLBACKS_H_
#define MAIDSAFE_TESTS_KADEMLIA_FAKE_CALLBACKS_H_

#include <boost/thread/thread.hpp>
#include <list>
#include <vector>
#include <string>
#include "maidsafe/protobuf/general_messages.pb.h"
#include "maidsafe/protobuf/kademlia_service_messages.pb.h"

class FakeCallback {
 public:
  FakeCallback() : result_("") {
  }
  virtual ~FakeCallback() {
  }
  virtual void CallbackFunc(const std::string& res) = 0;
  virtual void Reset() = 0;
  std::string result() const {return result_;}
 protected:
  std::string result_;
};

class PingCallback : public FakeCallback {
 public:
  PingCallback() : FakeCallback(), result_msg() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res))
      result_msg.set_result(kad::kRpcResultFailure);
    result_ = result_msg.result();
  }
  void Reset() {
    result_msg.Clear();
    result_ = "";
  }
 private:
  kad::PingResponse result_msg;
};

class StoreValueCallback :public FakeCallback {
 public:
  StoreValueCallback() : FakeCallback(), result_msg() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  kad::StoreResponse result_msg;
};

class FindCallback : public FakeCallback {
 public:
  FindCallback() : FakeCallback(), result_msg(), values_(), closest_nodes_(),
                   signed_values_() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    for (int i = 0; i < result_msg.values_size(); i++)
      values_.push_back(result_msg.values(i));
    for (int i = 0; i < result_msg.closest_nodes_size(); i++)
      closest_nodes_.push_back(result_msg.closest_nodes(i));
    for (int i = 0; i < result_msg.signed_values_size(); i++)
      signed_values_.push_back(result_msg.signed_values(i));
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
    values_.clear();
    closest_nodes_.clear();
    signed_values_.clear();
  };
  std::vector<std::string> values() const {return values_;}
  std::vector<std::string> closest_nodes() const {return closest_nodes_;}
  std::vector<kad::SignedValue> signed_values() {return signed_values_;}
 private:
  kad::FindResponse result_msg;
  std::vector<std::string> values_;
  std::vector<std::string> closest_nodes_;
  std::vector<kad::SignedValue> signed_values_;
};

class GetNodeContactDetailsCallback : public FakeCallback {
 public:
  GetNodeContactDetailsCallback() : result_msg(), contact_() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    if (result_msg.has_contact())
      contact_ = result_msg.contact();
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
    contact_ = "";
  };
  std::string contact() const {return contact_;}
 private:
  kad::FindNodeResult result_msg;
  std::string contact_;
};

class GeneralKadCallback : public FakeCallback {
 public:
  GeneralKadCallback() : FakeCallback(), result_msg() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  base::GeneralResponse result_msg;
};

class DeleteValueCallback : public FakeCallback {
 public:
  DeleteValueCallback() : FakeCallback(), result_msg() {
  }
  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res)) {
      result_msg.set_result(kad::kRpcResultFailure);
    }
    result_ = result_msg.result();
  };
  void Reset() {
    result_msg.Clear();
    result_ = "";
  };
 private:
  kad::DeleteResponse result_msg;
};

class UpdateValueCallback : public FakeCallback {
 public:
  UpdateValueCallback() : FakeCallback(), result_msg() { }

  void CallbackFunc(const std::string &res) {
    if (!result_msg.ParseFromString(res))
      result_msg.set_result(kad::kRpcResultFailure);
    result_ = result_msg.result();
  }

  void Reset() {
    result_msg.Clear();
    result_ = "";
  }

 private:
  kad::UpdateResponse result_msg;
};

inline void wait_result(FakeCallback *callback) {
  while (1) {
    {
      if (callback->result() != "")
        return;
    }
    boost::this_thread::sleep(boost::posix_time::milliseconds(500));
  }
}

#endif  // MAIDSAFE_TESTS_KADEMLIA_FAKE_CALLBACKS_H_
