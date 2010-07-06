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

#include "maidsafe/base/online.h"
#include "maidsafe/base/utils.h"

namespace base {

OnlineController* OnlineController::Instance() {
  static OnlineController oc;
  return &oc;
}

OnlineController::OnlineController()
    : online_(), ol_mutex_(), observers_() { }

boost::uint16_t OnlineController::RegisterObserver(
    const boost::uint16_t &group, const Observer &observer) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  boost::uint16_t id = 1 + base::RandomUint32() % 65535;
  std::pair<std::map<boost::uint16_t, GroupedObserver>::iterator, bool> ret;
  ret = observers_.insert(std::pair<boost::uint16_t, GroupedObserver>
                          (id, GroupedObserver(group, observer)));
  while (!ret.second) {
    id = 1 + base::RandomUint32() % 65535;
    ret = observers_.insert(std::pair<boost::uint16_t, GroupedObserver>
                            (id, GroupedObserver(group, observer)));
  }
  return id;
}

bool OnlineController::UnregisterObserver(boost::uint16_t id) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  std::map<boost::uint16_t, GroupedObserver>::iterator it = observers_.find(id);
  if (it != observers_.end()) {
    observers_.erase(it);

    return true;
  }
  return false;
}

void OnlineController::UnregisterGroup(const boost::uint16_t &group) {
  bool finished = false;
  boost::mutex::scoped_lock loch(ol_mutex_);
  while (!finished) {
    finished = true;
    for (std::map<boost::uint16_t, GroupedObserver>::iterator it =
         observers_.begin(); it != observers_.end(); ++it) {
      if ((*it).second.first == group) {
        observers_.erase(it);
        finished = false;
        break;
      }
    }
  }
}

void OnlineController::UnregisterAll() {
  boost::mutex::scoped_lock loch(ol_mutex_);
  observers_.clear();
}

void OnlineController::SetOnline(const boost::uint16_t &group,
                                 const bool &online) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  online_[group] = online;
  for (std::map<boost::uint16_t, GroupedObserver>::iterator it =
       observers_.begin(); it != observers_.end(); ++it) {
    if ((*it).second.first == group)
      (*it).second.second(online);
  }
}

void OnlineController::SetAllOnline(const bool &online) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  for (std::map<boost::uint16_t, bool>::iterator it = online_.begin();
       it != online_.end(); ++it) {
    (*it).second = online;
  }
  for (std::map<boost::uint16_t, GroupedObserver>::iterator it =
       observers_.begin(); it != observers_.end(); ++it) {
    online_[(*it).second.first] = online;
    (*it).second.second(online);
  }
}

bool OnlineController::Online(const boost::uint16_t &group) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  std::map<boost::uint16_t, bool>::iterator it = online_.find(group);
  return (it != online_.end()) && (*it).second;
}

boost::uint16_t OnlineController::ObserversCount() {
  boost::mutex::scoped_lock loch(ol_mutex_);
  return observers_.size();
}

boost::uint16_t OnlineController::ObserversInGroupCount(
    const boost::uint16_t &group) {
  boost::mutex::scoped_lock loch(ol_mutex_);
  boost::uint16_t n(0);
  for (std::map<boost::uint16_t, GroupedObserver>::iterator it =
       observers_.begin(); it != observers_.end(); ++it) {
    if ((*it).second.first == group)
      ++n;
  }
  return n;
}

void OnlineController::Reset() {
  boost::mutex::scoped_lock loch(ol_mutex_);
  observers_.clear();
  online_.clear();
}

}  // namespace base
