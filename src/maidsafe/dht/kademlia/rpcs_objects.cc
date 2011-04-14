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

#include "maidsafe/dht/kademlia/rpcs_objects.h"

namespace maidsafe {

namespace dht {

namespace kademlia {

ConnectedObjectsList::ConnectedObjectsList()
    : objects_container_(new ConnectedObjectsContainer),
      shared_mutex_(),
      index_(0) {}

ConnectedObjectsList::~ConnectedObjectsList() {}

boost::uint32_t ConnectedObjectsList::AddObject(
    const TransportPtr transport,
    const MessageHandlerPtr message_handler) {
  ConnectedObject object(transport, message_handler, index_);
  UniqueLock unique_lock(shared_mutex_);
  ConnectedObjectsContainer::index<TagIndexId>::type& index_by_index_id =
      objects_container_->get<TagIndexId>();
  index_by_index_id.insert(object);
  boost::uint32_t result = index_;
  // increment the counter
  // TODO(qi.ma@maidsafe.net): should some kind of range check to applied here?
  ++index_;
  return result;
}

bool ConnectedObjectsList::RemoveObject(boost::uint32_t index) {
  UpgradeLock upgrade_lock(shared_mutex_);
  ConnectedObjectsContainer::index<TagIndexId>::type& index_by_index_id =
      objects_container_->get<TagIndexId>();
  auto it = index_by_index_id.find(index);
  if (it == index_by_index_id.end())
    return false;
  UpgradeToUniqueLock unique_lock(upgrade_lock);
  // Remove the entry from multi index
  index_by_index_id.erase(it);
  return true;
}

TransportPtr ConnectedObjectsList::GetTransport(boost::uint32_t index) {
  SharedLock shared_lock(shared_mutex_);
  ConnectedObjectsContainer::index<TagIndexId>::type& index_by_index_id =
      objects_container_->get<TagIndexId>();
  auto it = index_by_index_id.find(index);
  if (it == index_by_index_id.end())
    return TransportPtr();
  return (*it).transport_ptr;
}

size_t ConnectedObjectsList::Size() {
  SharedLock shared_lock(shared_mutex_);
  return objects_container_->size();
}

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe
