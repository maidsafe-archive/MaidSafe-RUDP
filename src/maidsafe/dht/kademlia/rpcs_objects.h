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

#ifndef MAIDSAFE_DHT_KADEMLIA_RPCS_OBJECTS_H_
#define MAIDSAFE_DHT_KADEMLIA_RPCS_OBJECTS_H_

#include <cstdint>
#include <string>

#ifdef __MSVC__
#  pragma warning(push)
#  pragma warning(disable: 4244)
#endif
#include "boost/multi_index_container.hpp"
#include "boost/multi_index/composite_key.hpp"
#include "boost/multi_index/ordered_index.hpp"
#include "boost/multi_index/identity.hpp"
#include "boost/multi_index/member.hpp"
#include "boost/multi_index/mem_fun.hpp"
#ifdef __MSVC__
#  pragma warning(pop)
#endif
#include "boost/thread/shared_mutex.hpp"
#include "boost/thread/locks.hpp"

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/transport/transport.h"
#include "maidsafe/dht/kademlia/message_handler.h"
#include "maidsafe/dht/version.h"

#if MAIDSAFE_DHT_VERSION != 3104
#  error This API is not compatible with the installed library.\
    Please update the maidsafe-dht library.
#endif


namespace maidsafe  {

namespace dht {

namespace kademlia {

struct ConnectedObject {
  ConnectedObject(const TransportPtr transport,
       const MessageHandlerPtr message_handler,
       const uint32_t index)
      : transport_ptr(transport),
        message_handler_ptr(message_handler),
        this_index(index) {}

  TransportPtr transport_ptr;
  MessageHandlerPtr message_handler_ptr;
  uint32_t this_index;
};

struct TagIndexId {};

typedef boost::multi_index::multi_index_container<
  ConnectedObject,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<TagIndexId>,
      BOOST_MULTI_INDEX_MEMBER(ConnectedObject, uint32_t, this_index)
    >
  >
> ConnectedObjectsContainer;

// This class temporarily holds the connected objects of Rpcs to ensure all
// resources can be correctly released and no memory leaked
class ConnectedObjectsList  {
 public:
  ConnectedObjectsList();

  ~ConnectedObjectsList();
  // Adds a connected object into the multi index
  // return the index of those objects in the container
  uint32_t AddObject(const TransportPtr transport,
                     const MessageHandlerPtr message_handler);

  // Remove an object based on the index
  // Returns true if successfully removed or false otherwise.
  bool RemoveObject(uint32_t index);

  // Return the TransportPtr of the index
  TransportPtr GetTransport(uint32_t index);

  // Returns the size of the connected objects MI
  size_t Size();

 private:
  typedef boost::shared_lock<boost::shared_mutex> SharedLock;
  typedef boost::upgrade_lock<boost::shared_mutex> UpgradeLock;
  typedef boost::unique_lock<boost::shared_mutex> UniqueLock;
  typedef boost::upgrade_to_unique_lock<boost::shared_mutex>
          UpgradeToUniqueLock;

  /**  Multi_index container of connected objects */
  std::shared_ptr<ConnectedObjectsContainer> objects_container_;
  /** Thread safe shared mutex */
  boost::shared_mutex shared_mutex_;
  /** Global Counter used as an index for each added object */
  uint32_t index_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_RPCS_OBJECTS_H_
