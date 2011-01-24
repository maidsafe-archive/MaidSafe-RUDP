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

/*******************************************************************************
 * NOTE: This header is unlikely to have any breaking changes applied.         *
 *       However, it should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_COMMON_ROUTINGTABLE_H_
#define MAIDSAFE_COMMON_ROUTINGTABLE_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>

#include "maidsafe/kademlia/routingtable.h"
#include "maidsafe/kademlia/contact.h"
#include "maidsafe/kademlia/nodeid.h"

#ifdef MAIDSAFE_WIN32
#include <shlobj.h>
#endif
#include "maidsafe/common/platform_config.h"
#include <maidsafe/kademlia/config.h>
#include <functional>
#include <list>
#include <map>
#include <set>
#include <string>

namespace maidsafe {
  
class Contact;
  
class PublicRoutingTable {
  
 public:
   
  PublicRoutingTable(): contacts_() {}
  
  ~PublicRoutingTable();
  
  void Clear() {
    boost::mutex::scoped_lock guard(mutex_);
    contacts_.clear();
  }
  
  // Add the given contact to routing table; 
  // if it already exists, its status will be updated
  // if table full, fire a singal
  void AddContact(const kademlia::RoutingTableContact &new_contact);
  
  // Returns true and the contact if it is stored in routing table
  // otherwise it returns false
  bool GetContact(const kademlia::NodeId &node_id, Contact *contact);
  
  // Remove the contact with the specified node ID from the routing table
  void RemoveContact(const kademlia::NodeId &node_id, const bool &force);  
 
  // Finds a number of known contacts closest to the node/value with the
  // specified key.
  void FindCloseContacts(const kademlia::NodeId &target_id, 
			 const boost::uint32_t &count,
			 std::vector<Contact> *close_contacts);
		      
  int SetPublicKey(const kademlia::NodeId &node_id,
                      const std::string &new_public_key);
		      
  // int UpdateRankInfo(const kademlia::NodeId &node_id,const transport::Info &info);
  // accept Info pointer
  int UpdateRankInfo(const kademlia::NodeId &node_id,const kademlia::RankInfoPtr info);
  
  // Set the Preferred end point
  int SetPreferredEndpoint(const kademlia::NodeId &node_id,
			   const std::string &ip);  
  // Unknown Contact (ip&port without ID needs to be supported)
  // int SetPreferredEndpoint(const std::string &ip, const boost::uint16_t &port);
  
  void GetBootstrapContacts(std::vector<Contact> *contacts);  
  
  // Mark contact in routing table as having failed to respond correctly to an
  // RPC request.
  // return value is the contact's num of failed Rpcs
  int IncrementContactFailedRpcs(const kademlia::NodeId &node_id);  
  
 private:

  boost::mutex mutex_;  
  
  RoutingTableContactsContainer contacts_;
  
  Contact FindOldestContact();
  
  bool KadCloser(const Contact &contact1,const Contact &contact2,
                 const kademlia::NodeId &target_id) const;
};

// Tags
struct TagNodeId {};
struct TagRendezvousPort {};
struct TagTimeLastSeen {};
struct TagNumOfFailedRPCs {};

typedef boost::multi_index_container<
  kademlia::RoutingTableContact,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<TagNodeId>,
      boost::multi_index::const_mem_fun<
	kademlia::RoutingTableContact,kademlia::NodeId,&kademlia::RoutingTableContact.contact::node_id>
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagRendezvousPort>,
      boost::multi_index::member<
	kademlia::RoutingTableContact,transport::Port,&kademlia::RoutingTableContact.contact::rendezvous_endpoint::port>
    >,     
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagTimeLastSeen>,
      boost::multi_index::member<
	kademlia::RoutingTableContact,bptime::ptime,&kademlia::RoutingTableContact::last_seen>
    >,  
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<TagNumOfFailedRPCs>,
      boost::multi_index::member<
	kademlia::RoutingTableContact,boost::uint16_t,&kademlia::RoutingTableContact::num_failed_rpcs>      
    >
  >
> RoutingTableContactsContainer;

}  // namespace maidsafe

#endif  // MAIDSAFE_COMMON_ROUTINGTABLE_H_
