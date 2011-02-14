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

#ifndef MAIDSAFE_DHT_KADEMLIA_SERVICE_H_
#define MAIDSAFE_DHT_KADEMLIA_SERVICE_H_

#include <memory>
#include <string>
#include <vector>

#include "boost/cstdint.hpp"
#include "boost/enable_shared_from_this.hpp"
#include "boost/function.hpp"

#include "maidsafe-dht/kademlia/config.h"
#include "maidsafe-dht/kademlia/contact.h"

namespace maidsafe {

namespace kademlia {

class DataStore;
class RoutingTable;
class MessageHandler;

namespace protobuf {
class SignedValue;
class PingRequest;
class PingResponse;
class FindValueRequest;
class FindValueResponse;
class FindNodesRequest;
class FindNodesResponse;
class StoreRequest;
class StoreResponse;
class DeleteRequest;
class DeleteResponse;
class DownlistNotification;
}  // namespace protobuf

typedef std::shared_ptr<boost::signals2::signal<void(
    const Contact&)>> PingDownListContactsPtr;

/** Object handling service requests on a node.
 *  Contains tables of the routing contacts and <value,sig,key> tuples
 *  @class Service */
class Service : public boost::enable_shared_from_this<Service> {
 public:
  /** Constructor.  To create a Service, in all cases the routing_table and
   * data_store must be provided.
   *  @param routing_table The routing table contains all contacts.
   *  @param data_store The data_store table contains <value,sig,key> tuples.
   *  @param alternative_store Alternative store.
   *  @param securifier Securifier for <value,sig,key> validation. */
  Service(std::shared_ptr<RoutingTable> routing_table,
          std::shared_ptr<DataStore> data_store,
          AlternativeStorePtr alternative_store,
          SecurifierPtr securifier);
  /** Constructor.  To create a Service, in all cases the routing_table and
   * data_store must be provided.
   *  @param routing_table The routing table contains all contacts.
   *  @param data_store The data_store table contains <value,sig,key> tuples.
   *  @param alternative_store Alternative store.
   *  @param securifier Securifier for <value,sig,key> validation.
   *  @param[in] k k closest contacts.*/
  Service(std::shared_ptr<RoutingTable> routing_table,
          std::shared_ptr<DataStore> data_store,
          AlternativeStorePtr alternative_store,
          SecurifierPtr securifier,
          const boost::uint16_t &k);

  /** Dstructor. */
  ~Service();

  /** Connect to Signals.
   *  @param transport The Transportor to link.
   *  @param message_handler The Message Handler to link. */
  void ConnectToSignals(TransportPtr transport,
                        MessageHandlerPtr message_handler);
  /** Handle Ping request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void Ping(const transport::Info &info,
            const protobuf::PingRequest &request,
            protobuf::PingResponse *response);
  /** Handle FindValue request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */            
  void FindValue(const transport::Info &info,
                 const protobuf::FindValueRequest &request,
                 protobuf::FindValueResponse *response);
  /** Handle FindNodes request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */                 
  void FindNodes(const transport::Info &info,
                 const protobuf::FindNodesRequest &request,
                 protobuf::FindNodesResponse *response);
  /** Handle Store request.
   *  It can be a publish request or just a refresh request
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[in] message The message to store.
   *  @param[in] message_signature The signature of the message to store.
   *  @param[out] response To response. */                 
  void Store(const transport::Info &info,
             const protobuf::StoreRequest &request,
             const std::string &message,
             const std::string &message_signature,
             protobuf::StoreResponse *response);
  /** Handle Delete request.
   *  It can be a publish request or just a refresh request
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[in] message The message to delete.
   *  @param[in] message_signature The signature of the message to delete.
   *  @param[out] response To response. */              
  void Delete(const transport::Info &info,
              const protobuf::DeleteRequest &request,
              const std::string &message,
              const std::string &message_signature,
              protobuf::DeleteResponse *response);
  /** Handle Downlist request.
   *  Try to ping the contacts in the downlist and then remove those no-response
   *  contacts from the routing table
   *  @param info The rank info.
   *  @param request The request. */
  void Downlist(const transport::Info &info,
                const protobuf::DownlistNotification &request);
  /** Getter.
   *  @return The singal handler. */
  PingDownListContactsPtr GetPingOldestContactSingalHandler();
  /** Set the status to be joined or not joined
   *  @param joined The bool switch. */
  void set_node_joined(bool joined) { node_joined_ = joined; }
  /** Set the node contact
   *  @param contact The node contact. */
  void set_node_contact(const Contact &contact) { node_contact_ = contact; }
  /** Set the securifier
   *  @param securifier The securifier. */
  void set_securifier(SecurifierPtr securifier) { securifier_ = securifier; }
 private:
  /** Copy Constructor.
   *  @param Service The object to be copied. */   
  Service(const Service&);
  /** Assignment overload */
  Service& operator = (const Service&);
  /** routing table */
  std::shared_ptr<RoutingTable> routing_table_;
  /** data store */
  std::shared_ptr<DataStore> datastore_;
  /** alternative store */
  AlternativeStorePtr alternative_store_;
  /** securifier */
  SecurifierPtr securifier_;
  /** bool switch of joined status */
  bool node_joined_;
  /** node contact */
  Contact node_contact_;
    /** k closest to the target */
  const boost::uint16_t k_;
  /** Singal handler */
  PingDownListContactsPtr ping_down_list_contacts_;
};

}  // namespace kademlia

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_SERVICE_H_
