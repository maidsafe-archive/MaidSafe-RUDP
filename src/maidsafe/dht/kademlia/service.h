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

#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "maidsafe/dht/kademlia/config.h"
#include "maidsafe/dht/kademlia/contact.h"
#include "maidsafe/dht/kademlia/data_store.h"
#include "maidsafe/dht/kademlia/sender_task.h"

namespace maidsafe {

namespace dht {

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
class StoreRefreshRequest;
class StoreResponse;
class StoreRefreshResponse;
class DeleteRequest;
class DeleteRefreshRequest;
class DeleteRefreshResponse;
class DeleteResponse;
class DownlistNotification;
}  // namespace protobuf

namespace test {
class ServicesTest;
template <typename T>
class RpcsTest;
}  // namespace test


/** Object handling service requests on a node.
 *  Contains tables of the routing contacts and <value,sig,key> tuples
 *  @class Service */
class Service : public std::enable_shared_from_this<Service> {
 public:
  /** Constructor.  To create a Service, in all cases the routing_table and
   * data_store must be provided.
   *  @param routing_table The routing table contains all contacts.
   *  @param data_store The data_store table contains <value,sig,key> tuples.
   *  @param alternative_store Alternative store.
   *  @param securifier Securifier for <value,sig,key> validation.
   *  @param[in] k Kademlia constant k.*/
  Service(std::shared_ptr<RoutingTable> routing_table,
          std::shared_ptr<DataStore> data_store,
          AlternativeStorePtr alternative_store,
          SecurifierPtr securifier,
          const uint16_t &k);

  /** Dstructor. */
  ~Service();

  /** Connect to Signals.
   *  @param transport The Transportor to link.
   *  @param message_handler The Message Handler to link. */
  void ConnectToSignals(MessageHandlerPtr message_handler);
  /** Handle Ping request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void Ping(const transport::Info &info,
            const protobuf::PingRequest &request,
            protobuf::PingResponse *response,
            transport::Timeout *timeout);
  /** Handle FindValue request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void FindValue(const transport::Info &info,
                 const protobuf::FindValueRequest &request,
                 protobuf::FindValueResponse *response,
                 transport::Timeout *timeout);
  /** Handle FindNodes request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response To response. */
  void FindNodes(const transport::Info &info,
                 const protobuf::FindNodesRequest &request,
                 protobuf::FindNodesResponse *response,
                 transport::Timeout *timeout);
  /** Handle Store request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[in] message The message to store.
   *  @param[in] message_signature The signature of the message to store.
   *  @param[out] response The response. */
  void Store(const transport::Info &info,
             const protobuf::StoreRequest &request,
             const std::string &message,
             const std::string &message_signature,
             protobuf::StoreResponse *response,
             transport::Timeout *timeout);
  /** Handle StoreRefresh request.
   *  The request sender will be added into the routing table
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response The response. */
  void StoreRefresh(const transport::Info &info,
                    const protobuf::StoreRefreshRequest &request,
                    protobuf::StoreRefreshResponse *response,
                    transport::Timeout *timeout);
  /** Handle Delete request.
   *  The request sender will be added into the routing table.
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[in] message The message to delete.
   *  @param[in] message_signature The signature of the message to delete.
   *  @param[out] response The response. */
  void Delete(const transport::Info &info,
              const protobuf::DeleteRequest &request,
              const std::string &message,
              const std::string &message_signature,
              protobuf::DeleteResponse *response,
              transport::Timeout *timeout);
  /** Handle DeleteRefresh request.
   *  The request sender will be added into the routing table.
   *  @param[in] info The rank info.
   *  @param[in] request The request.
   *  @param[out] response The response. */
  void DeleteRefresh(const transport::Info &info,
                     const protobuf::DeleteRefreshRequest &request,
                     protobuf::DeleteRefreshResponse *response,
                     transport::Timeout *timeout);
  /** Handle Downlist request.
   *  Try to ping the contacts in the downlist and then remove those no-response
   *  contacts from the routing table
   *  @param info The rank info.
   *  @param request The request. */
  void Downlist(const transport::Info &info,
                const protobuf::DownlistNotification &request,
                transport::Timeout *timeout);
  /** Set the status to be joined or not joined
   *  @param joined The bool switch. */
  void set_node_joined(bool joined) { node_joined_ = joined; }
  /** Set the node contact
   *  @param contact The node contact. */
  void set_node_contact(const Contact &contact) { node_contact_ = contact; }
  /** Set the securifier
   *  @param securifier The securifier. */
  void set_securifier(SecurifierPtr securifier) { securifier_ = securifier; }

  friend class test::ServicesTest;
  template <typename T>
  friend class test::RpcsTest;

 private:
  /** Copy Constructor.
   *  @param Service The object to be copied. */
  Service(const Service&);
  /** Assignment overload */
  Service& operator = (const Service&);
  /** Standard parameter checks.  Non-NULL parameters are checked for validity.
   *  @param[in] method_name The name of the method calling this function.
   *  @param[in] key Kademlia key.
   *  @param[in] message Serialised message.
   *  @param[in] message_signature Message signature. */
  bool CheckParameters(const std::string &method_name,
                       const Key *key = NULL,
                       const std::string *message = NULL,
                       const std::string *message_signature = NULL) const;
  /** Store Callback.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation */
  void StoreCallback(KeyValueSignature key_value_signature,
                     protobuf::StoreRequest request,
                     transport::Info info,
                     RequestAndSignature request_signature,
                     std::string public_key,
                     std::string public_key_validation);
  /** Store Refresh Callback.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation */
  void StoreRefreshCallback(KeyValueSignature key_value_signature,
                            protobuf::StoreRefreshRequest request,
                            transport::Info info,
                            RequestAndSignature request_signature,
                            std::string public_key,
                            std::string public_key_validation);
  /** Validate the request and then store the tuple.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation
   *  @param[in] is_refresh Indicating a publish or a refresh
   *  @return Indicating validation succeed or not. The success of store will be
   *          reflected in response.result() */
  bool ValidateAndStore(const KeyValueSignature &key_value_signature,
                        const protobuf::StoreRequest &request,
                        const transport::Info &info,
                        const RequestAndSignature &request_signature,
                        const std::string &public_key,
                        const std::string &public_key_validation,
                        const bool is_refresh);
  /** Delete Callback.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation */
  void DeleteCallback(KeyValueSignature key_value_signature,
                      protobuf::DeleteRequest request,
                      transport::Info info,
                      RequestAndSignature request_signature,
                      std::string public_key,
                      std::string public_key_validation);
  /** Delete Refresh Callback.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation */
  void DeleteRefreshCallback(KeyValueSignature key_value_signature,
                             protobuf::DeleteRefreshRequest request,
                             transport::Info info,
                             RequestAndSignature request_signature,
                             std::string public_key,
                             std::string public_key_validation);
  /** Validate the request and then delete the tuple.
   *  @param[in] key_value_signature tuple of <key, value, signature>.
   *  @param[in] request The request.
   *  @param[in] info The rank info.
   *  @param[in] request_signature The request signature.
   *  @param[in] public_key public key
   *  @param[in] public_key_validation public key validation
   *  @param[in] is_refresh Indicating a publish or a refresh
   *  @return Indicating validation succeed or not. The success of delete will
   *          be reflected in response.result() */
  bool ValidateAndDelete(const KeyValueSignature &key_value_signature,
                         const protobuf::DeleteRequest &request,
                         const transport::Info &info,
                         const RequestAndSignature &request_signature,
                         const std::string &public_key,
                         const std::string &public_key_validation,
                         const bool is_refresh);

  void AddContactToRoutingTable(const Contact &contact,
                                const transport::Info &info);

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
  const uint16_t k_;
  /** sender task */
  std::shared_ptr<SenderTask> sender_task_;
  /** client node id that gets ignored by RT **/
  std::string client_node_id_;
};

}  // namespace kademlia

}  // namespace dht

}  // namespace maidsafe

#endif  // MAIDSAFE_DHT_KADEMLIA_SERVICE_H_
