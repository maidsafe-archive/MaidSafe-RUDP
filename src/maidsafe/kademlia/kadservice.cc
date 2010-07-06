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

#include <boost/compressed_pair.hpp>
#include <utility>
#include "maidsafe/base/log.h"
#include "maidsafe/kademlia/kadservice.h"
#include "maidsafe/kademlia/kadrpc.h"
#include "maidsafe/kademlia/knodeimpl.h"
#include "maidsafe/kademlia/datastore.h"
#include "maidsafe/base/alternativestore.h"
#include "maidsafe/base/crypto.h"
#include "maidsafe/base/utils.h"
#include "maidsafe/kademlia/knode-api.h"
#include "maidsafe/rpcprotocol/channel-api.h"
#include "maidsafe/protobuf/signed_kadvalue.pb.h"
#include "maidsafe/base/validationinterface.h"
#include "maidsafe/kademlia/kadid.h"

namespace kad {

static void downlist_ping_cb(const std::string&) {}

KadService::KadService(const NatRpcs &nat_rpcs,
                       boost::shared_ptr<DataStore> datastore,
                       const bool &hasRSAkeys, AddContactFunctor add_cts,
                       GetRandomContactsFunctor rand_cts,
                       GetContactFunctor get_ctc,
                       GetKClosestFunctor get_kcts,
                       PingFunctor ping,
                       RemoveContactFunctor remove_contact)
    : nat_rpcs_(nat_rpcs), pdatastore_(datastore), node_joined_(false),
      node_hasRSAkeys_(hasRSAkeys), node_info_(), alternative_store_(NULL),
      add_contact_(add_cts), get_random_contacts_(rand_cts),
      get_contact_(get_ctc), get_closestK_contacts_(get_kcts), ping_(ping),
      remove_contact_(remove_contact), signature_validator_(NULL) {}

void KadService::Bootstrap_NatDetectionRv(const NatDetectionResponse *response,
                                          struct NatDetectionData data) {
  Contact sender(data.newcomer.node_id(), data.newcomer.host_ip(),
      data.newcomer.host_port(), node_info_.ip(), node_info_.port());
  if (response->IsInitialized()) {
    if (response->result() == kRpcResultSuccess) {
      // Node B replies to A with A's external IP and PORT and a flag stating A
      // can only be contacted via rendezvous - END
      data.response->set_nat_type(2);
    } else {
      // Node B replies to node A with a flag stating no communication} - END
      // (later we can do tunneling for clients if needed)
      data.response->set_nat_type(3);
    }
    if (data.controller != NULL) {
      add_contact_(sender, data.controller->rtt(), false);
      delete data.controller;
      data.controller = NULL;
    } else {
      add_contact_(sender, 0.0, false);
    }
    delete response;
    data.done->Run();
  } else {
    data.ex_contacts.push_back(data.node_c);
    delete response;
    SendNatDetection(data);
  }
}

void KadService::Bootstrap_NatDetection(const NatDetectionResponse *response,
                                        struct NatDetectionData data) {
  if (response->IsInitialized()) {
    if (response->result() == kRpcResultSuccess) {
      // If true - node B replies to node A - DIRECT connected - END
      data.response->set_nat_type(1);
      // Try to get the sender's address from the local routingtable
      // if find no result in the local routingtable, do a find node
      Contact sender(data.newcomer.node_id(), data.newcomer.host_ip(),
          data.newcomer.host_port(), data.newcomer.local_ip(),
          data.newcomer.local_port());  // No rendezvous info
      if (data.controller != NULL) {
        add_contact_(sender, data.controller->rtt(), false);
        delete data.controller;
        data.controller = NULL;
      } else {
        add_contact_(sender, 0.0, false);
      }
      data.done->Run();
    } else {
      // Node B asks C to try a rendezvous to A with B as rendezvous
      NatDetectionResponse *resp = new NatDetectionResponse;
      google::protobuf::Closure *done = google::protobuf::NewCallback<
        KadService, const NatDetectionResponse*, struct NatDetectionData>(this,
        &KadService::Bootstrap_NatDetectionRv, resp, data);
      std::string newcomer_str;
      data.newcomer.SerialiseToString(&newcomer_str);
      // no need to send using rendezvous server of node C because it has
      // already made contact with it, it can connect to it directly
      nat_rpcs_.NatDetection(newcomer_str, data.bootstrap_node, 2,
          node_info_.node_id(), data.node_c.host_ip(), data.node_c.host_port(),
          "", 0, resp, data.controller, done);
    }
  } else {
    data.ex_contacts.push_back(data.node_c);
    SendNatDetection(data);
  }
  delete response;
}

void KadService::Ping(google::protobuf::RpcController *controller,
                      const PingRequest *request, PingResponse *response,
                      google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (request->ping() == "ping" &&
             GetSender(request->sender_info(), &sender)) {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::FindNode(google::protobuf::RpcController *controller,
                          const FindRequest *request, FindResponse *response,
                          google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    std::vector<Contact> closest_contacts, exclude_contacts;
    KadId key(request->key());
    if (key.IsValid()) {
      exclude_contacts.push_back(sender);
      get_closestK_contacts_(key, exclude_contacts, &closest_contacts);
      bool found_node(false);
      for (unsigned int i = 0; i < closest_contacts.size(); ++i) {
        std::string contact_str;
        closest_contacts[i].SerialiseToString(&contact_str);
        response->add_closest_nodes(contact_str);
        if (key == closest_contacts[i].node_id())
          found_node = true;
      }
      if (!found_node) {
        Contact key_node;
        if (get_contact_(key, &key_node)) {
          std::string str_key_contact;
          key_node.SerialiseToString(&str_key_contact);
          response->add_closest_nodes(str_key_contact);
        }
      }
      response->set_result(kRpcResultSuccess);
    } else {
      response->set_result(kRpcResultFailure);
    }
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
                                    (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::FindValue(google::protobuf::RpcController *controller,
                           const FindRequest *request, FindResponse *response,
                           google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    // If the value exists in the alternative store, add our contact details to
    // field alternative_value_holder.  If not, get the values if present in
    // this node's data store, otherwise execute find_node for this key.
    std::string key(request->key());
    std::vector<std::string> values_str;
    if (alternative_store_ != NULL) {
      if (alternative_store_->Has(key)) {
        *(response->mutable_alternative_value_holder()) = node_info_;
        response->set_result(kRpcResultSuccess);
        response->set_node_id(node_info_.node_id());
        done->Run();
        return;
      }
    }
    if (pdatastore_->LoadItem(key, &values_str)) {
      if (node_hasRSAkeys_) {
        for (unsigned int i = 0; i < values_str.size(); i++) {
          SignedValue *signed_value = response->add_signed_values();
          signed_value->ParseFromString(values_str[i]);
        }
      } else {
        for (unsigned int i = 0; i < values_str.size(); i++)
          response->add_values(values_str[i]);
      }
      response->set_result(kRpcResultSuccess);
      rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
      if (ctrl != NULL) {
        add_contact_(sender, ctrl->rtt(), false);
      } else  {
        add_contact_(sender, 0.0, false);
      }
    } else {
      FindNode(controller, request, response, done);
      return;
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Store(google::protobuf::RpcController *controller,
                       const StoreRequest *request, StoreResponse *response,
                       google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
                                  (controller);
  if (!CheckStoreRequest(request, &sender)) {
    response->set_result(kRpcResultFailure);
  } else if (node_hasRSAkeys_) {
    if (signature_validator_ == NULL ||
        !signature_validator_->ValidateSignerId(
            request->signed_request().signer_id(),
            request->signed_request().public_key(),
            request->signed_request().signed_public_key()) ||
        !signature_validator_->ValidateRequest(
            request->signed_request().signed_request(),
            request->signed_request().public_key(),
            request->signed_request().signed_public_key(), request->key())) {
      DLOG(WARNING) << "Failed to validate Store request for kad value"
                    << std::endl;
      response->set_result(kRpcResultFailure);
    } else {
      StoreValueLocal(request->key(), request->sig_value(), sender,
                      request->ttl(), request->publish(), response, ctrl);
    }
  } else {
    StoreValueLocal(request->key(), request->value(), sender, request->ttl(),
                    request->publish(), response, ctrl);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Downlist(google::protobuf::RpcController *controller,
                          const DownlistRequest *request,
                          DownlistResponse *response,
                          google::protobuf::Closure *done) {
  if (!node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (GetSender(request->sender_info(), &sender)) {
    for (int i = 0; i < request->downlist_size(); ++i) {
      Contact dead_node;
      if (!dead_node.ParseFromString(request->downlist(i)))
        continue;
    // A sophisticated attacker possibly send a random downlist. We only verify
    // the offline status of the nodes in our routing table.
      Contact contact_to_ping;
      response->set_result(kRpcResultSuccess);
      if (get_contact_(dead_node.node_id(), &contact_to_ping)) {
        ping_(dead_node, boost::bind(&downlist_ping_cb, _1));
      }
    }
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

bool KadService::GetSender(const ContactInfo &sender_info, Contact *sender) {
  std::string ser_info(sender_info.SerializeAsString());
  return sender->ParseFromString(ser_info);
}

void KadService::Bootstrap_NatDetectionPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  if (response->IsInitialized() && response->result() == kRpcResultSuccess) {
    data.response->set_result(kRpcResultSuccess);
  } else {
    data.response->set_result(kRpcResultFailure);
  }
  delete data.controller;
  delete response;
  data.done->Run();
}

void KadService::Bootstrap_NatDetectionRzPing(
    const NatDetectionPingResponse *response,
    struct NatDetectionPingData data) {
  Bootstrap_NatDetectionPing(response, data);
}

void KadService::NatDetection(google::protobuf::RpcController *controller,
                              const NatDetectionRequest *request,
                              NatDetectionResponse *response,
                              google::protobuf::Closure *done) {
  if (request->IsInitialized()) {
    if (request->type() == 1) {
      // C tries to ping A
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer())) {
        NatDetectionPingResponse *resp = new NatDetectionPingResponse;
        struct NatDetectionPingData data = {request->sender_id(), response,
            done, NULL};
        rpcprotocol::Controller *ctrler =
            static_cast<rpcprotocol::Controller*>(controller);
        data.controller = new rpcprotocol::Controller;
        data.controller->set_transport_id(ctrler->transport_id());
        google::protobuf::Closure *done =
            google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*, struct NatDetectionPingData>
            (this, &KadService::Bootstrap_NatDetectionPing, resp, data);
        nat_rpcs_.NatDetectionPing(node_a.host_ip(), node_a.host_port(), "", 0,
            resp, data.controller, done);
        return;
      }
    } else if (request->type() == 2) {
      // C tries a rendezvous to A with B as rendezvous
      Contact node_b;
      Contact node_a;
      if (node_a.ParseFromString(request->newcomer()) &&
          node_b.ParseFromString(request->bootstrap_node()) &&
          node_a.node_id().String() != kClientId) {
        NatDetectionPingResponse *resp = new NatDetectionPingResponse;
        struct NatDetectionPingData data =
          {request->sender_id(), response, done, NULL};
        rpcprotocol::Controller *ctrler =
            static_cast<rpcprotocol::Controller*>(controller);
        data.controller = new rpcprotocol::Controller;
        data.controller->set_transport_id(ctrler->transport_id());
        google::protobuf::Closure *done =
          google::protobuf::NewCallback<KadService,
            const NatDetectionPingResponse*,
            struct NatDetectionPingData>(this,
              &KadService::Bootstrap_NatDetectionRzPing,
              resp,
              data);
        nat_rpcs_.NatDetectionPing(node_a.host_ip(), node_a.host_port(),
            node_a.rendezvous_ip(), node_a.rendezvous_port(), resp,
            data.controller, done);
        return;
      }
    }
  }
  response->set_result(kRpcResultFailure);
  done->Run();
}

void KadService::NatDetectionPing(google::protobuf::RpcController *,
                                  const NatDetectionPingRequest *request,
                                  NatDetectionPingResponse *response,
                                  google::protobuf::Closure *done) {
  Contact sender;
  if (!request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
  } else if (request->ping() == "nat_detection_ping") {
    response->set_echo("pong");
    response->set_result(kRpcResultSuccess);
  } else {
    response->set_result(kRpcResultFailure);
  }
  response->set_node_id(node_info_.node_id());
  done->Run();
}

void KadService::Bootstrap(google::protobuf::RpcController *controller,
                           const BootstrapRequest *request,
                           BootstrapResponse *response,
                           google::protobuf::Closure *done) {
  if (!request->IsInitialized() || !node_joined_) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  // Checking if it is a client to return its external ip/port
  if (static_cast<NodeType>(request->node_type()) == CLIENT) {
    response->set_bootstrap_id(node_info_.node_id());
    response->set_newcomer_ext_ip(request->newcomer_ext_ip());
    response->set_newcomer_ext_port(request->newcomer_ext_port());
    response->set_result(kRpcResultSuccess);
    done->Run();
    return;
  }
  Contact newcomer;
  // set rendezvous IP/Port
  if (request->newcomer_ext_ip() == request->newcomer_local_ip()
      &&request->newcomer_ext_port() == request->newcomer_local_port()) {
    // Newcomer is directly connected to the Internet
    newcomer = Contact(request->newcomer_id(), request->newcomer_local_ip(),
        request->newcomer_local_port(), request->newcomer_local_ip(),
        request->newcomer_local_port());
  } else {
    // Behind firewall
    newcomer = Contact(request->newcomer_id(), request->newcomer_ext_ip(),
          request->newcomer_ext_port(), request->newcomer_local_ip(),
          request->newcomer_local_port(), node_info_.ip(), node_info_.port());
  }
  response->set_bootstrap_id(node_info_.node_id());
  response->set_newcomer_ext_ip(request->newcomer_ext_ip());
  response->set_newcomer_ext_port(request->newcomer_ext_port());
  response->set_result(kRpcResultSuccess);

  std::string this_node_str(node_info_.SerializeAsString());
  Contact node_c;
  std::vector<Contact> ex_contacs;
  ex_contacs.push_back(newcomer);
  struct NatDetectionData data = {newcomer, this_node_str, node_c,
                                  response, done,
                                  static_cast<rpcprotocol::Controller*>
                                      (controller),
                                  ex_contacs};
  SendNatDetection(data);
}

void KadService::SendNatDetection(NatDetectionData data) {
  std::vector<Contact> random_contacts;
  get_random_contacts_(1, data.ex_contacts, &random_contacts);
  if (random_contacts.size() != 1) {
    if (data.ex_contacts.size() > 1) {
      data.response->set_result(kRpcResultFailure);
    }
    for (size_t n = 0; n < data.ex_contacts.size(); ++n) {
      // remove contact from routing table
      remove_contact_(data.ex_contacts[n].node_id());
    }
    data.done->Run();
    return;
  } else {
    Contact node_c = random_contacts.front();
    data.node_c = node_c;
    // Node B asks C to try ping A
    std::string newcomer_str;
    data.newcomer.SerialiseToString(&newcomer_str);
    rpcprotocol::Controller *temp_controller =
        static_cast<rpcprotocol::Controller*>(data.controller);
    boost::int16_t temp_transport_id(temp_controller->transport_id());
    data.controller = new rpcprotocol::Controller;
    data.controller->set_transport_id(temp_transport_id);
    NatDetectionResponse *resp = new NatDetectionResponse;
    google::protobuf::Closure *done = google::protobuf::NewCallback
        <KadService, const NatDetectionResponse*, struct NatDetectionData>
        (this, &KadService::Bootstrap_NatDetection, resp, data);
    nat_rpcs_.NatDetection(newcomer_str, data.bootstrap_node, 1,
                           node_info_.node_id(), node_c.host_ip(),
                           node_c.host_port(), node_c.rendezvous_ip(),
                           node_c.rendezvous_port(), resp, data.controller,
                           done);
  }
}

bool KadService::CheckStoreRequest(const StoreRequest *request,
                                   Contact *sender) {
  if (!request->IsInitialized())
    return false;
  if (node_hasRSAkeys_) {
    if (!request->has_signed_request() || !request->has_sig_value())
      return false;
  } else {
    if (!request->has_value())
      return false;
  }
  return GetSender(request->sender_info(), sender);
}

void KadService::StoreValueLocal(const std::string &key,
                                 const std::string &value, Contact sender,
                                 const boost::int32_t &ttl,
                                 const bool &publish, StoreResponse *response,
                                 rpcprotocol::Controller *ctrl) {
  bool result;
  if (publish) {
    result = pdatastore_->StoreItem(key, value, ttl, false);
  } else {
    std::string ser_del_request;
    result = pdatastore_->RefreshItem(key, value, &ser_del_request);
    if (!result && ser_del_request.empty()) {
      result = pdatastore_->StoreItem(key, value, ttl, false);
    } else if (!result && !ser_del_request.empty()) {
      SignedRequest *req = response->mutable_signed_request();
      req->ParseFromString(ser_del_request);
    }
  }
  if (result) {
    response->set_result(kRpcResultSuccess);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
}

void KadService::StoreValueLocal(const std::string &key,
                                 const SignedValue &value, Contact sender,
                                 const boost::int32_t &ttl, const bool &publish,
                                 StoreResponse *response,
                                 rpcprotocol::Controller *ctrl) {
  bool result, hashable;
  std::string ser_value(value.value() + value.value_signature());
  if (publish) {
    if (CanStoreSignedValueHashable(key, ser_value, &hashable)) {
      result = pdatastore_->StoreItem(key, value.SerializeAsString(), ttl,
                                      hashable);
      if (!result) {
        DLOG(WARNING) << "pdatastore_->StoreItem 1 Failed.";
      }
    } else {
      DLOG(WARNING) << "CanStoreSignedValueHashable Failed.";
      result = false;
    }
  } else {
    std::string ser_del_request;
    result = pdatastore_->RefreshItem(key, value.SerializeAsString(),
                                      &ser_del_request);

    if (!result && CanStoreSignedValueHashable(key, ser_value, &hashable) &&
        ser_del_request.empty()) {
      result = pdatastore_->StoreItem(key, value.SerializeAsString(), ttl,
                                      hashable);
      if (!result)
        DLOG(WARNING) << "pdatastore_->StoreItem 2 Failed.";
    } else if (!result && !ser_del_request.empty()) {
      SignedRequest *req = response->mutable_signed_request();
      req->ParseFromString(ser_del_request);
        DLOG(WARNING) << "Weird Failed. - adding signed req to resp.";
    } else if (!result) {
        DLOG(WARNING) << "pdatastore_->RefreshItem Failed.";
    }
  }
  if (result) {
    response->set_result(kRpcResultSuccess);
    if (ctrl != NULL) {
      add_contact_(sender, ctrl->rtt(), false);
    } else {
      add_contact_(sender, 0.0, false);
    }
  } else {
    response->set_result(kRpcResultFailure);
  }
}

bool KadService::CanStoreSignedValueHashable(const std::string &key,
                                             const std::string &value,
                                             bool *hashable) {
  std::vector< std::pair<std::string, bool> > attr;
  attr = pdatastore_->LoadKeyAppendableAttr(key);
  *hashable = false;
  if (attr.empty()) {
    crypto::Crypto cobj;
    cobj.set_hash_algorithm(crypto::SHA_512);
    if (key == cobj.Hash(value, "", crypto::STRING_STRING, false))
      *hashable = true;
  } else if (attr.size() == 1) {
    *hashable = attr[0].second;
    if (*hashable && value != attr[0].first) {
      return false;
    }
  }
  return true;
}

void KadService::Delete(google::protobuf::RpcController *controller,
                        const DeleteRequest *request, DeleteResponse *response,
                        google::protobuf::Closure *done) {
  // only node with RSAkeys can delete values
  if (!node_joined_ || !node_hasRSAkeys_ || signature_validator_ == NULL ||
      !request->IsInitialized()) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }

  response->set_node_id(node_info_.node_id());
  // validating request
  if (signature_validator_ == NULL ||
        !signature_validator_->ValidateSignerId(
          request->signed_request().signer_id(),
          request->signed_request().public_key(),
          request->signed_request().signed_public_key()) ||
        !signature_validator_->ValidateRequest(
          request->signed_request().signed_request(),
          request->signed_request().public_key(),
          request->signed_request().signed_public_key(), request->key())) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }

  // only the signer of the value can delete it
  std::vector<std::string> values_str;
  if (!pdatastore_->LoadItem(request->key(), &values_str)) {
    response->set_result(kRpcResultFailure);
    done->Run();
    return;
  }
  crypto::Crypto cobj;
  if (cobj.AsymCheckSig(request->value().value(),
      request->value().value_signature(),
      request->signed_request().public_key(), crypto::STRING_STRING)) {
    Contact sender;
    if (pdatastore_->MarkForDeletion(request->key(),
        request->value().SerializeAsString(),
        request->signed_request().SerializeAsString()) &&
        GetSender(request->sender_info(), &sender)) {
      rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
        (controller);
      if (ctrl != NULL)
        add_contact_(sender, ctrl->rtt(), false);
      else
        add_contact_(sender, 0.0, false);
      response->set_result(kRpcResultSuccess);
      done->Run();
      return;
    }
  }
  response->set_result(kRpcResultFailure);
  done->Run();
}

void KadService::Update(google::protobuf::RpcController *controller,
                        const UpdateRequest *request,
                        UpdateResponse *response,
                        google::protobuf::Closure *done) {
  // only node with RSAkeys can update values
  response->set_node_id(node_info_.node_id());
  response->set_result(kRpcResultFailure);

  if (!node_joined_ || !node_hasRSAkeys_ || !request->IsInitialized()) {
    done->Run();
#ifdef DEBUG
    if (!node_joined_)
      DLOG(WARNING) << "KadService::Update - !node_joined_" << std::endl;
    if (!node_hasRSAkeys_)
      DLOG(WARNING) << "KadService::Update - !node_hasRSAkeys_" << std::endl;
    if (!request->IsInitialized())
      DLOG(WARNING) << "KadService::Update - !request->IsInitialized()" <<
                       std::endl;
#endif
    return;
  }

  // validating request
  if (signature_validator_ == NULL ||
      !signature_validator_->ValidateSignerId(
          request->request().signer_id(),
          request->request().public_key(),
          request->request().signed_public_key()) ||
       !signature_validator_->ValidateRequest(
          request->request().signed_request(),
          request->request().public_key(),
          request->request().signed_public_key(), request->key())) {
    done->Run();
#ifdef DEBUG
    if (signature_validator_ == NULL)
      DLOG(WARNING) << "KadService::Update - signature_validator_ == NULL" <<
                       std::endl;
    if (!signature_validator_->ValidateSignerId(
          request->request().signer_id(),
          request->request().public_key(),
          request->request().signed_public_key()))
      DLOG(WARNING) << "KadService::Update - Failed ValidateSignerId" <<
                 std::endl;
    if (!signature_validator_->ValidateRequest(
          request->request().signed_request(),
          request->request().public_key(),
          request->request().signed_public_key(), request->key()))
      DLOG(WARNING) << "KadService::Update - Failed ValidateRequest" <<
                 std::endl;
#endif
    return;
  }

  // Check the key exists
  std::vector<std::string> values_str;
  if (!pdatastore_->LoadItem(request->key(), &values_str)) {
    done->Run();
    DLOG(WARNING) << "KadService::Update - Didn't find key" << std::endl;
    return;
  }

  // Check the value to be updated exists
  bool found(false);
  std::string ser_sv(request->old_value().SerializeAsString());
  for (size_t n = 0; n < values_str.size() && !found; ++n) {
    if (ser_sv == values_str[n]) {
      found = true;
    }
  }

  if (!found) {
    done->Run();
    DLOG(WARNING) << "KadService::Update - Didn't find value" << std::endl;
    return;
  }

  crypto::Crypto cobj;
  if (!cobj.AsymCheckSig(request->new_value().value(),
                         request->new_value().value_signature(),
                         request->request().public_key(),
                         crypto::STRING_STRING)) {
    done->Run();
    DLOG(WARNING) << "KadService::Update - New value doesn't validate" <<
                     std::endl;
    return;
  }

  SignedValue sv;
  sv.ParseFromString(ser_sv);
  if (!cobj.AsymCheckSig(sv.value(),
                         sv.value_signature(),
                         request->request().public_key(),
                         crypto::STRING_STRING)) {
    done->Run();
    DLOG(WARNING) << "KadService::Update - Old value doesn't validate" <<
                     std::endl;
    return;
  }

/*******************************************************************************
This code would check if the current value is hashable, and accept only
hashable replacement values.

//  bool current_hashable(request->key() ==
//                        cobj.Hash(sv.value() + sv.value_signature(), "",
//                                  crypto::STRING_STRING, false));
//  bool new_hashable(request->key() ==
//                    cobj.Hash(request->new_value().value() +
//                                  request->new_value().value_signature(),
//                              "", crypto::STRING_STRING, false));
//  if (current_hashable && !new_hashable && values_str.size() == size_t(1)) {
//    done->Run();
//    DLOG(WARNING) << "KadService::Update - Hashable tags don't match" <<
//                     std::endl;
//    return;
//  }
*******************************************************************************/

  bool new_hashable(request->key() ==
                    cobj.Hash(request->new_value().value() +
                                  request->new_value().value_signature(),
                              "", crypto::STRING_STRING, false));
  Contact sender;
  if (!pdatastore_->UpdateItem(request->key(),
                               request->old_value().SerializeAsString(),
                               request->new_value().SerializeAsString(),
                               request->ttl(), new_hashable)) {
    done->Run();
    DLOG(WARNING) << "KadService::Update - Failed UpdateItem" << std::endl;
    return;
  }

  if (GetSender(request->sender_info(), &sender)) {
    rpcprotocol::Controller *ctrl = static_cast<rpcprotocol::Controller*>
                                    (controller);
    if (ctrl != NULL)
      add_contact_(sender, ctrl->rtt(), false);
    else
      add_contact_(sender, 0.0, false);
    response->set_result(kRpcResultSuccess);
  } else {
    DLOG(WARNING) << "KadService::Update - Failed to add_contact_" << std::endl;
  }

  done->Run();
}

}  // namespace kad
