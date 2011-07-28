/*******************************************************************************
 *  Copyright 2011 maidsafe.net limited                                        *
 *                                                                             *
 *  The following source code is property of maidsafe.net limited and is not   *
 *  meant for external use.  The use of this code is governed by the license   *
 *  file LICENSE.TXT found in the root of this directory and also on           *
 *  www.maidsafe.net.                                                          *
 *                                                                             *
 *  You are not free to copy, amend or otherwise use this source code without  *
 *  the explicit written permission of the board of directors of maidsafe.net. *
 ***************************************************************************//**
 * @file  node_detail.h
 * @brief Class for serialisation of node related objects.
 * @date  2011-07-12
 */

#ifndef MAIDSAFE_PD_VAULT_NODE_DETAIL_H_
#define MAIDSAFE_PD_VAULT_NODE_DETAIL_H_

#include <string>
#include <vector>

#include "boost/asio/ip/address.hpp"
#include "boost/serialization/nvp.hpp"
#include "boost/serialization/vector.hpp"

#include "maidsafe/dht/kademlia/node_id.h"
#include "maidsafe/dht/kademlia/contact.h"

namespace boost {

namespace serialization {

template <class Archive>
void serialize(Archive & ar, maidsafe::dht::kademlia::NodeId & node_id,
               const unsigned int /*version*/) {
  std::string node_id_local;
  if (Archive::is_saving::value) {
    node_id_local = maidsafe::EncodeToBase64(node_id.String());
  }
  ar & boost::serialization::make_nvp("node_id", node_id_local);
  if (Archive::is_loading::value) {
    node_id = maidsafe::dht::kademlia::NodeId(
                  maidsafe::DecodeFromBase64(node_id_local));
  }
}

template <class Archive>
void serialize(Archive & ar, maidsafe::dht::transport::Endpoint & endpoint,
               const unsigned int /*version*/) {
  std::string ip;
  boost::uint16_t port = endpoint.port;
  if (Archive::is_saving::value) {
    ip = endpoint.ip.to_string();
    port = endpoint.port;
  }
  ar & boost::serialization::make_nvp("ip", ip);
  ar & boost::serialization::make_nvp("port", port);
  if (Archive::is_loading::value) {
    boost::system::error_code ec;
    endpoint.ip = boost::asio::ip::address::from_string(ip, ec);
    if (ec)
      port = 0;
    endpoint.port = port;
  }
}

template <class Archive>
void serialize(Archive & ar, maidsafe::dht::kademlia::Contact & contact,
               const unsigned int /*version*/) {
  maidsafe::dht::kademlia::NodeId node_id;
  maidsafe::dht::transport::Endpoint endpoint;
  std::vector<maidsafe::dht::transport::Endpoint> local_endpoints;
  maidsafe::dht::transport::Endpoint rendezvous_endpoint;
  bool tcp443;
  bool tcp80;
  std::string public_key_id;
  std::string public_key;
  std::string other_info;

  if (Archive::is_saving::value) {
    node_id = contact.node_id();
    endpoint = contact.endpoint();
    local_endpoints = contact.local_endpoints();
    rendezvous_endpoint = contact.rendezvous_endpoint();
    tcp443 = contact.tcp443endpoint().port == 443;
    tcp80 = contact.tcp80endpoint().port == 80;
    public_key_id = maidsafe::EncodeToBase64(contact.public_key_id());
    public_key = maidsafe::EncodeToBase64(contact.public_key());
    other_info = contact.other_info();
  }

  ar & make_nvp("node_id", node_id);
  ar & make_nvp("endpoint", endpoint);
  ar & make_nvp("local_endpoints", local_endpoints);
  ar & make_nvp("rendezvous_endpoint", rendezvous_endpoint);
  ar & make_nvp("tcp443", tcp443);
  ar & make_nvp("tcp80", tcp80);
  ar & make_nvp("public_key_id", public_key_id);
  ar & make_nvp("public_key", public_key);
  ar & make_nvp("other_info", other_info);

  if (Archive::is_loading::value) {
    public_key_id = maidsafe::DecodeFromBase64(public_key_id);
    public_key = maidsafe::DecodeFromBase64(public_key);
    contact = maidsafe::dht::kademlia::Contact(node_id, endpoint,
                                               local_endpoints,
                                               rendezvous_endpoint, tcp443,
                                               tcp80, public_key_id,
                                               public_key, other_info);
  }
}

}  // namespace serialization

}  // namespace boost

#endif  // MAIDSAFE_PD_VAULT_NODE_DETAIL_H_
