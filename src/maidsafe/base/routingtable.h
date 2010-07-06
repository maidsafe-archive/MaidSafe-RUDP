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

#ifndef MAIDSAFE_BASE_ROUTINGTABLE_H_
#define MAIDSAFE_BASE_ROUTINGTABLE_H_

#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <boost/multi_index_container.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>

#ifdef WIN32
#include <shlobj.h>
#endif
#include <maidsafe/maidsafe-dht_config.h>
#include <functional>
#include <list>
#include <map>
#include <set>
#include <string>


namespace base {

struct PublicRoutingTableTuple {
  PublicRoutingTableTuple()
      : kademlia_id(), host_ip(), rendezvous_ip(), public_key(), host_port(0),
        rendezvous_port(0), rank(0), rtt(0), space(0),
        connection_type(kad::UNKNOWN) {}
  PublicRoutingTableTuple(const std::string &kademlia_id,
                          const std::string &host_ip,
                          const boost::uint16_t &host_port,
                          const std::string &rendezvous_ip,
                          const boost::uint16_t &rendezvous_port,
                          const std::string &public_key,
                          const float &rtt,
                          const boost::uint16_t &rank,
                          const boost::uint32_t &space)
      : kademlia_id(kademlia_id), host_ip(host_ip),
        rendezvous_ip(rendezvous_ip), public_key(public_key),
        host_port(host_port), rendezvous_port(rendezvous_port), rank(rank),
        rtt(rtt), space(space), connection_type(kad::UNKNOWN) {}
  PublicRoutingTableTuple(const PublicRoutingTableTuple &tuple)
      : kademlia_id(tuple.kademlia_id), host_ip(tuple.host_ip),
        rendezvous_ip(tuple.rendezvous_ip), public_key(tuple.public_key),
        host_port(tuple.host_port), rendezvous_port(tuple.rendezvous_port),
        rank(tuple.rank), rtt(tuple.rtt), space(tuple.space),
        connection_type(tuple.connection_type) {}
  PublicRoutingTableTuple& operator=(const PublicRoutingTableTuple &tuple) {
    kademlia_id = tuple.kademlia_id;
    host_ip = tuple.host_ip;
    host_port = tuple.host_port;
    rendezvous_ip = tuple.rendezvous_ip;
    rendezvous_port = tuple.rendezvous_port;
    public_key = tuple.public_key;
    rtt = tuple.rtt;
    rank = tuple.rank;
    space = tuple.space;
    connection_type = tuple.connection_type;
    return *this;
  }
  std::string kademlia_id, host_ip, rendezvous_ip, public_key;
  boost::uint16_t host_port, rendezvous_port, rank;
  float rtt;
  boost::uint32_t space;
  kad::ConnectionType connection_type;
};

// Tags
struct t_ip_port {};
struct t_key {};
struct t_rtt {};
struct t_rank {};

typedef boost::multi_index_container<
  PublicRoutingTableTuple,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<t_ip_port>,
      boost::multi_index::composite_key<
        PublicRoutingTableTuple,
        BOOST_MULTI_INDEX_MEMBER(PublicRoutingTableTuple, std::string, host_ip),
        BOOST_MULTI_INDEX_MEMBER(PublicRoutingTableTuple, boost::uint16_t,
                                 host_port)
      >
    >,
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<t_key>,
      BOOST_MULTI_INDEX_MEMBER(PublicRoutingTableTuple, std::string,
                               kademlia_id)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_rtt>,
      BOOST_MULTI_INDEX_MEMBER(PublicRoutingTableTuple, float, rtt)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_rank>,
      BOOST_MULTI_INDEX_MEMBER(PublicRoutingTableTuple, boost::uint16_t, rank),
      std::greater<boost::uint16_t>
    >
  >
> routingtable;

class PublicRoutingTableHandler {
 public:
  PublicRoutingTableHandler() : routingtable_(), mutex_() {}
  void Clear() {
    boost::mutex::scoped_lock guard(mutex_);
    routingtable_.clear();
  }
  int GetTupleInfo(const std::string &kademlia_id,
                   PublicRoutingTableTuple *tuple);
  int GetTupleInfo(const std::string &host_ip, const boost::uint16_t &host_port,
                   PublicRoutingTableTuple *tuple);
  int GetClosestRtt(const float &rtt, const std::set<std::string> &exclude_ids,
                    PublicRoutingTableTuple *tuple);
  int GetClosestContacts(const std::string &target_key,
                         const boost::uint32_t &count,
                         std::list<PublicRoutingTableTuple> *tuples);
  int AddTuple(base::PublicRoutingTableTuple tuple);
  int DeleteTupleByKadId(const std::string &kademlia_id);
  int UpdateHostIp(const std::string &kademlia_id,
                   const std::string &new_host_ip);
  int UpdateHostPort(const std::string &kademlia_id,
                     const boost::uint16_t &new_host_port);
  int UpdateRendezvousIp(const std::string &kademlia_id,
                         const std::string &new_rv_ip);
  int UpdateRendezvousPort(const std::string &kademlia_id,
                           const boost::uint16_t &new_rv_port);
  int UpdatePublicKey(const std::string &kademlia_id,
                      const std::string &new_public_key);
  int UpdateRtt(const std::string &kademlia_id, const float &new_rtt);
  int UpdateRank(const std::string &kademlia_id,
                 const boost::uint16_t &new_rank);
  int UpdateSpace(const std::string &kademlia_id,
                  const boost::uint32_t &new_space);
  int ContactLocal(const std::string &kademlia_id);
  int UpdateContactLocal(const std::string &kademlia_id,
                         const std::string &host_ip,
                         const kad::ConnectionType &new_contact_type);
  int UpdateLocalToUnknown(const std::string &ip, const boost::uint16_t &port);
 private:
  PublicRoutingTableHandler(const PublicRoutingTableHandler&);
  PublicRoutingTableHandler &operator=(const PublicRoutingTableHandler&);
  bool KadCloser(const PublicRoutingTableTuple &pdrtt1,
                 const PublicRoutingTableTuple &pdrtt2,
                 const std::string &target_key) const;
  routingtable routingtable_;
  boost::mutex mutex_;
};

class PublicRoutingTable {
 public:
  static PublicRoutingTable* GetInstance();
  boost::shared_ptr<PublicRoutingTableHandler> operator[] (
      const std::string &name);
 private:
  PublicRoutingTable() : pdroutingtablehdls_() {}
  explicit PublicRoutingTable(PublicRoutingTable const&);
  static PublicRoutingTable *single;
  void operator=(PublicRoutingTable const&);
  std::map< std::string, boost::shared_ptr<PublicRoutingTableHandler> >
      pdroutingtablehdls_;
};

}  // namespace base

#endif  // MAIDSAFE_BASE_ROUTINGTABLE_H_
