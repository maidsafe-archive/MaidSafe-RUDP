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

#include "maidsafe/base/routingtable.h"
#include <boost/filesystem.hpp>
#include <boost/foreach.hpp>
#include <algorithm>
#include <vector>
#include "maidsafe/kademlia/kadid.h"

namespace base {

int PublicRoutingTableHandler::GetTupleInfo(const std::string &kademlia_id,
                                            PublicRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  *tuple = *it;
  return 0;
}

int PublicRoutingTableHandler::GetTupleInfo(const std::string &host_ip,
                                            const boost::uint16_t &host_port,
                                            PublicRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::iterator it = routingtable_.find(boost::make_tuple(host_ip,
      host_port));
  if (it == routingtable_.end())
    return 1;
  *tuple = *it;
  return 0;
}

int PublicRoutingTableHandler::GetClosestRtt(
    const float &rtt,
    const std::set<std::string> &exclude_ids,
    PublicRoutingTableTuple *tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_rtt>::type& rtt_indx = routingtable_.get<t_rtt>();
  routingtable::index<t_rtt>::type::iterator indx0 = rtt_indx.lower_bound(rtt);
  routingtable::index<t_rtt>::type::iterator indx1 = rtt_indx.upper_bound(rtt);
  bool found_closest = false;
  float distance_ideal = -1;
  std::set<std::string>::const_iterator set_it;
  while (indx0 != rtt_indx.end() && !found_closest) {
    set_it = exclude_ids.find(indx0->kademlia_id);
    if (set_it == exclude_ids.end()) {
      found_closest = true;
      distance_ideal = indx0->rtt - rtt;
      *tuple = *indx0;
    }
    ++indx0;
  }
  found_closest = false;
  while (indx1 != rtt_indx.begin() && !found_closest) {
    --indx1;
    set_it = exclude_ids.find(indx1->kademlia_id);
    if (set_it == exclude_ids.end()) {
      found_closest = true;
      if (distance_ideal < 0.0 || distance_ideal > (rtt - indx1->rtt))
        *tuple = *indx1;
    }
  }
  if (distance_ideal < 0.0)
  // couldn't find a tuple with rtt close to ideal_rtt
    return 1;
  return 0;
}

bool PublicRoutingTableHandler::KadCloser(const PublicRoutingTableTuple &pdrtt1,
                                          const PublicRoutingTableTuple &pdrtt2,
                                          const std::string &target_key) const {
  kad::KadId id1(pdrtt1.kademlia_id), id2(pdrtt2.kademlia_id),
      target_id(target_key);
  return kad::KadId::CloserToTarget(id1, id2, target_id);
}

int PublicRoutingTableHandler::GetClosestContacts(
    const std::string &target_key,
    const boost::uint32_t &count,
    std::list<PublicRoutingTableTuple> *tuples) {
  if (target_key.size() != kad::kKeySizeBytes || tuples == NULL)
    return -1;
  boost::mutex::scoped_lock guard(mutex_);
  std::vector< boost::reference_wrapper<const PublicRoutingTableTuple> > temp;
  temp.reserve(routingtable_.size());
  BOOST_FOREACH(const PublicRoutingTableTuple &pdrtt, routingtable_)temp.
      push_back(boost::cref(pdrtt));
  std::sort(temp.begin(), temp.end(), boost::bind(
      &PublicRoutingTableHandler::KadCloser, this, _1, _2, target_key));
  if (count == 0 || count > routingtable_.size()) {
    tuples->assign(temp.begin(), temp.end());
  } else {
    std::vector< boost::reference_wrapper<
                 const PublicRoutingTableTuple> >::iterator itr = temp.begin();
    itr += count;
    tuples->assign(temp.begin(), itr);
  }
  return 0;
}

int PublicRoutingTableHandler::AddTuple(base::PublicRoutingTableTuple tuple) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it =
      key_indx.find(tuple.kademlia_id);
  if (it == key_indx.end()) {
    key_indx.insert(tuple);
  } else {
    tuple.connection_type = it->connection_type;
    if (!(tuple.rtt > 0) && !(tuple.rtt < 0))
      tuple.rtt = it->rtt;
    key_indx.replace(it, tuple);
  }
  return 0;
}

int PublicRoutingTableHandler::DeleteTupleByKadId(
    const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  key_indx.erase(it);
  return 0;
}

int PublicRoutingTableHandler::UpdateHostIp(const std::string &kademlia_id,
                                            const std::string &new_host_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.host_ip = new_host_ip;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateHostPort(
    const std::string &kademlia_id,
    const boost::uint16_t &new_host_port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.host_port = new_host_port;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateRendezvousIp(
    const std::string &kademlia_id,
    const std::string &new_rv_ip) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.rendezvous_ip = new_rv_ip;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateRendezvousPort(
    const std::string &kademlia_id,
    const boost::uint16_t &new_rv_port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.rendezvous_port = new_rv_port;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdatePublicKey(
    const std::string &kademlia_id,
    const std::string &new_public_key) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.public_key = new_public_key;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateRtt(const std::string &kademlia_id,
                                         const float &new_rtt) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.rtt = new_rtt;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateRank(const std::string &kademlia_id,
                                          const boost::uint16_t &new_rank) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.rank = new_rank;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateSpace(const std::string &kademlia_id,
                                           const boost::uint32_t &new_space) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.space = new_space;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::ContactLocal(const std::string &kademlia_id) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 2;
  return it->connection_type;
}

int PublicRoutingTableHandler::UpdateContactLocal(
    const std::string &kademlia_id,
    const std::string &host_ip,
    const kad::ConnectionType &new_contact_type) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::index<t_key>::type& key_indx = routingtable_.get<t_key>();
  routingtable::index<t_key>::type::iterator it = key_indx.find(kademlia_id);
  if (it == key_indx.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.host_ip = host_ip;
  new_tuple.connection_type = new_contact_type;
  key_indx.replace(it, new_tuple);
  return 0;
}

int PublicRoutingTableHandler::UpdateLocalToUnknown(
    const std::string &ip,
    const boost::uint16_t &port) {
  boost::mutex::scoped_lock guard(mutex_);
  routingtable::iterator it = routingtable_.find(boost::make_tuple(ip, port));
  if (it == routingtable_.end())
    return 1;
  PublicRoutingTableTuple new_tuple = *it;
  new_tuple.connection_type = kad::UNKNOWN;
  routingtable_.replace(it, new_tuple);
  return 0;
}

PublicRoutingTable* PublicRoutingTable::single = 0;
boost::mutex pdrt_mutex;

PublicRoutingTable* PublicRoutingTable::GetInstance() {
  if (single == 0) {
    boost::mutex::scoped_lock lock(pdrt_mutex);
    if (single == 0)
      single = new PublicRoutingTable();
  }
  return single;
}

boost::shared_ptr<PublicRoutingTableHandler> PublicRoutingTable::operator[] (
    const std::string &name) {
  std::map<std::string,
           boost::shared_ptr<PublicRoutingTableHandler> >::iterator it;
  it = pdroutingtablehdls_.find(name);
  if (it == pdroutingtablehdls_.end()) {
    pdroutingtablehdls_.insert(std::pair<std::string,
        boost::shared_ptr<PublicRoutingTableHandler> >(name,
        boost::shared_ptr<PublicRoutingTableHandler>(
            new PublicRoutingTableHandler)));
    return pdroutingtablehdls_[name];
  }
  return it->second;
}
}  // namespace base
