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

#ifndef MAIDSAFE_KADEMLIA_DATASTORE_H_
#define MAIDSAFE_KADEMLIA_DATASTORE_H_

#include <boost/multi_index_container.hpp>
#include <boost/multi_index/ordered_index.hpp>
#include <boost/multi_index/identity.hpp>
#include <boost/multi_index/member.hpp>
#include <boost/multi_index/composite_key.hpp>
#include <boost/cstdint.hpp>
#include <boost/thread/mutex.hpp>
#include <string>
#include <vector>
#include <set>
#include <utility>

namespace kad {
// This class implements physical storage (for data published and fetched via
// the RPCs) for the Kademlia DHT. Boost::multiindex are used

enum delete_status {
  NOT_DELETED,
  MARKED_FOR_DELETION,
  DELETED
};

struct refresh_value {
  std::string key_, value_;
  boost::int32_t ttl_;
  delete_status del_status_;
  refresh_value(const std::string &key, const std::string &value, const
                boost::int32_t &ttl)
      : key_(key), value_(value), ttl_(ttl), del_status_(NOT_DELETED) {}
  refresh_value(const std::string &key, const std::string &value, const
                delete_status &del_status)
      : key_(key), value_(value), ttl_(0), del_status_(del_status) {}
};

struct key_value_tuple {
  std::string key_, value_, ser_delete_req_;
  boost::uint32_t last_refresh_time_, expire_time_;
  boost::int32_t ttl_;
  bool hashable_;
  delete_status del_status_;

  key_value_tuple(const std::string &key, const std::string &value,
                  const boost::uint32_t &last_refresh_time,
                  const boost::uint32_t &expire_time, const boost::int32_t &ttl,
                  const bool &hashable)
      : key_(key), value_(value), ser_delete_req_(),
        last_refresh_time_(last_refresh_time), expire_time_(expire_time),
        ttl_(ttl), hashable_(hashable), del_status_(NOT_DELETED) {
    if (ttl < 0)
      expire_time_ = 0;
  }
  key_value_tuple(const std::string &key, const std::string &value,
                  const boost::uint32_t &last_refresh_time)
      : key_(key), value_(value), ser_delete_req_(),
        last_refresh_time_(last_refresh_time), expire_time_(0), ttl_(0),
        hashable_(true), del_status_(NOT_DELETED) {}
};

/* Tags */
struct t_key {};
struct t_last_refresh_time {};
struct t_expire_time {};

typedef boost::multi_index::multi_index_container<
  key_value_tuple,
  boost::multi_index::indexed_by<
    boost::multi_index::ordered_unique<
      boost::multi_index::tag<t_key>,
      boost::multi_index::composite_key<
        key_value_tuple,
        BOOST_MULTI_INDEX_MEMBER(key_value_tuple, std::string, key_),
        BOOST_MULTI_INDEX_MEMBER(key_value_tuple, std::string, value_)
      >
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_last_refresh_time>,
      BOOST_MULTI_INDEX_MEMBER(key_value_tuple, boost::uint32_t,
                               last_refresh_time_)
    >,
    boost::multi_index::ordered_non_unique<
      boost::multi_index::tag<t_expire_time>,
      BOOST_MULTI_INDEX_MEMBER(key_value_tuple, boost::uint32_t,
                               expire_time_)
    >
  >
> datastore;

class DataStore {
 public:
  // t_refresh = refresh time of key/value pair in seconds
  explicit DataStore(const boost::uint32_t &t_refresh);
  ~DataStore();
  bool Keys(std::set<std::string> *keys);
  // time_to_live is in seconds.
  bool StoreItem(const std::string &key, const std::string &value,
                 const boost::int32_t &time_to_live, const bool &hashable);
  bool LoadItem(const std::string &key, std::vector<std::string> *values);
  bool DeleteKey(const std::string &key);
  bool DeleteItem(const std::string &key, const std::string &value);
  void DeleteExpiredValues();

  boost::uint32_t LastRefreshTime(const std::string &key,
                                  const std::string &value);
  boost::uint32_t ExpireTime(const std::string &key, const std::string &value);
  std::vector<refresh_value> ValuesToRefresh();
  boost::int32_t TimeToLive(const std::string &key, const std::string &value);
  void Clear();
  std::vector< std::pair<std::string, bool> > LoadKeyAppendableAttr(
      const std::string &key);
  bool RefreshItem(const std::string &key, const std::string &value,
                   std::string *str_delete_req);
  // If key, value pair does not exist, then it returns false
  bool MarkForDeletion(const std::string &key, const std::string &value,
                       const std::string &ser_del_request);
  // If key, value pair does not exist or its status is not MARKED_FOR_DELETION,
  // then it returns false
  bool MarkAsDeleted(const std::string &key, const std::string &value);
  bool UpdateItem(const std::string &key,
                  const std::string &old_value,
                  const std::string &new_value,
                  const boost::int32_t &time_to_live,
                  const bool &hashable);
  boost::uint32_t t_refresh() const;
 private:
  datastore datastore_;
  // refresh time in seconds
  boost::uint32_t t_refresh_;
  boost::mutex mutex_;
};

}  // namespace kad
#endif  // MAIDSAFE_KADEMLIA_DATASTORE_H_
