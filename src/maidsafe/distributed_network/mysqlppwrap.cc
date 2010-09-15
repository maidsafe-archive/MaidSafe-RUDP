/* Copyright (c) 2010 maidsafe.net limited
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
#include "maidsafe/distributed_network/mysqlppwrap.h"

namespace net_client {

MySqlppWrap::MySqlppWrap() : connection_(false), connected_(false), table_() {}

int MySqlppWrap::Init(const std::string &db, const std::string &server,
                      const std::string &user, const std::string &pass,
                      const std::string &table) {
  if (!connection_.connect(db.c_str(), server.c_str(), user.c_str(),
                           pass.c_str()))
    return -1;

  connected_ = true;
  table_ = table;

  return 0;
}

int MySqlppWrap::Insert(const std::string &key, const std::string &value) {
  if (!connected_)
    return -2;

  try {
    mysqlpp::Query query = connection_.query();
    query << "INSERT INTO " << table_ << " VALUES('" << mysqlpp::escape << key
          << "', '" << mysqlpp::escape << value << "')";
    mysqlpp::SimpleResult res = query.execute();
    if (res.rows() != 1)
      return -1;
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }

  return 0;
}

int MySqlppWrap::Update(const std::string &key, const std::string &old_value,
                        const std::string &new_value) {
  if (!connected_)
    return -2;

  try {
    mysqlpp::Query query = connection_.query();
    query << "UPDATE " << table_ << " SET kadvalue='"
          << mysqlpp::escape << new_value << "' WHERE kadkey='"
          << mysqlpp::escape << key << "' AND kadvalue='"
          << mysqlpp::escape << old_value << "'";
    mysqlpp::SimpleResult res = query.execute();
    if (res.rows() != 1) {
      printf("AAAAAAAAA %llu\n", res.rows());
      return -1;
    }
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }

  return 0;
}

int MySqlppWrap::Delete(const std::string &key, const std::string &value) {
  if (!connected_)
    return -2;

  try {
    mysqlpp::Query query = connection_.query();
    if (!key.empty() && !value.empty()) {
      query << "DELETE FROM " << table_ << " WHERE kadkey='"
            << mysqlpp::escape << key << "' AND kadvalue='"
            << mysqlpp::escape << value << "'";
    } else if (key.empty() && value.empty()) {
      query << "DELETE FROM " << table_;
    } else if (value.empty()) {
      query << "DELETE FROM " << table_ << " WHERE kadkey='"
            << mysqlpp::escape << key << "'";
    } else {
      printf("Unbelievable query you're trying to do. Shame on you!\n");
      return -1;
    }
    mysqlpp::SimpleResult res = query.execute();
    return res.rows();
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
}

int MySqlppWrap::Get(const std::string &key, std::vector<std::string> *values) {
  if (!connected_) {
    printf("MySqlppWrap::Get - Not connected\n");
    return -2;
  }

  values->clear();
  try {
    mysqlpp::Query query = connection_.query();
    if (key.empty())
      query << "SELECT kadvalue FROM " << table_;
    else
      query << "SELECT kadvalue FROM " << table_ << " WHERE kadkey='"
            << mysqlpp::escape << key << "'";
    mysqlpp::StoreQueryResult res = query.store();
    if (!res) {
      printf("Failed getting values for key %s\n", key.c_str());
      return -1;
    }

    for (size_t i = 0; i < res.num_rows(); ++i)
      values->push_back(static_cast<std::string>(res[i][0]));
  }
  catch(const std::exception &e) {
    printf("%s\n", e.what());
    return -1;
  }
  return 0;
}

}  // namespace net_client
