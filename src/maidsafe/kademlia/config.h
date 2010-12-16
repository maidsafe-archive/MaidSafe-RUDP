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

#ifndef MAIDSAFE_KADEMLIA_CONFIG_H_
#define MAIDSAFE_KADEMLIA_CONFIG_H_

#include <boost/cstdint.hpp>
#include <string>
#include <vector>

namespace kademlia {

// Functor for general callback functions.
typedef boost::function<void(std::string)> VoidFunctorOneString;

enum KBucketExitCode { SUCCEED, FULL, FAIL };

// CLIENT - does not map external ip and port, is not stored in other  nodes
//          routing table
// CLIENT_PORT_MAPPED - maps external ip and port, is not stored in other nodes
//                      routing table
// VAULT - maps external ip and port, complete functionality of a kademlia node
enum NodeType { CLIENT, CLIENT_PORT_MAPPED, VAULT };

enum ConnectionType { LOCAL, REMOTE, UNKNOWN };

// The size of DHT keys and node IDs in bytes.
const boost::uint16_t kKeySizeBytes = 64;

// The parallel level of search iterations.
const boost::uint16_t kAlpha = 3;

// The number of replies required in a search iteration to allow the next
// iteration to begin.
const boost::uint16_t kBeta = 2;

// The frequency (in seconds) of the refresh routine.
const boost::uint32_t kRefreshTime = 3600;  // 1 hour

// The frequency (in seconds) of the <key,value> republish routine.
const boost::uint32_t kRepublishTime = 43200;  // 12 hours

// The duration (in seconds) after which a given <key,value> is deleted locally.
const boost::uint32_t kExpireTime = kRepublishTime + kRefreshTime + 300;

// The ratio of k successful individual kad store RPCs to yield overall success.
const double kMinSuccessfulPecentageStore = 0.75;

// The number of failed RPCs tolerated before a contact is removed from the
// k-bucket.
const boost::uint16_t kFailedRpc = 0;

// The maximum number of bootstrap contacts allowed in the .kadconfig file.
const boost::uint32_t kMaxBootstrapContacts = 10000;

// Signature used to sign anonymous RPC requests.
const std::string kAnonymousSignedRequest(2 * kKeySizeBytes, 'f');

typedef transport::Endpoint Endpoint;

}  // namespace kademlia

#endif  // MAIDSAFE_KADEMLIA_CONFIG_H_
