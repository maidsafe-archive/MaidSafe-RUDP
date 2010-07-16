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

#ifndef MAIDSAFE_MAIDSAFE_DHT_H_
#define MAIDSAFE_MAIDSAFE_DHT_H_

// Configuration file
#include <maidsafe/maidsafe-dht_config.h>

// API files
#include <maidsafe/transport/transport-api.h>
#include <maidsafe/rpcprotocol/channelmanager-api.h>
#include <maidsafe/rpcprotocol/channel-api.h>
#include <maidsafe/kademlia/knode-api.h>

// General files
#include <maidsafe/base/alternativestore.h>
#include <maidsafe/base/crypto.h>
#include <maidsafe/kademlia/kadid.h>
#include <maidsafe/base/log.h>
#include <maidsafe/kademlia/contact.h>
#include <maidsafe/base/online.h>
#include <maidsafe/base/routingtable.h>
#include <maidsafe/transport/transportudt.h>
#include <maidsafe/base/utils.h>
#include <maidsafe/base/validationinterface.h>

// Generated protocol buffer files
#include <maidsafe/protobuf/signed_kadvalue.pb.h>
#include <maidsafe/protobuf/kademlia_service_messages.pb.h>
#include <maidsafe/protobuf/contact_info.pb.h>
#include <maidsafe/protobuf/general_messages.pb.h>

#endif  // MAIDSAFE_MAIDSAFE_DHT_H_
