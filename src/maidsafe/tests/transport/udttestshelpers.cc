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

#include "maidsafe/tests/transport/udttestshelpers.h"
#include <vector>
#include "maidsafe/protobuf/transport_message.pb.h"
#include "maidsafe/udt/api.h"

namespace transport {

namespace test {

bool SocketAlive(const SocketId &udt_socket_id) {
  std::vector<int> socket_to_check(1, udt_socket_id);
  std::vector<int> sockets_bad;
  return (UDT::selectEx(socket_to_check, NULL, NULL, &sockets_bad, 1000) == 0);
}

testing::AssertionResult MessagesMatch(
    const TransportMessage &first_transport_message,
    const TransportMessage &second_transport_message) {
  // Check type field
  if (first_transport_message.has_type()) {
    if (second_transport_message.has_type()) {
      if (first_transport_message.type() != second_transport_message.type())
        return testing::AssertionFailure() << "message type " <<
            first_transport_message.type() << " doesn't equal " <<
            second_transport_message.type();
    } else {
      return testing::AssertionFailure() << "first message has type " <<
          first_transport_message.type() << " and second message has no type.";
    }
  } else {
    if (second_transport_message.has_type()) {
      return testing::AssertionFailure() << "second message has type " <<
          second_transport_message.type() << " and first message has no type.";
    }
  }

  // Check data field
  if (first_transport_message.has_data()) {
    std::string first_data = first_transport_message.data().SerializeAsString();
    if (second_transport_message.has_data()) {
      std::string second_data =
          second_transport_message.data().SerializeAsString();
      if (first_data != second_data)
        return testing::AssertionFailure() << "messages' data unequal.";
    } else {
      return testing::AssertionFailure() << "first message has data and "
                                              "second has none.";
    }
  } else {
    if (second_transport_message.has_data()) {
      return testing::AssertionFailure() << "second message has data and "
                                              "first has none.";
    }
  }
  return testing::AssertionSuccess();
}

}  // namespace test

}  // namespace transport
