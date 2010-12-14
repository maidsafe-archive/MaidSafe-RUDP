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

/*******************************************************************************
 * NOTE: This header should not be regarded as finalised until this notice is  *
 *       removed.                                                              *
 ******************************************************************************/

#ifndef MAIDSAFE_TRANSPORT_TRANSPORT_H_
#define MAIDSAFE_TRANSPORT_TRANSPORT_H_

#include <boost/shared_ptr.hpp>
#include <boost/signals2/signal.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/date_time/posix_time/posix_time_duration.hpp>
#include <maidsafe/transport/transportconditions.h>
#include <string>
#include <iostream>

#if MAIDSAFE_DHT_VERSION < 25
#error This API is not compatible with the installed library.
#error Please update the maidsafe-dht library.
#endif

namespace bs2 = boost::signals2;

namespace transport {

typedef boost::asio::ip::address IP;
typedef boost::uint16_t Port;
typedef boost::int32_t DataSize;
typedef int ConversationId;

struct Info {
  boost::uint32_t rtt;
};  

struct Endpoint {
  Endpoint(IP ip, Port port) : ip(ip), port(port) {}
  IP ip;
  Port port;
};

const DataSize kMaxTransportMessageSize = 67108864;

// Base class for all transport types.
class Transport {
 public:
  virtual ~Transport() {}
  /**
   * Enables the transport to accept incoming communication. Fails if already
   * listening or the requested endpoint is unavailable.
   * @param endpoint The endpoint to listen for messages on.
   * @return Success or an appropriate error code.
   */
  virtual TransportCondition StartListening(const Endpoint &endpoint) = 0;
  /**
   * Stops the transport from accepting incoming communication.
   */
  virtual void StopListening() = 0;
  /**
   * Sends the given message to the specified receiver.
   * @param data The message data to transmit.
   * @param endpoint The data receiver's endpoint.
   * @param timeout Time after which to terminate a conversation.
   */
  virtual void Send(const std::string &data,
                    const Endpoint &endpoint,
                    const boost::posix_time::milliseconds &timeout) = 0;
  /**
   * Sends the given message within an already established conversation.
   * @param data The message data to transmit.
   * @param conversation_id ID of the conversation to respond to.
   * @param timeout Time after which to terminate a conversation.
   */
  virtual void Respond(const std::string &data,
                       const ConversationId &conversation_id,
                       const boost::posix_time::ptime &timeout) = 0;
  /**
   * Sends data that is being streamed from the given source.
   * @param data The input stream delivering data to send.
   * @param endpoint The data receiver's endpoint.
   */
  virtual void SendStream(const std::istream &data,
                          const Endpoint &endpoint) = 0;
  /**
   * Getter for the transport's signals.
   * @return A pointer to the signals object.
   */
  boost::shared_ptr<Signals> signals() { return signals_; }
  /**
   * Getter for the listening port.
   * @return The port number or 0 if not listening.
   */
  Port listening_port() const { return listening_port_; }
 protected:
  Transport() : signals_(new Signals), listening_port_(0) {}
  boost::shared_ptr<Signals> signals_;
  Port listening_port_;
 private:
  Transport(const Transport&);
  Transport& operator=(const Transport&);
};

// to handle the event of receiving a message
typedef bs2::signal<void(const ConversationId&,
                         const std::string&,
                         const Info&)> OnMessageReceived;

// to handle the event of any kind of failure, at any stage
typedef bs2::signal<void(const ConversationId&,
                         const TransportCondition&)> OnError;

class Signals {
 public:
  Signals() : on_message_received_(),
              on_error_() {}
  ~Signals() {}

  // OnMessageReceived =========================================================
  bs2::connection ConnectOnMessageReceived(
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(slot);
  }

  bs2::connection GroupConnectOnMessageReceived(
      const int &group,
      const OnMessageReceived::slot_type &slot) {
    return on_message_received_.connect(group, slot);
  }

  // OnError ===================================================================
  bs2::connection ConnectOnError(const OnError::slot_type &slot) {
    return on_error_.connect(slot);
  }

  bs2::connection GroupConnectOnStats(const int &group,
                                      const OnError::slot_type &slot) {
    return on_error_.connect(group, slot);
  }

 private:
  OnMessageReceived on_message_received_;
  OnError on_error_;
};

}  // namespace transport

#endif  // MAIDSAFE_TRANSPORT_TRANSPORT_H_
