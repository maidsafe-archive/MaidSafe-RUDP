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


#ifndef MAIDSAFE_TRANSPORT_TCPCONNECTION_H_
#define MAIDSAFE_TRANSPORT_TCPCONNECTION_H_
#include <boost/asio.hpp>
#include <boost/cstdint.hpp>
#include <boost/function.hpp>
#include <boost/enable_shared_from_this.hpp>
#include <boost/shared_ptr.hpp>
#include <string>

using boost::asio::ip::tcp;

namespace transport {

/**
* @class TCPConnection
* Object used to connect two peers with the TCP protocol.
* boost::shared_ptr and boost::enable_shared_from_this are used to keep the
* TCPConnection object alive as long as there is an operation that refers
* to it.
*/

class TCPConnection
    : public boost::enable_shared_from_this<TCPConnection>,
      private boost::noncopyable {
 public:
  /**
  * Constructor
  * @param io_service boost I/O service that will handle the asynchronous
  * operations of the socket
  * @param send_notifier boost function that will be called when a complete
  * message has been sent
  * @param read_notifier boost function that will be called when a complete
  * message has been read
  */
  TCPConnection(boost::asio::io_service &io_service,  // NOLINT
    boost::function<void(const boost::uint32_t&, const bool&, const bool&,
      const boost::system::error_code&)> send_notifier,
    boost::function<void(const std::string, const boost::uint32_t&,
      const boost::system::error_code&)> read_notifier);
  /**
  * Starts the asynchronous operation to read data from the socket.  Returns
  * immediately.  The result of the operation is notified in the read_notifier
  * passed in the constructor.
  */
  void StartReceiving();
  /**
  * Starts the asynchronous operation to send data to another peer.  Returns
  * immediately.  The result of the operation is notified in the send_notifier
  * passed in the constructor.
  */
  void Send(const std::string &data);
  /**
  * Get the socket tcp::socket associated to the object.
  * @return ip::tcp::socket object
  */
  inline tcp::socket& Socket() { return socket_; }
  /**
  * Get the remote endpoint of the socket
  * @return remote endpoint of the socket
  */
  boost::asio::ip::tcp::endpoint RemoteEndPoint(
    boost::system::error_code &error);
  /**
  * Get the data that has been read so far from the socket
  * @return String read from the socket
  */
  inline std::string in_data() const { return in_data_; }
  /**
  * Set the identifier for the object.  It is returned in all the notifiers.
  * @param id integer that is associated as the id of the connection
  */
  inline void set_connection_id(const boost::uint32_t &id) {
    connection_id_ = id;
  }
  /**
  * Closes the socket.
  */
  void Close();
  /**
  * Connects the socket the specified enpoint binding to a specific port.
  * @param remote_addr endpoint to which the socket tries to connect
  * @param out_port number of the port where the socket is bound
  * @return result of the operation
  */
  bool Connect(const boost::asio::ip::tcp::endpoint &remote_addr,
    const boost::uint16_t &out_port);
  /**
  * Connects the socket the specified enpoint binding to a random
  * available port.
  * @param remote_addr endpoint to which the socket tries to connect
  * @return result of the operation
  */
  bool Connect(const boost::asio::ip::tcp::endpoint &remote_addr);
  /**
  * @return number or the port used to connect to the remote endpoint
  */
  inline boost::uint16_t out_port() const { return out_port_; }
  /**
  * @return current size of that read by the socket
  */
  inline boost::uint32_t in_data_size() const { return in_data_size_; }
  /**
  * @param send_once flag indicating the object is just going to be used to
  * to send only one message
  */
  inline void send_once(const bool &send_once) { send_once_ = send_once; }
  /**
  * Sets internal stat that message sent is an rpc message.  Only if the message
  * sent is a rpc one, it is notified when the send operation finishes.
  * @param sending_rpc flag indicating the message sent to a remote endpoint is
  * an rpc message
  */
  inline void sending_rpc(const bool &sending_rpc) {
    sending_rpc_ = sending_rpc;
  }
 private:
  void ReadHandle(const bool &read_size, const boost::system::error_code &error,
    size_t bytes_read);
  void WriteHandle(const boost::system::error_code &error,
    const bool &size_sent);
  tcp::socket socket_;
  std::string in_data_, out_data_;
  boost::array<char, 1024> tmp_data_;
  boost::uint32_t in_data_size_, connection_id_;
  boost::function<void(const boost::uint32_t&, const bool&, const bool&,
    const boost::system::error_code &error)> send_notifier_;
  boost::function<void(const std::string, const boost::uint32_t&,
    const boost::system::error_code &error)> read_notifier_;
  boost::uint16_t out_port_;
  bool send_once_, sending_rpc_, closed_, receiving_;
};

typedef boost::shared_ptr<TCPConnection> tcpconnection_ptr;
}  // namespace transport


#endif  // MAIDSAFE_TRANSPORT_TCPCONNECTION_H_
