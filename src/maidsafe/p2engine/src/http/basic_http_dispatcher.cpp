#include "p2engine/http/basic_http_dispatcher.hpp"

namespace p2engine { namespace http {

	http_connection_dispatcher::received_signal_type http_connection_dispatcher::s_msg_handler_;
	http_connection_dispatcher::received_request_header_signal_type http_connection_dispatcher::s_request_handler_;
	http_connection_dispatcher::received_response_header_signal_type http_connection_dispatcher::s_response_handler_;


	bool http_connection_dispatcher::dispatch_request(request& buf)
	{
		//1. search <message_soceket,net_event_handler_type> bind in this socket
		if (!request_handler_.empty())
		{
			request_handler_(buf);
			return true;
		}
		
		//2. search <message_soceket,net_event_handler_type> bind in all socket
		if (!s_request_handler_.empty())
		{
			s_request_handler_(buf);
			return true;
		}

		//3. not find, alert error
		BOOST_ASSERT(0&&"can't find message dispatch_packet slot");
		LOG(LogError("can't find message dispath slot"););
		return false;
	}
	bool http_connection_dispatcher::dispatch_response(response& buf)
	{
		//1. search <message_soceket,net_event_handler_type> bind in this socket
		if (!response_handler_.empty())
		{
			response_handler_(buf);
			return true;
		}

		//2. search <message_soceket,net_event_handler_type> bind in all socket
		if (!s_response_handler_.empty())
		{
			s_response_handler_(buf);
			return true;
		}

		//3. not find, alert error
		BOOST_ASSERT(0&&"can't find message dispatch_packet slot");
		LOG(LogError("can't find message dispath slot"));
		return false;
	}
	bool http_connection_dispatcher::dispatch_packet(safe_buffer& buf)
	{
		//1. search <message_soceket,net_event_handler_type> bind in this socket
		if (!msg_handler_.empty())
		{
			msg_handler_(buf);
			return true;
		}

		//2. search <message_soceket,net_event_handler_type> bind in all socket
		if (!s_msg_handler_.empty())
		{
			s_msg_handler_(buf);
			return true;
		}

		//3. not find, alert error
		BOOST_ASSERT(0&&"can't find message dispatch_packet slot");
		LOG(LogError("can't find message dispath slot"));
		return false;
	}


}
}