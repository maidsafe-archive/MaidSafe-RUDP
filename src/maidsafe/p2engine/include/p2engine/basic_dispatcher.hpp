//
// basic_dispatcher.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009, GuangZhu Wu  <guangzhuwu@gmail.com>
//
//This program is free software; you can redistribute it and/or modify it 
//under the terms of the GNU General Public License or any later version.
//
//This program is distributed in the hope that it will be useful, but 
//WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY 
//or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License 
//for more details.
//
//You should have received a copy of the GNU General Public License along 
//with this program; if not, contact <guangzhuwu@gmail.com>.
//
#ifndef basic_dispatcher_h__
#define basic_dispatcher_h__

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/unordered_map.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/logging.hpp"
#include "p2engine/fssignal.hpp"
#include "p2engine/safe_buffer_io.hpp"

namespace p2engine
{
	template<typename MessageType>
	struct messsage_extractor
	{
		typedef MessageType message_type;
		static message_type invalid_message()
		{
			return (~MessageType(0));
		}
		MessageType operator()(safe_buffer&buf)
		{
			message_type messageType(~MessageType(0));
			if (buf.length()>=sizeof(message_type))
			{
				safe_buffer_io io(&buf);
				io>>messageType;
			}
			return messageType;
		}
	};

	template<>
	struct messsage_extractor<void>
	{
		typedef void message_type;
		static message_type invalid_message()
		{
			return;
		}
		void operator()(safe_buffer&buf)
		{
			return;
		}
	};

	typedef messsage_extractor<void> void_message_extractor;

	template<typename MesssageExtraction> class basic_message_dispatcher;

	template<typename MesssageExtraction> class basic_connection_dispatcher;

	template<typename MessageSocket> class basic_acceptor_dispatcher;


#define basic_message_dispatcher_typedef(MesssageExtraction,typename)\
	public:\
		typedef  MesssageExtraction   messsage_extractor_type;\
		typedef  typename messsage_extractor_type::message_type   message_type;\
		typedef  basic_message_dispatcher<messsage_extractor_type> dispatcher_type;\
		\
		typedef fssignal::signal<void(safe_buffer&)>      message_signal_type;\
		\
		typedef boost::unordered_map<message_type,message_signal_type> message_dispatch_map;\



	template<typename MesssageExtraction>
	class basic_message_dispatcher
	{
		typedef basic_message_dispatcher<MesssageExtraction> this_type;
		SHARED_ACCESS_DECLARE;
		basic_message_dispatcher_typedef(MesssageExtraction,typename)

	protected:
		virtual ~basic_message_dispatcher(){}

	public:
		message_signal_type& message_signal(const message_type& msgType) 
		{
			return msg_handler_map_[msgType];
		}
		const message_signal_type& message_signal(const message_type& msgType)const
		{
			return msg_handler_map_[msgType];
		}
		message_signal_type& invalid_message_signal(const message_type& msgType)
		{
			return invalid_message_signal_;
		}
		const message_signal_type& invalid_message_signal(const message_type& msgType)const
		{
			return invalid_message_signal_;
		}

		static  message_signal_type& global_message_signal(const message_type& msgType)
		{
			return s_receive_handler_map_[msgType];
		}

		bool extract_and_dispatch_message(safe_buffer& buf)
		{
			message_type msg_type=messsage_extractor_type()(buf);
			if (msg_type==messsage_extractor_type().invalid_message())
			{
				if (invalid_message_signal_.empty())
				{
					BOOST_ASSERT(0&&"dispatcher is not found for invalid message"&&msg_type);
					LOG(
						LogError("dispatcher is not found for invalid message %s",boost::lexical_cast<std::string>(msg_type).c_str());
						);
					return false;
				}
				else
					invalid_message_signal_(buf);
			}
			return dispatch_packet(buf,msg_type);
		}

		void disconnect_all_slots()
		{
			while(!msg_handler_map_.empty())
			{
				msg_handler_map_.begin()->second.disconnect_all_slots();
				msg_handler_map_.erase(msg_handler_map_.begin());
			}
		}

		bool dispatch_packet(safe_buffer& buf,const message_type& msg_type)
		{
			typedef typename message_dispatch_map::iterator iterator;

			//1. search <message_soceket,net_event_handler_type> bind in this socket
			if (!msg_handler_map_.empty())
			{
				iterator itr(msg_handler_map_.find(msg_type));
				if (itr!=msg_handler_map_.end())
				{
					(itr->second)(buf);
					return true;
				}
			}

			//2. search <message_soceket,net_event_handler_type> bind in all socket
			if (!s_receive_handler_map_.empty())
			{
				iterator itr=s_receive_handler_map_.find(msg_type);
				if (itr!=s_receive_handler_map_.end())
				{
					(itr->second)(buf);
					return true;
				}
			}

			//3. not find, alert error
			//BOOST_ASSERT(0&&"can't find message dispatch_packet slot for message "&&msg_type);
			LOG(
			LogError("can't find message dispath slot for message %s",boost::lexical_cast<std::string>(msg_type).c_str());
			);
			return false;
		}

	public:
		message_dispatch_map msg_handler_map_;
		message_dispatch_map invalid_message_signal_;
		static message_dispatch_map s_receive_handler_map_;
	};
	template<typename MesssageExtraction>
	typename basic_message_dispatcher<MesssageExtraction>::message_dispatch_map
		basic_message_dispatcher<MesssageExtraction>::s_receive_handler_map_;


#define  basic_connection_dispatcher_typedef(MesssageExtraction,typename)\
	public:\
		typedef  MesssageExtraction   messsage_extractor_type;\
		typedef  typename messsage_extractor_type::message_type   message_type;\
		typedef  basic_connection_dispatcher<messsage_extractor_type> dispatcher_type;\
		\
		typedef fssignal::signal<void(safe_buffer&)>      received_signal_type;\
		typedef fssignal::signal<void(const error_code&)> connected_signal_type;\
		typedef fssignal::signal<void(const error_code&)> disconnected_signal_type;\
		typedef fssignal::signal<void()>				  writable_signal_type;\
		\
		typedef boost::unordered_map<message_type,received_signal_type> message_dispatch_map;\


	template<typename MesssageExtraction>
	class basic_connection_dispatcher
	{
		typedef basic_connection_dispatcher<MesssageExtraction> this_type;
		SHARED_ACCESS_DECLARE;
		basic_connection_dispatcher_typedef(MesssageExtraction,typename);

	protected:
		virtual ~basic_connection_dispatcher(){}

	public:
		received_signal_type& received_signal(const message_type& msgType) 
		{
			return msg_handler_map_[msgType];
		}
		const received_signal_type& received_signal(const message_type& msgType)const
		{
			return msg_handler_map_[msgType];
		}
		received_signal_type& invalid_message_signal(const message_type& msgType)
		{
			return invalid_message_signal_;
		}
		const received_signal_type& invalid_message_signal(const message_type& msgType)const
		{
			return invalid_message_signal_;
		}

		static received_signal_type& global_message_signal(const message_type& msgType)
		{
			return s_receive_handler_map_[msgType];
		}

		connected_signal_type& connected_signal() 
		{
			return on_connected_;
		}
		const connected_signal_type& connected_signal() const
		{
			return on_connected_;
		}
		disconnected_signal_type& disconnected_signal() 
		{
			return on_disconnected_;
		}
		const disconnected_signal_type& disconnected_signal() const
		{
			return on_disconnected_;
		}
		writable_signal_type& writable_signal() 
		{
			return on_writable_;
		}
		const writable_signal_type& writable_signal() const
		{
			return on_writable_;
		}

		bool extract_and_dispatch_message(safe_buffer& buf)
		{
			message_type msg_type=messsage_extractor_type()(buf);
			if (msg_type==messsage_extractor_type().invalid_message())
			{
				if (invalid_message_signal_.empty())
				{
					BOOST_ASSERT(0&&"dispatcher is not found for invalid message"&&msg_type);
					LOG(
					LogError("dispatcher is not found for invalid message %s",boost::lexical_cast<std::string>(msg_type).c_str());
					);
					return false;
				}
				else
					invalid_message_signal_(buf);
			}
			return dispatch_packet(buf,msg_type);
		}

		void disconnect_all_slots()
		{
			while(!msg_handler_map_.empty())
			{
				msg_handler_map_.begin()->second.disconnect_all_slots();
				msg_handler_map_.erase(msg_handler_map_.begin());
			}
			on_connected_.disconnect_all_slots();
			on_disconnected_.disconnect_all_slots();
			on_writable_.disconnect_all_slots();
		}
		void dispatch_disconnected(const error_code& ec)
		{
			disconnected_signal()(ec);
		}
		void dispatch_connected(const error_code& ec)
		{
			connected_signal()(ec);
		}
		void dispatch_sendout()
		{
			writable_signal()();
		}
		bool dispatch_packet(safe_buffer& buf,const message_type& msg_type)
		{
			typedef typename message_dispatch_map::iterator iterator;

			//1. search <message_soceket,net_event_handler_type> bind in this socket
			if (!msg_handler_map_.empty())
			{
				iterator itr(msg_handler_map_.find(msg_type));
				if (itr!=msg_handler_map_.end())
				{
					(itr->second)(buf);
					return true;
				}
			}

			//2. search <message_soceket,net_event_handler_type> bind in all socket
			if (!s_receive_handler_map_.empty())
			{
				iterator itr=s_receive_handler_map_.find(msg_type);
				if (itr!=s_receive_handler_map_.end())
				{
					(itr->second)(buf);
					return true;
				}
			}

			//3. not find, alert error
			//BOOST_ASSERT(0&&"can't find message dispatch_packet slot for message "&&msg_type);
			LOG(
				LogError("can't find message dispath slot for message %d",boost::lexical_cast<int>(msg_type));
				);
			return false;
		}

	public:
		disconnected_signal_type on_disconnected_;
		connected_signal_type    on_connected_;
		writable_signal_type     on_writable_;
		message_dispatch_map msg_handler_map_;
		received_signal_type invalid_message_signal_;
		static message_dispatch_map s_receive_handler_map_;
	};
	template<typename MesssageExtraction>
	typename basic_connection_dispatcher<MesssageExtraction>::message_dispatch_map
		basic_connection_dispatcher<MesssageExtraction>::s_receive_handler_map_;

	template< >
	class basic_connection_dispatcher<void_message_extractor>
	{
		typedef basic_connection_dispatcher<void_message_extractor> this_type;
		SHARED_ACCESS_DECLARE;

		basic_connection_dispatcher_typedef(void_message_extractor,);

	protected:
		virtual ~basic_connection_dispatcher(){}

	public:
		received_signal_type& received_signal() 
		{
			return msg_handler_;
		}
		const received_signal_type& received_signal()const
		{
			return msg_handler_;
		}
		static received_signal_type& global_received_signal()
		{
			return s_msg_handler_;
		}
		connected_signal_type& connected_signal() 
		{
			return on_connected_;
		}
		const connected_signal_type& connected_signal() const
		{
			return on_connected_;
		}
		disconnected_signal_type& disconnected_signal() 
		{
			return on_disconnected_;
		}
		const disconnected_signal_type& disconnected_signal() const
		{
			return on_disconnected_;
		}
		writable_signal_type& writable_signal() 
		{
			return on_writable_;
		}
		const writable_signal_type& writable_signal() const
		{
			return on_writable_;
		}

		bool extract_and_dispatch_message(safe_buffer& buf)
		{
			return dispatch_packet(buf);
		}
		void disconnect_all_slots()
		{
			msg_handler_.disconnect_all_slots();
			on_connected_.disconnect_all_slots();
			on_disconnected_.disconnect_all_slots();
			on_writable_.disconnect_all_slots();
		}

		void dispatch_disconnected(const error_code& ec)
		{
			disconnected_signal()(ec);
		}
		void dispatch_connected(const error_code& ec)
		{
			connected_signal()(ec);
		}
		void dispatch_sendout()
		{
			writable_signal()();
		}
		bool dispatch_packet(safe_buffer& buf)
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
			LOG(
				LogError("can't find message dispath slot");
				);
			return false;
		}

	public:
		disconnected_signal_type on_disconnected_;
		connected_signal_type on_connected_;
		writable_signal_type on_writable_;
		received_signal_type msg_handler_;
		static received_signal_type s_msg_handler_;
	};

	//////////////////////////////////////////////////////////////////////////

#define  basic_acceptor_dispatcher_typedef(MessageSocket,typename)\
	public:\
		typedef MessageSocket socket_type;\
		typedef basic_acceptor_dispatcher<socket_type> dispatcher_type;\
		typedef typename boost::shared_ptr<socket_type> connection_sptr;\
		typedef fssignal::signal<void(connection_sptr,const error_code&)> accepted_signal_type;\

	template<typename MessageSocket>
	class basic_acceptor_dispatcher
	{
		typedef basic_acceptor_dispatcher<MessageSocket> this_type;

		SHARED_ACCESS_DECLARE;
		
		basic_acceptor_dispatcher_typedef(MessageSocket,typename);

	protected:
		virtual ~basic_acceptor_dispatcher(){}

	public:
		accepted_signal_type& accepted_signal()
		{
			return accept_handler_;
		}

		const accepted_signal_type& accepted_signal()const
		{
			return accept_handler_;
		}

		virtual void dispatch_accepted(connection_sptr sock, const error_code& ec)
		{
			accepted_signal()(sock,ec);
		}

	protected:
		accepted_signal_type accept_handler_;
	};
}

#endif