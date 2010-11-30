#include "p2engine/packet_reader.hpp"
#include "p2engine/rdp/basic_shared_udp_layer.hpp"
#include "p2engine/rdp/urdp_visitor.hpp"
#include "p2engine/utilities.hpp"
#include "p2engine/safe_buffer_io.hpp"

NAMESPACE_BEGIN(p2engine)
NAMESPACE_BEGIN(urdp)

typedef urdp_packet_basic_format packet_format_type;

basic_shared_udp_layer::this_type_container basic_shared_udp_layer::s_shared_this_type_pool_;
boost::mutex basic_shared_udp_layer::s_shared_this_type_pool_mutex_;

basic_shared_udp_layer::flow_token::shared_ptr 
basic_shared_udp_layer::create_flow_token(
	io_service& ios,
	const endpoint_type& local_edp,
	void* flow,
	recvd_data_handler_type handler,
	error_code& ec
	)
{
	shared_ptr obj=create(ios,local_edp,ec);
	return create_flow_token(obj,flow,handler,ec);
}

//called by flow,when listened a passive connect request
basic_shared_udp_layer::flow_token::shared_ptr 
basic_shared_udp_layer::create_flow_token(
	shared_layer_sptr udplayer,
	void* flow,//the flow that has been created when received SYN
	recvd_data_handler_type handler,
	error_code& ec
	)
{
	BOOST_ASSERT(udplayer);
	int flowID=INVALID_FLOWID;
	udplayer->register_flow(flow,handler,flowID,ec);
	return flow_token::shared_ptr(new flow_token(flowID,udplayer,flow));
}

//called by acceptor to listen at a local endpoint
basic_shared_udp_layer::acceptor_token::shared_ptr 
basic_shared_udp_layer::create_acceptor_token(
	io_service& ios,
	const endpoint_type& local_edp,
	void* acceptor,
	recvd_request_handler_type handler,
	const std::string domainName,
	error_code& ec
	)
{
	shared_ptr obj=create(ios,local_edp,ec);
	if (!ec) obj->register_acceptor(acceptor,domainName,handler,ec);
	return acceptor_token::shared_ptr(new acceptor_token(domainName,obj,acceptor));
}

basic_shared_udp_layer::shared_ptr 
basic_shared_udp_layer::create(io_service& ios, const endpoint_type& local_edp, error_code& ec)
{
	bool anyport=(local_edp.port()==endpoint_type().port());
	asio::ip::address address=local_edp.address();
	bool anyaddr=(address==asio::ip::address_v4::any()
		||address==asio::ip::address_v6::any());
	if ((anyport||anyaddr))
	{
		boost::mutex::scoped_lock lock(s_shared_this_type_pool_mutex_);

		this_type_container::iterator itr=s_shared_this_type_pool_.begin();
		for (;itr!=s_shared_this_type_pool_.end();++itr)
		{
			BOOST_ASSERT(itr->second);
			shared_ptr net_obj=itr->second->shared_ptr_from_this();

			bool address_match=(address==net_obj->local_endpoint_.address());
			bool port_match=(local_edp.port()==net_obj->local_endpoint_.port());
			if ((anyport&&address_match)||(anyaddr&&port_match))
			{
				return net_obj;
			}
		}
	}
	else
	{
		boost::mutex::scoped_lock lock(s_shared_this_type_pool_mutex_);
		this_type_container::iterator iter = s_shared_this_type_pool_.find(local_edp);
		if (iter != s_shared_this_type_pool_.end())
		{
			BOOST_ASSERT(iter->second);
			return iter->second->shared_ptr_from_this();
		}
	}
	shared_ptr net_obj;
	endpoint_type edp(local_edp);
	for (int i=(anyport?1024:1);i>0;--i)
	{
		/*
		typedef boost::mt19937 base_generator_type;
		typedef boost::uniform_int<> distribution_type;
		typedef boost::variate_generator<base_generator_type&, distribution_type > random_generator;
		static boost::shared_ptr<random_generator> port_generator;
		if (!port_generator)
		{
		static base_generator_type generator;
		generator.seed(static_cast<base_generator_type::result_type>(rough_local_tick_count()));
		distribution_type port(1000,60000);
		port_generator.reset(new random_generator(generator, port));
		}
		if (anyport)
		edp.port((unsigned short)(*port_generator)());
		*/
		if (anyport)
			edp.port(random<unsigned short>(1000,60000));
		try
		{
			net_obj= shared_ptr(new this_type(ios, edp,ec));
		}
		catch (...)
		{
			LOG(
				LogError("catched exception when create basic_shared_udp_layer");
			);
			continue;
		}
		if (!ec&&net_obj->is_open())
		{
			ec.clear();
			net_obj->start();
			break;
		}
	}
	BOOST_ASSERT(net_obj);
	return net_obj;
}

bool basic_shared_udp_layer::is_shared_endpoint(const endpoint_type& endpoint)
{
	boost::mutex::scoped_lock lock(s_shared_this_type_pool_mutex_);
	return s_shared_this_type_pool_.find(endpoint)!=s_shared_this_type_pool_.end(); 
}

basic_shared_udp_layer::~basic_shared_udp_layer()
{
	{
		boost::mutex::scoped_lock lock(s_shared_this_type_pool_mutex_);
		s_shared_this_type_pool_.erase(local_endpoint_);
	}

	close_without_protector();
	//if(lingerSendTimer_)
	//{
	//	lingerSendTimer_->cancel();
	//	lingerSendTimer_.reset();
	//}

	BOOST_ASSERT(acceptors_.empty());
	DEBUG_SCOPE(
		for (std::size_t i=0;i<flows_.size();++i)
		{
			BOOST_ASSERT(flows_[i].flow==NULL);
		}
		);
}

basic_shared_udp_layer::basic_shared_udp_layer(io_service& ios, 
											   const endpoint_type& local_edp,
											   error_code& ec)
											   : basic_engine_object(ios)
											   , socket_(ios)
											   , state_(INIT)
											   , flows_cnt_(0)
											   , id_allocator_(true)
{
	this->set_obj_desc("basic_shared_udp_layer");
	socket_.open(local_edp.protocol(), ec);
	asio::socket_base::reuse_address reuse_address_option(true);
	asio::socket_base::receive_buffer_size receive_buffer_size_option(1024*1024);
	asio::socket_base::send_buffer_size send_buffer_size_option(512*1024);
	asio::socket_base::non_blocking_io nonblock_command(true);
	socket_.io_control(nonblock_command);
	socket_.set_option(reuse_address_option,ec);
	socket_.set_option(receive_buffer_size_option,ec);
	socket_.set_option(send_buffer_size_option,ec);
	disable_icmp_unreachable(socket_.native());
	if (ec)
	{
		LOG(
			LogError("unable to open udp socket, error:%d, %s",
			ec.value(),ec.message().c_str());
		);
		socket_.close(ec);
		return;
	}
	socket_.bind(local_edp, ec);
	if (ec)
	{
		LOG(
			LogError("unable to bind udp socket with endpoint %s, error %d %s",
			print_endpoint(local_edp).c_str(),ec.value(),
			ec.message().c_str());
		);
		socket_.close(ec);
	}
	else
	{
		local_endpoint_=socket_.local_endpoint(ec);
		if (ec)
		{
			LOG(
				LogError(("unable get_local_endpoint, error %d %s",
				ec.value(),ec.message().c_str()
				));
			);
			socket_.close(ec);
			local_endpoint_=endpoint_type();
			return;
		}
		else
		{
			boost::mutex::scoped_lock lock(s_shared_this_type_pool_mutex_);
			s_shared_this_type_pool_.insert(std::make_pair(local_endpoint_, this));
		}
	}
	recv_buffer_.reallocate(mtu_size);
};


void basic_shared_udp_layer::handle_receive(const error_code& ec, 
											std::size_t bytes_transferred)
{
	//OBJ_PROTECTOR(protector);
	if (state_!=STARTED)
		return;
	if (!ec)
	{
		s_remote_to_local_speed_meter()+=bytes_transferred;
		safe_buffer forProcessBuf;
		if(bytes_transferred<(mtu_size/3))//size is too smaller than capacity, new a buffer
		{
			safe_buffer_io io(&forProcessBuf);
			io.write(buffer_cast<char*>(recv_buffer_),bytes_transferred);
			recv_buffer_.resize(recv_buffer_.capacity());
		}
		else
		{
			forProcessBuf= recv_buffer_.buffer_ref(0,bytes_transferred);
			recv_buffer_.reallocate(mtu_size);
		}
		do_handle_received(forProcessBuf);
		async_receive();
	}
	else
	{
		LOG(
			LogWarning("basic_shared_udp_layer receiving error"
			", local_endpoint=%s, errno=%d, error msg=:%s",
			print_endpoint(local_endpoint_).c_str(),
			ec.value(),ec.message().c_str()
			);
		);

		if (ec == asio::error::message_size)
		{
			LOG(
				LogWarning("the packet is too long, drop it, still keep receiving");
			);
			static char tmp[0xffff];
			error_code err;
			std::size_t len=socket_.receive(asio::buffer(tmp,sizeof(tmp)),0,err);//too long，drop it
			s_remote_to_local_speed_meter()+=len;
			async_receive();
		}
		else if (
			true//忽略所有错误
			//ec != errc::host_unreachable
			//ec != errc::fault
			//&& ec != errc::connection_reset
			//&& ec != errc::connection_refused
			//&& ec != errc::connection_aborted
			)// don't stop listening on recoverable errors
		{
			LOG(
				LogWarning("the packet is too long, drop it, still keep receiving");
			);
			async_receive();
		}
		else
		{
			LOG(
				LogWarning("the packet is too long, drop it, still keep receiving");
			);
		}
	}
}

void basic_shared_udp_layer::async_receive()
{
	if (state_!=STARTED)
		return;
	socket_.async_receive_from(
		asio::buffer(p2engine::buffer_cast<char*>(recv_buffer_),recv_buffer_.size()),
		sender_endpoint_,
		boost::bind(&this_type::handle_receive,SHARED_OBJ_FROM_THIS,_1, _2)
		);
}


error_code basic_shared_udp_layer::register_acceptor(const void* acc,
													 const std::string& domainName,
													 recvd_request_handler_type callBack,
													 error_code& ec
													 )
{
	boost::mutex::scoped_lock lockAcceptor(acceptor_mutex_);

	acceptor_element elm;
	elm.acceptor=(void*)acc;
	elm.handler=callBack;
	std::pair<acceptor_container::iterator,bool> insertRst
		=acceptors_.insert(std::make_pair(domainName,elm));
	if (!insertRst.second)
	{
		ec=asio::error::already_open; 
		return ec;
	}
	ec.clear();
	return ec;
}

void basic_shared_udp_layer::register_flow(const void* flow, 
										   recvd_data_handler_type callBack,
										   int& id, error_code& ec)
{
	OBJ_PROTECTOR(protector);

	boost::recursive_mutex::scoped_lock lock(flow_mutex_);

	while(released_id_catch_.size()>0)
	{
		if (!released_id_keeper_.is_keeped(released_id_catch_.front()))
		{
			id_allocator_.release_id(released_id_catch_.front());
			released_id_catch_.pop_front();
		}
		else
		{
			break;
		}
	}

	id=id_allocator_.alloc_id();
	if (id>=(int)INVALID_FLOWID)
	{
		__release_flow_id(id);
		ec=asio::error::no_descriptors;
		id=INVALID_FLOWID;
		return;//too much,drop it
	}
	else
	{			
		if (static_cast<int>(flows_.size())<=id)
		{
			if (flows_.size()==0)
				flows_.reserve(512);
			flows_.resize(id+1);
		}
		BOOST_ASSERT(!flows_[id].flow&&!flows_[id].handler);
		flows_[id].flow=const_cast<void*>(flow);
		flows_[id].handler=(callBack);
		ec.clear();
		flows_cnt_++;
	}
}

void basic_shared_udp_layer::unregister_flow(object_id_type flow_id,void* flow)
{
	boost::recursive_mutex::scoped_lock lock(flow_mutex_);

	if (flow_id!=INVALID_FLOWID&&flow_id<flows_.size())
	{
		BOOST_ASSERT(flows_[flow_id].flow==flow);
		UNUSED_PARAMETER(flow);
		__release_flow_id(flow_id);
	}
	else
	{
		BOOST_ASSERT(0);
	}
}

void basic_shared_udp_layer::__release_flow_id(int id)
{
	flows_cnt_--;
	flows_[id].flow=NULL;
	flows_[id].handler=NULL;
	lingerSends_.erase(id);

	released_id_catch_.push_back(id);
	released_id_keeper_.try_keep(id, seconds(128));//一个ID在一定时间内不会被重用
	while(released_id_catch_.size()>0)
	{
		if (!released_id_keeper_.is_keeped(released_id_catch_.front()))
		{
			id_allocator_.release_id(released_id_catch_.front());
			released_id_catch_.pop_front();
		}
		else
		{
			break;
		}
	}
}

void  basic_shared_udp_layer::unregister_acceptor(const void*acptor)
{
	boost::mutex::scoped_lock lock(acceptor_mutex_);

	acceptor_container::iterator itr=acceptors_.begin();
	for (;itr!=acceptors_.end();++itr)
	{
		if (itr->second.acceptor==const_cast<void*>(acptor))
		{
			acceptors_.erase(itr);
			break;
		}
	}
}

std::size_t basic_shared_udp_layer::send_to_imeliately( void const* p, std::size_t len,
												  const endpoint_type& ep, 
												  error_code& ec)
{
	//if(!is_open())
	//{
	//	ec=asio::error::not_socket;
	//	return 0;
	//}
	//ec.clear();
	int flags=0;
	s_local_to_remote_speed_meter()+=len;
	return socket().send_to(asio::buffer(p, len), ep, flags, ec);
}

void basic_shared_udp_layer::do_handle_received(const safe_buffer& buffer)
{
	if (buffer.length()<packet_format_type::packet_size())
	{
		return;//too short,drop it
	}
	do_handle_received_urdp_msg((safe_buffer&)buffer);
}

void basic_shared_udp_layer::do_handle_received_urdp_msg(safe_buffer& buffer)
{
	packet_reader<packet_format_type> urdpHeader(buffer);
	packet_format_type& urdpHeaderDef=urdpHeader.packet_format_def();
	int dstPeerID=INVALID_FLOWID;

	boost::recursive_mutex::scoped_lock lockFlow(flow_mutex_);

	if (is_conn_request_vistor<packet_format_type>()(urdpHeaderDef))
	{
		boost::mutex::scoped_lock lockAcceptor(acceptor_mutex_);

		std::string domainName=get_demain_name_vistor<packet_format_type>()(urdpHeaderDef,buffer);
		//检查是否有监听在这一domain上的acceptor
		acceptor_container::iterator itr=acceptors_.find(domainName);
		if (itr==acceptors_.end())
		{
			error_code ec;
			safe_buffer buf=make_refuse_vistor<packet_format_type>()(urdpHeaderDef);
			send_to_imeliately(buf,sender_endpoint_,ec);
			return;//drop
		}

		request_uuid id;
		id.remoteEndpoint=sender_endpoint_;
		id.remotePeerID=get_src_peer_id_vistor<packet_format_type>()(urdpHeaderDef);
		id.session=get_session_vistor<packet_format_type>()(urdpHeaderDef);

		timed_keeper<request_uuid>::const_iterator keeperItr=request_uuid_keeper_.find(id);
		if (keeperItr!=request_uuid_keeper_.end())
		{//已经给对方分配了一个flow，查找到这个flow响应request
			dstPeerID=keeperItr->id.flow_id;
		}
		else
		{//新来的，分配一个flow，并记录flow id
			acceptor_element& acceptorElement= itr->second;
			id.flow_id=acceptorElement.handler(id.remoteEndpoint);
			BOOST_ASSERT(std::find(released_id_catch_.begin(),released_id_catch_.end(),id.flow_id)==released_id_catch_.end());
			request_uuid_keeper_.try_keep(id,seconds(30));
			dstPeerID=id.flow_id;
		}
	}
	else
	{
		dstPeerID=get_dst_peer_id_vistor<packet_format_type>()(urdpHeaderDef);
	}

	if(dstPeerID!=INVALID_FLOWID)
	{
		if (dstPeerID<(int)flows_.size()&&flows_[dstPeerID].flow)
		{
			if (flows_[dstPeerID].handler)
			{
				BOOST_ASSERT(std::find(released_id_catch_.begin(),released_id_catch_.end(),dstPeerID)==released_id_catch_.end());
				//std::cout<<"找到槽位"<<dstPeerID<<std::endl;
				flows_[dstPeerID].handler(buffer,sender_endpoint_);
			}
		}
	}
}

NAMESPACE_END(urdp)
NAMESPACE_END(p2engine)
