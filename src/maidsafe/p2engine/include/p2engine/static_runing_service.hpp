//
// static_runing_service.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010, GuangZhu Wu 
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

#ifndef P2ENGINE_STATIC_RUNING_ASIO_HPP
#define P2ENGINE_STATIC_RUNING_ASIO_HPP

#include "p2engine/config.hpp"
#include "p2engine/push_warning_option.hpp"
#include <boost/thread.hpp>
#include "p2engine/pop_warning_option.hpp"
#include "p2engine/singleton.hpp"

namespace p2engine {

	template<size_t THREAD_COUNT=1>
	class runing_service{
	public:
		runing_service(){}
		~runing_service(){
			join();
		}
		io_service& get_runing_io_service()
		{
			if (!runing_service_ios_.get())
			{
				boost::mutex::scoped_lock lock(runing_service_mutex_);
				if (!runing_service_ios_.get())
				{
					runing_service_threads_.clear();
					runing_service_threads_error_.clear();
					runing_service_ios_.reset(new io_service);
					runing_service_work_.reset(new io_service::work(*runing_service_ios_));

					for (size_t i=0;i<THREAD_COUNT;++i)
					{
						runing_service_threads_error_.push_back(error_code());
						runing_service_threads_.push_back(boost::shared_ptr<boost::thread>(
							new boost::thread(boost::bind(&io_service::run,runing_service_ios_.get(),
							runing_service_threads_error_[i])
							)));
					}
				}
			}
			return *runing_service_ios_;
		}
		void join()
		{
			printf("---------------runing_service joining....\n");
			try
			{
				boost::mutex::scoped_lock lock(runing_service_mutex_);
				if (runing_service_work_.get())
				{
					runing_service_work_.reset();
					runing_service_ios_->stop();
					for (size_t i=0;i<THREAD_COUNT;++i)
					{
						runing_service_threads_[i]->join();
					}
				}
			}
			catch (...)
			{
			}
			printf("---------------runing_service--joined!\n");
		}
	protected:
		std::auto_ptr<io_service> runing_service_ios_;
		std::auto_ptr<io_service::work> runing_service_work_;
		std::vector<boost::shared_ptr<boost::thread> >runing_service_threads_;
		std::vector<error_code >runing_service_threads_error_;
		boost::mutex runing_service_mutex_;
	};
}
#endif

