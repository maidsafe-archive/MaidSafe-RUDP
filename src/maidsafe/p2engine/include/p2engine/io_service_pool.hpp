//
// io_service_pool.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
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
//

#ifndef BAS_IO_SERVICE_POOL_HPP
#define BAS_IO_SERVICE_POOL_HPP

#include <boost/assert.hpp>
#include <boost/thread.hpp>
#include <boost/asio.hpp>
#include <boost/noncopyable.hpp>
#include <boost/shared_ptr.hpp>

#include <map>
#include <vector>

#include "p2engine/config.hpp"

#include "p2engine/push_warning_option.hpp"

namespace p2engine{

	/// A pool of io_service objects.
	class io_service_pool
		: private boost::noncopyable
	{
		typedef boost::shared_ptr<asio::io_service> io_service_ptr;
		typedef boost::shared_ptr<asio::io_service::work> work_ptr;
		typedef boost::shared_ptr<boost::thread> thread_ptr;
		typedef boost::recursive_mutex mutex_type;
	public:
		/// Construct the io_service pool.
		explicit io_service_pool(size_t pool_size)
			: io_services_(),
			work_(),
			threads_(),
			next_io_service_(0),
			block_(false)
		{
			mutex_type::scoped_lock lock(mutex_);

			BOOST_ASSERT(pool_size != 0);
			// Create io_service pool.
			io_services_.reserve(pool_size);
			for (size_t i = 0; i < pool_size; ++i)
			{
				io_services_.push_back(io_service_ptr(new asio::io_service));
			}
		}

		/// Destruct the pool object.
		~io_service_pool()
		{
			stop();
			// Destroy all work.
			work_.clear();
			// Destroy io_service pool.
			io_services_.clear();
		}

		size_t size()
		{
			mutex_type::scoped_lock lock(mutex_);
			return io_services_.size();
		}

		/// Start all io_service objects in nonblock model.
		void start(bool block=false)
		{
			__start(block);
		}

		/// Stop all io_service objects in the pool.
		void stop()
		{
			__wait();
		}

		/// Get an io_service to use.round robin
		asio::io_service& get_io_service()
		{
			mutex_type::scoped_lock lock(mutex_);
			asio::io_service& io_service = *io_services_[next_io_service_];
			if (++next_io_service_ == io_services_.size())
				next_io_service_ = 0;
			return io_service;
		}

		/// Get the certain io_service to use.
		asio::io_service& get_io_service(size_t offset)
		{
			mutex_type::scoped_lock lock(mutex_);
			BOOST_ASSERT(offset < io_services_.size());
			return *io_services_[offset%io_services_.size()];
		}

		//is ios in this pool
		bool in_pool(asio::io_service&ios)
		{
			mutex_type::scoped_lock lock(mutex_);

			for (size_t i=0;i<io_services_.size();++i)
			{
				if (&ios==io_services_[i].get())
					return true;
			}
			return false;
		}

		//find ios by thread id.
		asio::io_service* find(const boost::thread::id& thread_id)
		{
			mutex_type::scoped_lock lock(mutex_);
			typedef std::map<boost::thread::id,asio::io_service*>::iterator iterator;
			iterator itr=io_services_map_.find(thread_id);
			if (itr==io_services_map_.end())
				return NULL;
			return (itr->second);
		}
	private:
		/// Wait for all threads in the pool to exit.
		void __wait();

		/// Start all io_service objects in the pool.
		void __start(bool block);

	private:
		std::map<boost::thread::id,asio::io_service*> io_services_map_;

		/// The pool of io_services.
		std::vector<io_service_ptr> io_services_;

		/// The work that keeps the io_services running.
		std::vector<work_ptr> work_;

		/// The pool of threads for running individual io_service.
		std::vector<thread_ptr> threads_;

		/// The next io_service to use for a connection.
		size_t next_io_service_;

		/// Flag to indicate that start() functions will block or not.
		bool block_;

		///for thread safe
		mutex_type mutex_;
	};

} // namespace p2engine
#include "p2engine/pop_warning_option.hpp"

#endif // BAS_IO_SERVICE_POOL_HPP
