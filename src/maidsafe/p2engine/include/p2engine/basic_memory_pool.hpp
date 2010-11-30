//
// basic_memory_pool.hpp
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
//with this program; if not, contact <guangzhuwu@gmail.com>.
//

#ifndef P2ENGINE_BASIC_MEMORY_POOL_HPP
#define P2ENGINE_BASIC_MEMORY_POOL_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include <boost/pool/pool.hpp>
#include <boost/assign.hpp>
#include <boost/thread.hpp>

#include <vector>
#include <iostream>

#include "p2engine/pop_warning_option.hpp"

#include "p2engine/fast_mutex.hpp"
#include "p2engine/null_mutex.hpp"
#include "p2engine/singleton.hpp"

#if defined(_MSC_VER)
# pragma warning (push)
# pragma warning(disable : 4267)
#endif

namespace p2engine {

	struct default_user_allocator_malloc_free
	{
		typedef std::size_t size_type;
		typedef std::ptrdiff_t difference_type;

		static char * malloc(const size_type bytes)
		{ return reinterpret_cast<char *>(std::malloc(bytes)); }
		static void free(void * const block)
		{ std::free(block); }
		static char * realloc(void * const block, size_type bytes)
		{ return reinterpret_cast<char *>(std::realloc(block,bytes)); }
	};

	template <typename UserAllocator=default_user_allocator_malloc_free,
		typename MutexType=fast_mutex>
	class  basic_memory_pool
	{
#ifndef NDEBUG
#	define MEMORY_POOL_DEBUG(x) x
#else
#	define MEMORY_POOL_DEBUG(x)
#endif
		typedef basic_memory_pool<UserAllocator,MutexType> this_type;
		typedef MutexType mutex_type;
		template <typename _ThisType> friend class singleton;
		typedef singleton<this_type> singleton_type;

	protected:
		enum{MAX_SIZE=4096};
		enum{BLOCK_SIZE=8};
		enum{MAX_INDEX_CNT=(MAX_SIZE+BLOCK_SIZE-1)/BLOCK_SIZE};

		class  PtrPtrVec
		{
		public:
			PtrPtrVec()
			{
				memset(buf_,0,sizeof(buf_));
				memset(size_map_,0,sizeof(size_map_));
				memset(capacity_map_,0,sizeof(capacity_map_));
				for (int i=0;i<MAX_INDEX_CNT+1;i++)
				{
					max_capacity_map_[i]=(32*1024*1024)/(BLOCK_SIZE*(i+1));
				}
			}
			void push_back(int which,void* p)
			{
				if( capacity_map_[which]>=max_capacity_map_[which] )
				{
					UserAllocator::free(((char*)p-sizeof(size_t)));
					return;
				}
				if (capacity_map_[which]<=size_map_[which])
				{
					if (capacity_map_[which]==0)
					{
						capacity_map_[which]=8;
						buf_[which]=(void**)UserAllocator::malloc(capacity_map_[which]*sizeof(void**));
					}
					else
					{
						if(capacity_map_[which]<16*1024)
							capacity_map_[which]<<=1;
						else
							capacity_map_[which]+=1024;
						buf_[which]= (void**)UserAllocator::realloc(buf_[which],capacity_map_[which]*sizeof(void**));
					}
				}
				buf_[which][size_map_[which]]=p;
				++size_map_[which];
			}
			void* pop_back(int which)
			{
				if (which>MAX_INDEX_CNT||size_map_[which]==0)
					return NULL;
				--size_map_[which];
				return buf_[which][size_map_[which]];
			}
			void clear()
			{
				for (size_t i=0;i<sizeof(buf_)/sizeof(buf_[0]);++i)
				{
					if (buf_[i]==NULL)
						continue;
					for(int j=0;j<size_map_[i];j++)
					{
						char* ptr=reinterpret_cast<char*>(buf_[i][j]);
						ptr-=sizeof(size_t);
						UserAllocator::free(ptr);
					}
					UserAllocator::free(buf_[i]);
				}
			}
			int size(size_t which)
			{
				return size_map_[which];
			}
			int capacity(size_t which)
			{
				return capacity_map_[which];
			}
		private:
			void** buf_[MAX_INDEX_CNT+1]; 
			int size_map_[MAX_INDEX_CNT+1];
			int capacity_map_[MAX_INDEX_CNT+1];
			int max_capacity_map_[MAX_INDEX_CNT+1];
		};
		friend class ReuseBaseClear;

	protected:
		basic_memory_pool()
		{
			MEMORY_POOL_DEBUG(
				reused_=alloc_=deleted_=0;
			memset(reused_vec_,0,sizeof(reused_vec_));
			memset(alloc_vec_,0,sizeof(alloc_vec_));
			memset(deleted_vec_,0,sizeof(deleted_vec_));
			)
		}

	public:
		~basic_memory_pool()
		{
			clearall();
		}
		void* malloc(size_t n)
		{
			if (n==0)
				n=1;
			BOOST_STATIC_ASSERT(BLOCK_SIZE==8);
			register size_t n8=((n+7)>>3);//将要分配的字节长度转化为8字节为单位的长度
			register void * p=NULL;
			if(n8<=MAX_INDEX_CNT)
			{
				mutex_.lock();
				p=mem_.pop_back((int)n8);
				mutex_.unlock();
				if (p==NULL)
				{
					void* pl =UserAllocator::malloc((n8<<3)+ sizeof(size_t));//前面字节用来保存对象的大小
					if(!pl)
						return NULL;
					*(size_t*)(pl)=n8;
					p = ((char*)pl)+sizeof(size_t);
					
					MEMORY_POOL_DEBUG(alloc_++;alloc_vec_[n8]++;);
				}
				else 
				{
					MEMORY_POOL_DEBUG( reused_++;reused_vec_[n8]++;);
				}
			}
			else
			{
				void* pl= UserAllocator::malloc(n+sizeof(size_t));//前面字节用来保存对象的大小
				if(!pl)
					return NULL;
				*(size_t*)(pl)=(size_t)(0);//0表示这一分配不会被reuse
				p = ((char*)pl)+sizeof(size_t);
			}
			return p;
		}
		void free(void* p)
		{
			if(!p)
				return;
			char* real_p=((char*)p-sizeof(size_t));
			register size_t len_8 = (*(size_t*)real_p); // 以8字节为单位
			if(len_8==0)
			{
				UserAllocator::free(real_p);
			}
			else
			{
				mutex_.lock();
				mem_.push_back((int)len_8,p);
				mutex_.unlock();
				MEMORY_POOL_DEBUG(deleted_++;deleted_vec_[len_8]++);
			}
		}

	private:
		void clearall()
		{
			mutex_.lock();
			MEMORY_POOL_DEBUG(
				print_info();
			);
			mem_.clear();
			mutex_.unlock();
		}

		MEMORY_POOL_DEBUG(
			void print_info()
		{

			size_t tot = 0;
			std::cout << "Printing HeapReuse information" << std::endl;
			std::cout << "Reused " << reused_ << " Newalloc " << alloc_
				<< " Deleted " << deleted_ << std::endl;
			for (int i = 0; i <=MAX_INDEX_CNT; ++i)
			{
				if (0==mem_.size(i))
				{
					/*
					std::cout <<"index="<<i<<",Size=" << i*BLOCK_SIZE<<" :";
					std::cout << " NULL " << std::endl;
					*/
				}
				else
				{
					std::cout <<"index="<<i<<",Size=" << i*BLOCK_SIZE<<" :";
					std::cout << " capacity " << mem_.capacity(i)
						<< " size " << mem_.size(i)
						<< " total bytes " << mem_.size(i)*i*BLOCK_SIZE
						<< std::endl;
					tot += mem_.size(i) *i;
				}
			}

			std::cout << "Total bytes in ReuseBase " << tot * BLOCK_SIZE<<std::endl;
			std::cout<<"alloc: "<<alloc_+reused_<<"(reused="<<reused_<<", real_alloc="<<alloc_<<")"<<std::endl;
			std::cout<<"delete: "<<deleted_<<std::endl;
			if (deleted_!=alloc_+reused_)
			{
				std::cout<<"bad!!! new and delete is not equal in your code,check it!"<<std::endl;
				for (int i=0;i<MAX_INDEX_CNT;++i)
				{
					if(deleted_vec_[i]!=alloc_vec_[i]+reused_vec_[i])
					{
						std::cout <<"~~bad index="<<i<<",Size=" <<i*BLOCK_SIZE<< ",Capacity=" << mem_.capacity(i)
							<<"; alloc:"<<alloc_vec_[i]
						<<", deleted:"<<deleted_vec_[i]
						<<", reused:"<<reused_vec_[i]
						<<std::endl;
					}
				}
				assert(0);
			}
			else
				std::cout<<"good!"<<std::endl;
			system("pause");

		};
		);

	private:
		MEMORY_POOL_DEBUG( 
			size_t reused_;
		size_t alloc_;
		size_t deleted_;
		size_t reused_vec_[MAX_INDEX_CNT+1];
		size_t alloc_vec_[MAX_INDEX_CNT+1];
		size_t deleted_vec_[MAX_INDEX_CNT+1];
		);

		mutex_type mutex_;
		PtrPtrVec mem_;
#undef MEMORY_POOL_DEBUG
	};

} // namespace p2engine

#if defined(_MSC_VER)
# pragma warning (pop)
#endif

#endif // p2engine_BASIC_MEMORY_POOL_HPP
