//
// safe_buffer.hpp
// ~~~~~~~~~~~~~~~~~~~~~~~~~~
//
// Copyright (c) 2009-2010  GuangZhu Wu
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
//
// THANKS  Meng Zhang <albert.meng.zhang@gmail.com>
//

#ifndef P2ENGINE_SAFE_BUFFER_HPP
#define P2ENGINE_SAFE_BUFFER_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"
#include <boost/asio.hpp>
#include "p2engine/pop_warning_option.hpp"

#include "p2engine/typedef.hpp"
#include "p2engine/raw_buffer.hpp"

namespace p2engine {

	struct buffer_cast_helper;
	class safe_buffer_io;
	class safe_stream_buffer;
	class asio_const_buffer;
	class asio_mutable_buffer;
	class asio_const_buffers_1;
	class asio_mutable_buffers_1;
	struct buffer_cast_helper;
	class safe_buffer;
	class safe_buffer_io;
	class safe_stream_buffer;

	class safe_buffer_base
	{
		friend class asio_const_buffer;
		friend class asio_mutable_buffer;
		friend class asio_const_buffers_1;
		friend class asio_mutable_buffers_1;
		friend struct buffer_cast_helper;
		typedef boost::intrusive_ptr<raw_buffer> raw_buffer_type;
		friend class safe_buffer;
		friend class safe_buffer_io;
		friend class safe_stream_buffer;
		enum{FRONT_BLANK_SIZE=4};
	public:
		template <class OStream>
		OStream& dump(OStream& os, bool dump_as_char = false,
			size_t trucated_len = ((std::numeric_limits<size_t>::max))(),
			size_t bytes_per_line = static_cast<size_t>(0x10)) const
		{
			if (!raw_buffer_)
			{
				os <<"<null>"<<std::endl;
			}
			else
			{
				os <<"<<"<<(int)buf_ptr()<<">>"<<std::endl;
				assert(trucated_len == ((std::numeric_limits<size_t>::max))() ||
					trucated_len <= this->buffer_len());
				if (this->buffer_len() == 0)
				{
					os <<"<null>"<<std::endl;
				}
				else
				{
					size_t offset;
					for(offset = 0; offset < (std::min)(trucated_len, this->buffer_len());
						++ offset)
					{
						if (offset % bytes_per_line == 0)
						{
							os.fill('0');
							os.width(sizeof(boost::uint32_t) * 2);
							os <<std::hex<<std::uppercase<<static_cast<boost::uint32_t>(offset)
								<<"h:";
						}
						boost::uint8_t byte_val = *(pptr()+ offset);
						os <<" ";
						os.fill('0');
						os.width(sizeof(char) * 2);
						os <<std::hex<<std::uppercase<<static_cast<unsigned long>(static_cast<unsigned char>(byte_val));
						if (offset % bytes_per_line == bytes_per_line - 1)
						{
							if (dump_as_char)
							{
								os <<" ; ";
								for(size_t i = offset + 1 - bytes_per_line; i <= offset; ++ i)
									os <<static_cast<char>(*(gptr() + i));
							}
							os <<std::endl;
						}
					}
					if (offset % bytes_per_line != 0)
					{
						os <<std::endl;
					}
				}
			}
			os.width(0); os.fill(' '); os <<std::dec;
			os.flush();
			return os;
		}

		void reset()
		{
			raw_buffer_.reset();
			gptr(NULL);
			pptr(NULL);
		}

		void resize(size_t len)
		{
			reserve(len);
			pptr(gptr()+len);
		}

		size_t capacity()const
		{
			if (raw_buffer_)
			{
				return raw_buffer_->length()-(gptr()-raw_buffer_->buffer());
			}
			return 0;
		}

		void clear()
		{
			if (raw_buffer_)
			{
				gptr(raw_buffer_->buffer());
				pptr(raw_buffer_->buffer());
			}
			else
			{
				gptr(NULL);
				pptr(NULL);
			}
		}

		void reallocate(size_t len)
		{
			raw_buffer_ = raw_buffer::create(len);
			gptr(raw_buffer_->buffer());
			pptr(raw_buffer_->buffer()+len);
		}

		void swap(safe_buffer_base&buf)
		{
			raw_buffer_.swap(buf.raw_buffer_);
			std::swap(p_ptr_, buf.p_ptr_);
			std::swap(g_ptr_, buf.g_ptr_);
		}

		size_t size() const 
		{
			return buffer_len();
		};

		operator bool() const
		{
			assert(this->raw_buffer_ || (this->gptr()== NULL && this->pptr()== NULL));
			return this->raw_buffer_!=NULL;
		}

		virtual ~safe_buffer_base(){}

		safe_buffer_base& operator=(const safe_buffer_base& buf)
		{
			this->reset(buf);
			return *this;
		}
	protected:
		safe_buffer_base():p_ptr_(NULL),g_ptr_(NULL)
		{
		}
		explicit safe_buffer_base(size_t len)
			: raw_buffer_(raw_buffer::create(((std::max))(len,(size_t)128)))
		{
			gptr(raw_buffer_->buffer());
			pptr(raw_buffer_->buffer()+len);
		}
		safe_buffer_base(const safe_buffer_base &buf,
			size_t trucated_len = ((std::numeric_limits<size_t>::max))())
		{
			//this->set_obj_desc("safe_buffer_base");
			this->reset(buf, trucated_len);
		}
		void reset(const safe_buffer_base &buf,
			size_t trucated_len = ((std::numeric_limits<size_t>::max))())
		{
			raw_buffer_ = buf.raw_buffer_;
			g_ptr_ = buf.g_ptr_;
			p_ptr_ = g_ptr_+(std::min)(buf.buffer_len(), trucated_len);
		}
		void* buf_ptr() const
		{
			if (!raw_buffer_)
				return NULL;
			return reinterpret_cast<void *>(g_ptr_);
		}
		void consume(size_t n)
		{
			assert(size()>=n);
			g_ptr_+=n;
		}
		void commit(size_t n)
		{
			assert(capacity()>=n+size());
			p_ptr_+=n;
		}
		size_t buffer_len() const 
		{
			if (!raw_buffer_)
				return 0;
			assert(raw_buffer_->length() >=(size_t)(p_ptr_ - g_ptr_));
			return p_ptr_ - g_ptr_;
		};
		//char& operator[](size_t i)
		//{ 
		//	assert(i < size()); 
		//	return *(char*)(p_ptr_+i);
		//}
		//char const& operator[](size_t i) const 
		//{
		//	assert(i < size()); 
		//	return *(const char*)(p_ptr_+i);
		//}

		char* gptr()const
		{
			return g_ptr_; 
		}
		void gptr(char* p)
		{
			BOOST_ASSERT(!p
				||(p>=raw_buffer_->buffer())&&(p<raw_buffer_->buffer()+raw_buffer_->length())
				);
			g_ptr_=p;
		}
		char* pptr()const
		{
			return p_ptr_; 
		}
		void pptr(char* p)
		{
			BOOST_ASSERT(!p
				||(p>=raw_buffer_->buffer())&&(p<=raw_buffer_->buffer()+raw_buffer_->length())//<=
				);
			p_ptr_=p;
		}
		const char* raw_buffer_ptr()const
		{
			return raw_buffer_->buffer();
		}
		char* raw_buffer_ptr()
		{
			return raw_buffer_->buffer();
		}

		void reserve(size_t len);

		safe_buffer_base clone() const;
	protected:
		raw_buffer_type raw_buffer_;
		char* p_ptr_;
		char* g_ptr_;
	};

	template<class OStream>
	inline OStream& operator<<(OStream& os, const safe_buffer_base& buf)
	{
		return buf.dump(os);
	}

	class asio_const_buffer : public boost::asio::const_buffer
	{
	public:
		asio_const_buffer(const safe_buffer_base &buf, size_t trucated_len)
			: boost::asio::const_buffer(buf.buf_ptr(), trucated_len), safe_buffer_base_(buf)
		{
			assert(trucated_len <= buf.buffer_len());
		}
		asio_const_buffer(const safe_buffer_base &buf, size_t offset,
			size_t trucated_len) 
			: boost::asio::const_buffer((char*)buf.buf_ptr()+offset, trucated_len)
			, safe_buffer_base_(buf)
		{
			assert(trucated_len+offset <= buf.buffer_len());
		}
		asio_const_buffer(const asio_const_buffer &buf)
			: boost::asio::const_buffer(buf.safe_buffer_base_.buf_ptr(), buf.safe_buffer_base_.buffer_len()),
			safe_buffer_base_(buf.safe_buffer_base_)
		{};
	private:
		safe_buffer_base safe_buffer_base_;
	};

	class asio_mutable_buffer : public boost::asio::mutable_buffer
	{
	public:
		asio_mutable_buffer(const safe_buffer_base &buf, size_t trucated_len)
			: boost::asio::mutable_buffer(buf.buf_ptr(), trucated_len), safe_buffer_base_(buf)
		{
			assert(trucated_len <= buf.buffer_len());
		}
		asio_mutable_buffer(const safe_buffer_base &buf, size_t offset,
			size_t trucated_len) 
			: boost::asio::mutable_buffer((char*)buf.buf_ptr()+offset, trucated_len), safe_buffer_base_(buf)
		{
			assert(trucated_len+offset <= buf.capacity());
		}
		asio_mutable_buffer(const asio_mutable_buffer &buf)
			: boost::asio::mutable_buffer(buf.safe_buffer_base_.buf_ptr(), buf.safe_buffer_base_.buffer_len()),
			safe_buffer_base_(buf.safe_buffer_base_)
		{};
	private:
		safe_buffer_base safe_buffer_base_;
	};

	class asio_const_buffers_1 : public boost::asio::const_buffers_1
	{
	public:
		asio_const_buffers_1(const safe_buffer_base &buf, size_t trucated_len)
			: boost::asio::const_buffers_1(buf.buf_ptr(), trucated_len), safe_buffer_base_(buf)
		{
			assert(trucated_len <= buf.buffer_len());
		}
		asio_const_buffers_1(const asio_const_buffers_1 &buf)
			: boost::asio::const_buffers_1(buf.safe_buffer_base_.buf_ptr(), buf.safe_buffer_base_.buffer_len()),
			safe_buffer_base_(buf.safe_buffer_base_)
		{};
	private:
		safe_buffer_base safe_buffer_base_;
	};

	class asio_mutable_buffers_1 : public boost::asio::mutable_buffers_1
	{
	public:
		asio_mutable_buffers_1(const safe_buffer_base &buf, size_t trucated_len)
			: boost::asio::mutable_buffers_1(buf.buf_ptr(), trucated_len), safe_buffer_base_(buf)
		{
			assert(trucated_len <= buf.buffer_len());
		}
		asio_mutable_buffers_1(const asio_mutable_buffers_1 &buf)
			: boost::asio::mutable_buffers_1(buf.safe_buffer_base_.buf_ptr(), buf.safe_buffer_base_.buffer_len()),
			safe_buffer_base_(buf.safe_buffer_base_)
		{};
	private:
		safe_buffer_base safe_buffer_base_;
	};

	class basic_safe_buffer : public safe_buffer_base
	{
		friend class const_asio_safe_buffer;
		friend class mutable_asio_safe_buffer;
		friend class safe_buffer_io;
	protected:
		basic_safe_buffer() : safe_buffer_base() {};
		basic_safe_buffer(size_t len) : safe_buffer_base(len) {};
		basic_safe_buffer(const safe_buffer_base &buf,
			size_t trucated_len = (std::numeric_limits<size_t>::max)())
			: safe_buffer_base(buf, trucated_len) {};
	public:
		asio_const_buffer to_asio_const_buffer(size_t trucated_len = (std::numeric_limits<size_t>::max)()) const
		{
			assert(raw_buffer_);
			assert(trucated_len == (std::numeric_limits<size_t>::max)() || trucated_len <= buffer_len());
			return asio_const_buffer(*this, (trucated_len == (std::numeric_limits<size_t>::max)()) ? buffer_len() : trucated_len);
		};
		asio_mutable_buffer to_asio_mutable_buffer(size_t trucated_len = (std::numeric_limits<size_t>::max)()) const
		{
			assert(raw_buffer_);
			assert(trucated_len == (std::numeric_limits<size_t>::max)() || trucated_len <= buffer_len());
			return asio_mutable_buffer(*this, (trucated_len == (std::numeric_limits<size_t>::max)()) ? buffer_len() : trucated_len);
		};
		asio_const_buffers_1 to_asio_const_buffers_1(size_t trucated_len = (std::numeric_limits<size_t>::max)()) const
		{
			assert(raw_buffer_);
			assert(trucated_len == (std::numeric_limits<size_t>::max)() || trucated_len <= buffer_len());
			return asio_const_buffers_1(*this, (trucated_len == (std::numeric_limits<size_t>::max)()) ? buffer_len() : trucated_len);
		};
		asio_mutable_buffers_1 to_asio_mutable_buffers_1(size_t trucated_len = (std::numeric_limits<size_t>::max)()) const
		{
			assert(raw_buffer_);
			assert(trucated_len == (std::numeric_limits<size_t>::max)() || trucated_len <= buffer_len());
			return asio_mutable_buffers_1(*this, (trucated_len == (std::numeric_limits<size_t>::max)()) ? buffer_len() : trucated_len);
		};
	};

	template <typename T>
	class safe_array_buffer : public basic_safe_buffer
	{
	protected:
		friend class safe_buffer;
		safe_array_buffer() : basic_safe_buffer() {};
	public:
		safe_array_buffer(size_t n) : basic_safe_buffer(n * sizeof(T)) {};
		safe_array_buffer(const safe_buffer_base &buf,
			size_t trucated_len = (std::numeric_limits<size_t>::max)())
			: basic_safe_buffer(buf, trucated_len) {};
		safe_array_buffer & operator=(const safe_buffer_base &buf)
		{
			safe_buffer_base::reset(buf);
			return *this;
		}
		T & operator[](size_t n) const
		{
			return *(reinterpret_cast<T *>(gptr()+n*sizeof(T)));
		}
		safe_array_buffer<T> clone() const
		{
			safe_array_buffer<T> buf(safe_buffer_base::clone());
			return buf;
		}
	};

	class safe_buffer : public basic_safe_buffer
	{
	public:
		safe_buffer() : basic_safe_buffer() {};
		safe_buffer(size_t len) : basic_safe_buffer(len) {};
		safe_buffer(const safe_buffer_base &buf,size_t trucated_len = (std::numeric_limits<size_t>::max)()) 
			:basic_safe_buffer(buf, trucated_len) {};

		safe_buffer & operator=(const safe_buffer& buf)
		{
			safe_buffer_base::reset(buf);
			return *this;
		}

		safe_buffer buffer_ref(std::ptrdiff_t byte_offset,
			size_t buffer_length = (std::numeric_limits<size_t>::max)()) const;

		template<typename T>
		safe_array_buffer<T> to_array_buffer(size_t byte_offset = 0) const
		{
			assert(this->raw_buffer_ != NULL);
			assert(byte_offset+sizeof(T)<=this->buffer_len());

			safe_array_buffer<T> arr_buf(*this);
			arr_buf.consume(byte_offset);

			return arr_buf;
		}

		size_t length() const
		{
			return safe_buffer_base::buffer_len();
		}

		using safe_buffer_base::size;

		template <typename T>
		T get(size_t byte_offset = 0) const
		{
			assert(this->raw_buffer_ != NULL);
			assert(gptr()+byte_offset + sizeof(T) <= pptr());
			return *(reinterpret_cast<T *>(gptr()+byte_offset));
		}
		template <typename T>
		void set(const T &val, size_t byte_offset = 0)
		{
			assert(this->raw_buffer_ != NULL);
			assert(gptr() + byte_offset + sizeof(T) <= pptr());
			*(reinterpret_cast<T *>(gptr()+byte_offset))=val;
		}
		template <typename T>
		T get_nth_elem(size_t n, size_t byte_offset = 0) const
		{
			return get<T>(byte_offset+n*sizeof(T));
		}
		template <typename T>
		void set_nth_elem(size_t n, const T &val, size_t byte_offset = 0)
		{
			return set<T>(val,byte_offset+n*sizeof(T));
		}
		size_t get_data(void * buf, size_t buf_size, size_t len, size_t byte_offset = 0) const
		{
			assert(this->raw_buffer_ != NULL);
			assert(buf_size >= len);
			assert(length()>=byte_offset);
			size_t true_len = (std::min)(len, length()-byte_offset);
			std::memcpy(buf, gptr()+byte_offset, true_len);
			return true_len;
		}
		void set_data(const void * buf, size_t len, size_t byte_offset = 0)
		{
			assert(this->raw_buffer_ != NULL);
			assert(byte_offset+len<=length());
			std::memcpy(gptr()+ byte_offset, buf, len);
		}
		size_t get_data(safe_buffer &buf, size_t len, size_t byte_offset = 0) const
		{
			return get_data(buf.buf_ptr(),buf.length(),len,byte_offset);
		}
		void set_data(const safe_buffer& buf, size_t len, size_t byte_offset = 0)
		{
			assert(buf.raw_buffer_ != NULL);
			assert(buf.length() >= len);
			set_data(buf.buf_ptr(),len,byte_offset);
		}

		size_t memset(boost::uint8_t byte_val, size_t len = (std::numeric_limits<size_t>::max)(),
			size_t byte_offset = 0);

		safe_buffer clone() const
		{
			safe_buffer buf(safe_buffer_base::clone());
			return buf;
		}
	};
	struct buffer_cast_helper
	{
		void* operator()(const safe_buffer_base&buf){return buf.buf_ptr();}
	};

	template <typename PointerToPodType>
	inline PointerToPodType buffer_cast(const boost::asio::const_buffer& b)
	{
		return boost::asio::buffer_cast<PointerToPodType>(b);
	}
	inline size_t buffer_size(const boost::asio::const_buffer& b)
	{
		return boost::asio::buffer_size(b);
	}
	template <typename PointerToPodType>
	inline PointerToPodType buffer_cast(const safe_buffer_base& b)
	{
		return static_cast<PointerToPodType>(buffer_cast_helper()(b));
	}
	inline size_t buffer_size(const safe_buffer_base& b)
	{
		return b.size();
	}

	template <class SafeBufferSequence, class ConstAsioBufferSequence>
	void to_asio_const_buffers(const SafeBufferSequence& safe_buffers, 
		ConstAsioBufferSequence& asio_buffers)
	{
		BOOST_STATIC_ASSERT((boost::is_base_of<safe_buffer, typename SafeBufferSequence::value_type>::value));
		asio_buffers.clear();
		asio_buffers.reserve(safe_buffers.size());
		typename SafeBufferSequence::const_iterator iter;
		for(iter = safe_buffers.begin(); iter != safe_buffers.end(); ++ iter)
		{
			asio_buffers.push_back(iter->to_asio_const_buffer());
		}
	}

	template <class SafeBufferSequence, class MutableAsioBufferSequence>
	void to_asio_mutable_buffers(const SafeBufferSequence& safe_buffers, 
		MutableAsioBufferSequence& asio_buffers)
	{
		BOOST_STATIC_ASSERT((boost::is_base_of<safe_buffer, typename SafeBufferSequence::value_type>::value));
		asio_buffers.clear();
		asio_buffers.reserve(safe_buffers.size());
		typename SafeBufferSequence::const_iterator iter;
		for(iter = safe_buffers.begin(); iter != safe_buffers.end(); ++ iter)
		{
			asio_buffers.push_back(iter->to_asio_mutable_buffer());
		}
	}

} // namespace p2engine

#endif // P2ENGINE_SAFE_BUFFER_HPP

