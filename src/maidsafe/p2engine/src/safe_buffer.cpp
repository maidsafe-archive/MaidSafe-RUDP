#include "p2engine/safe_buffer.hpp"

namespace p2engine{
	//////////////////////////////////////////////////////////////////////////
	//safe_buffer_base
	//////////////////////////////////////////////////////////////////////////
	void safe_buffer_base::reserve(std::size_t len)
	{
		if (len==0)
			len=1;
		if (!raw_buffer_)
		{
			raw_buffer_=raw_buffer::create(len);
			gptr(raw_buffer_->buffer());
			pptr(raw_buffer_->buffer());
		}
		else if(capacity()<len)
		{
			std::size_t n=size();
			raw_buffer_->realloc(len);
			gptr(raw_buffer_->buffer());
			pptr(raw_buffer_->buffer()+n);
		}
	}

	safe_buffer_base safe_buffer_base::clone() const
	{
		if (raw_buffer_)
		{
			safe_buffer_base buf(size());
			std::memcpy(buf.gptr(), gptr(), size());
			return buf;
		}
		else
		{
			return safe_buffer_base();
		}
	}

	//////////////////////////////////////////////////////////////////////////
	//safe_buffer
	//////////////////////////////////////////////////////////////////////////
	safe_buffer safe_buffer::buffer_ref(std::ptrdiff_t byte_offset,
		std::size_t buffer_length ) const
	{
		BOOST_ASSERT(raw_buffer_ != NULL);
		if (buffer_length == (std::numeric_limits<std::size_t>::max)())
			buffer_length = buffer_len() - byte_offset;
		BOOST_ASSERT((std::ptrdiff_t)buffer_length+byte_offset<= (std::ptrdiff_t)buffer_len());
		BOOST_ASSERT(byte_offset>=0||g_ptr_+byte_offset>=raw_buffer_->buffer());

		safe_buffer buf(*this);
		buf.g_ptr_+=byte_offset;
		buf.pptr(buf.gptr()+buffer_length);

		return buf;
	}

	std::size_t safe_buffer::memset(boost::uint8_t byte_val, 
		std::size_t len , 
		std::size_t byte_offset)
	{
		BOOST_ASSERT(raw_buffer_ != NULL);
		BOOST_ASSERT(byte_offset <= length());
		if (len == (std::numeric_limits<std::size_t>::max)())
			len = pptr()-(gptr() + byte_offset);
		BOOST_ASSERT(byte_offset+len<=length());
		std::memset(gptr() + byte_offset, byte_val, len);
		return len;
	}

}//namespace p2engine
