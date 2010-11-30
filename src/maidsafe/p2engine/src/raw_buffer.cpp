#include "p2engine/raw_buffer.hpp"

NAMESPACE_BEGIN(p2engine)

	void raw_buffer::realloc(std::size_t len)
{
	if (len==0)
	{
		if (buffer_)
		{
			memory_pool_type::instance().free(buffer_);
			buffer_=NULL;
		}
	}
	else
	{
		char* oldBuf=buffer_;
		buffer_=(char *)memory_pool_type::instance().malloc(len);
		if (oldBuf)
		{
			memcpy(buffer_,oldBuf,length_);
			memory_pool_type::instance().free(oldBuf);
		}
	}
	length_=len;
}
raw_buffer::raw_buffer(std::size_t length):buffer_(NULL),length_(length)
{
	if (length)
		buffer_=(char *)memory_pool_type::instance().malloc(length);
};

raw_buffer::~raw_buffer()
{
	if (buffer_)
	{
		memory_pool_type::instance().free(buffer_);
		buffer_=NULL;
	}
};
NAMESPACE_END(p2engine)