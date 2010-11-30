//
// compressed_bitset.hpp
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

#ifndef P2ENGINE_COMPRESSED_BITSET_HPP
#define P2ENGINE_COMPRESSED_BITSET_HPP

#if defined(_MSC_VER) && (_MSC_VER >= 1200)
# pragma once
#endif // defined(_MSC_VER) && (_MSC_VER >= 1200)

#include "p2engine/push_warning_option.hpp"
#include "p2engine/config.hpp"

#include <boost/dynamic_bitset.hpp>

#include <iostream>

#include "p2engine/io.hpp"

namespace p2engine{

	//一个压缩单位为n个bit，每个压缩单位的第1bit表示一个<原BIT位>的True或False
	//在连续多个<原BIT位>的情况相同时，压缩表示后面的（n-1）bit表示连续的个数。
	//比如在n=8时：
	//一个<原BIT位>为True，但下一个相邻的<原BIT位>为False，表示为0x80（10000000）
	//有15个连续<原BIT位>False，则表示为：0x0f(00001111)
	//有65个连续<原BIT位>True，则表示为:0x91(11000001)
	class compressed_bitset
	{
	public:
		typedef boost::dynamic_bitset<uint8_t> dynamic_bitset;

	private:
		inline void _set_bit(const void *data,uint32_t bitIdx, uint8_t bitVal)
		{
			uint8_t* p=(uint8_t *)data+(bitIdx>>3);//(uint8_t *)data+bitIdx/8
			if (bitVal == 0)
				(*p) &= ~(0x01 << (bitIdx % 8));
			else
				(*p) |= (0x01 << (bitIdx % 8));
		}

		inline void _set_bits(const void *data,uint32_t bitIdx, 
			uint32_t bitCnt, uint32_t val)
		{
			for(uint32_t i = bitIdx; i < bitIdx + bitCnt; ++ i)
			{
				_set_bit(data, i, (uint8_t)(val & 0x1));
				val >>= 1;
			}
		}

		inline uint8_t _get_bit(const void *data,uint32_t bitIdx)
		{
			uint8_t byteVal = *((uint8_t *)data + bitIdx / 8);
			return (byteVal >> (bitIdx % 8)) & 0x01;
		}

		inline uint32_t _get_bits(const void *data, uint32_t bitIdx, 
			unsigned int bitCnt)
		{
			uint32_t res = 0;
			for(unsigned int i = bitIdx; i < bitIdx + bitCnt; ++ i)
			{
				res |= (_get_bit(data, i) << (i - bitIdx));
			}
			return res;
		}
		//压缩
		template<class T>
		bool _commpless_to_buf(T&compressedBuf,size_t bits,size_t stop)
		{
			BOOST_STATIC_ASSERT(sizeof(T::value_type)==1);
			int k=0;
			compressedBuf.clear();
			//前三个字节中的两个字节表示bitset的长度，第三个表示压缩单位
			compressedBuf.resize(3,0);
			for(size_t i=0;i<bitset_.size();)
			{
				bool velue=bitset_[i];
				uint32_t x=velue?(1<<(bits-1)):0;
				uint32_t maxLen=(0xffffffff)>>(32-bits+1);//所能表示的最大连续bit个数（有一位已经用作标识）
				uint32_t j=0;
				i++;
				while(i<bitset_.size()&&j<maxLen&&bitset_[i]==velue)
				{
					x++;
					j++;
					i++;
				}
				while(k+bits>(compressedBuf.size()-3)*8)
				{
					compressedBuf.push_back(0);
					if(compressedBuf.size()>=stop)
						return false;
				}
				_set_bits(&compressedBuf[0]+3,k,bits,x);
				k+=bits;
			}
			char* p=(char*)&compressedBuf[0];
			write_int16(bitset_.size(),p);
				compressedBuf[2]=bits;
			return true;
		}
	public:
		compressed_bitset(size_t n=0)
			:bitset_(n)
		{
		}
	public:
		//注，非线程安全的！
		template<class T>
		bool compress_to_buf(T&compressedBuf,size_t& bits)
		{
			BOOST_STATIC_ASSERT(sizeof(T::value_type)==1);
			assert(bitset_.size()<0xffff);
			bool comped=false;
			size_t bytes=(bitset_.size()+7)/8;
			T tmp;
			tmp.reserve(bytes);
			bits=1;
			for(size_t i=8;i>1;i--)
			{
				if(_commpless_to_buf(tmp,i,bytes))
				{
					if (comped&&compressedBuf.size()<tmp.size())
					{
						break;
					}
					if(!comped||compressedBuf.size()>tmp.size())
					{
						compressedBuf.clear();
						compressedBuf.assign(tmp.begin(),tmp.end());
						bits=i;
						comped=true;
					}
				}
				tmp.clear();
			}
			return comped;
		}

		void decompress(const void* buf,const size_t bufLen)
		{
			bitset_.clear();
			if (bufLen<3)
				return;

			const uint8_t* p=(const uint8_t* )buf;
			uint32_t bitsetSize=read_uint16(p);//p=p+2; after read
			uint8_t bits=*p;
			p+=1;
			if ((bitsetSize/bits+7)/8+3>bufLen)
				return;

			bitset_.resize(bitsetSize);
			int j=0;
			for(size_t i=0;i<bitset_.size();)
			{
				uint32_t num=(uint32_t)_get_bits(p,j,bits);
				uint32_t v=num&(1<<(bits-1));
				num&=~v;
				bitset_[i++]=(v!=0);
				for(uint32_t k=0;k<num&&i<bitset_.size();k++)
					bitset_[i++]=(v!=0);
				j+=bits;
			}
		}

		const boost::dynamic_bitset<uint8_t>& bitset()const
		{
			return bitset_;
		}

		boost::dynamic_bitset<uint8_t>& bitset()
		{
			return bitset_;
		}

	private:
		boost::dynamic_bitset<uint8_t> bitset_;
	};
}
#include "p2engine/pop_warning_option.hpp"
#endif//P2ENGINE_COMPRESSED_BITSET_HPP