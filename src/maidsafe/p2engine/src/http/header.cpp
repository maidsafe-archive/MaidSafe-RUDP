//
// header.hpp
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

#include <iostream>
#include <cctype>
#include <exception>
#include <sstream>
#include "p2engine/http/header.hpp"
using namespace std;

namespace p2engine { namespace http{
	//
#define HTTP_ATOM_DEFINE
#include "p2engine/http/atom.hpp"
#undef HTTP_ATOM_DEFINE


	const std::string header::m_nullString;

	header::header()
		:m_version(HTTP_VERSION_1_0)
		,m_parseState(FIRSTLINE_1)
		,m_iCRorLFcontinueNum(0)
	{
	}

	header::header(const std::string& version)
		:m_version(version)
	{
	}
	/*
	header::header(const header&h)
	:m_mapNameValue(h.m_mapNameValue)
	,m_version(h.m_version)
	,m_parseState(h.m_parseState)
	,m_key(h.m_key)
	,m_value(h.m_value)
	,m_readPtr(h.m_readPtr)
	,m_readEndPtr(h.m_readEndPtr)
	{
	}
	/*
	header& header::operator= (const header&h)
	{
	if (this!=&h)
	{
	m_mapNameValue=h.m_mapNameValue;
	m_version=h.m_version;
	m_parseState=h.m_parseState;
	m_key=h.m_key;
	m_value=h.m_value;
	m_readPtr=h.m_readPtr;
	m_readEndPtr=h.m_readEndPtr;
	}
	return *this;
	}
	*/

	header::~header()
	{
	}

	const std::string& header::get(const std::string&name ) const
	{
		map_type::const_iterator itr=m_mapNameValue.find(name);
		if (itr!=m_mapNameValue.end())
			return itr->second;
		return m_nullString;
	}


	const std::string& header::get(const std::string&name,const std::string& defauleValue) const
	{
		map_type::const_iterator itr=m_mapNameValue.find(name);
		if (itr!=m_mapNameValue.end())
			return itr->second;
		return defauleValue;
	}

	void header::clear()
	{
		m_mapNameValue.clear();
		m_version.clear();
		m_key.clear();
		m_value.clear();
		m_readPtr=NULL;
		m_readEndPtr=NULL;
		m_iCRorLFcontinueNum=0;
		m_parseState=FIRSTLINE_1;
	}

	int header::write(std::ostream& ostr) const
	{
		std::ostream::pos_type len=ostr.tellp();
		map_type::const_iterator itr =m_mapNameValue.begin();
		for(;itr != m_mapNameValue.end();itr++)
		{
			ostr <<itr->first << ": " << itr->second<<"\r\n";
		}
		return  static_cast<int>(ostr.tellp()-len);
	}

	int header::write(std::string& str) const
	{
		std::ostringstream ostr;
		int l=write(ostr);
		str=ostr.str();
		return l;
	}

	int header::read(const char* begin,std::size_t len)
	{
		if (len==0)
			return 0;
		m_readPtr=begin;
		m_readEndPtr=begin+len;
		for (;m_readPtr!=m_readEndPtr;++m_readPtr)
		{
			switch (m_parseState)
			{
			case PARSER_KEY:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_key.empty())
						break;
					else 
						return -1;
				}
				//容错
				if (*m_readPtr=='\n'||*m_readPtr=='\r')
				{
					m_iCRorLFcontinueNum++;
					if (m_iCRorLFcontinueNum==4)
					{
						++m_readPtr;
						return 1;
					}
					if(!m_key.empty())
						m_key.clear();
					break;
				}
				//读取m_key
				if(*m_readPtr != ':' 
					&&m_key.length() < MAX_NAME_LENGTH
					) 
				{ 
					if (m_iCRorLFcontinueNum==3)
						return 1;
					m_iCRorLFcontinueNum=0;
					m_key += *m_readPtr; 
					break;
				}
				else if (*m_readPtr== ':')
				{
					if (m_iCRorLFcontinueNum==3)
						return -1;
					m_iCRorLFcontinueNum=0;
					m_parseState=PARSER_VALUE;
					break;
				}
				else
				{
					m_iCRorLFcontinueNum=0;
					//OutputError("header field name too long; no colon found!");
					return -1;
				}
			case PARSER_VALUE:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_value.empty())
						break;
					else 
						m_value += *m_readPtr; 
					break;
				}
				//读取value
				if(*m_readPtr!= '\r' 
					&&*m_readPtr!= '\n' 
					&& m_key.length() < MAX_NAME_LENGTH
					) 
				{ 
					if (m_iCRorLFcontinueNum==3)
						return 1;
					m_iCRorLFcontinueNum=0;
					m_value += *m_readPtr; 
					break;
				}
				else if (
					*m_readPtr=='\r'
					||*m_readPtr=='\n'
					)
				{
					m_iCRorLFcontinueNum++;
					m_parseState=PARSER_KEY;
					if (!m_key.empty()&&!m_value.empty())
					{
						m_mapNameValue.insert(make_pair(m_key, m_value));
						m_key.clear();
						m_value.clear();
					}
					break;
				}
				else
				{
					////OutputError("header field name too long; no colon found!");
					return -1;
				}
			}
		}
		return 0;
	}


	int header::read(std::istream& istr)
	{
		static const int eof = std::char_traits<char>::eof();
		std::string name;
		std::string value;

		std::istream::pos_type len=istr.tellg();

		name.reserve(128);
		value.reserve(128);

		char ch = istr.get();
		while (ch != eof 
			&& ch != '\r' 
			&& ch != '\n'
			)
		{
			name.clear();
			value.clear();
			//读取name
			while (ch != eof 
				&& ch != ':' 
				&& ch != '\n' 
				&& name.length() < MAX_NAME_LENGTH
				) 
			{ 
				name += ch; 
				ch = istr.get(); 
			}
			//没有找到":"就出现"\n",忽略这一错误
			if (ch == '\n')
			{ 
				ch = istr.get(); 
				continue; 
			} 
			//没有找到":"
			if (ch != ':') 
			{
				//OutputError("header field name too long; no colon found!");
				return -1;
			}
			// 读取':'下一个字符
			if (ch != eof) 
				ch = istr.get(); 
			//越过空格
			while (std::isspace(ch)) 
				ch = istr.get();

			//读取value
			while (ch != eof 
				&& ch != '\r' 
				&& ch != '\n' 
				&& value.length() < MAX_VALUE_LENGTH
				) 
			{ 
				value += ch; 
				ch = istr.get(); 
			}
			if (ch == '\r') 
				ch = istr.get();
			if (ch == '\n')
				ch = istr.get();
			else if (ch != eof)
			{
				//OutputError("header field value too long; no CRLF found!");
				return -1;
			}
			while (ch == ' ' || ch == '\t') // folding
			{
				while (ch != eof 
					&& ch != '\r' 
					&& ch != '\n' 
					&& value.length() < MAX_VALUE_LENGTH) 
				{ 
					value += ch; 
					ch = istr.get(); 
				}
				if (ch == '\r') 
					ch = istr.get();
				if (ch == '\n')
					ch = istr.get();
				else if (ch != eof)
				{
					//OutputError("header folded field value too long/no CRLF found!");
					return -1;
				}
			}
			//std::cout<<name<<"    "<<value<<std::endl;
			m_mapNameValue.insert(make_pair(name, value));
		}
		istr.putback(ch);
		return static_cast<int>(istr.tellg()-len);
	}

	void header::content_length(int64_t length)
	{
		if (length >0)
		{
			std::ostringstream ostrm;
			ostrm<<length;
			this->set(HTTP_ATOM_Content_Length,ostrm.str());
		}
		else
			erase(HTTP_ATOM_Content_Length);
	}

	int64_t header::content_length() const
	{
		map_type::const_iterator itr=m_mapNameValue.find(HTTP_ATOM_Content_Length);
		if (itr!=m_mapNameValue.end())
		{
			const char* p=itr->second.c_str();
			if (!isdigit(*p))
				return -1;
			std::istringstream istrm(itr->second);
			int64_t len=0;
			istrm>>len;
			return len;
		}
		return -1;
	}

	void header::transfer_encoding(const std::string& transferEncoding)
	{
		if (transferEncoding==IDENTITY_TRANSFER_ENCODING)
			erase(HTTP_ATOM_Transfer_Encoding);
		else
			set(HTTP_ATOM_Transfer_Encoding, transferEncoding);
	}


	const std::string& header::transfer_encoding() const
	{
		map_type::const_iterator itr=m_mapNameValue.find(HTTP_ATOM_Transfer_Encoding);
		if (itr!=m_mapNameValue.end())
			return itr->second;
		else
			return IDENTITY_TRANSFER_ENCODING;
	}


	void header::chunked_transfer_encoding(bool flag)
	{
		if (flag)
			set(HTTP_ATOM_Transfer_Encoding, CHUNKED_TRANSFER_ENCODING);
		else
			erase(HTTP_ATOM_Transfer_Encoding);
	}

	void header::content_type(const std::string& mediaType)
	{
		if (mediaType.empty())
			erase(HTTP_ATOM_Content_Type);
		else
			set(HTTP_ATOM_Content_Type, mediaType);
	}


	void header::keep_alive(bool keepAlive)
	{
		if (keepAlive)
			set(HTTP_ATOM_Connection, CONNECTION_KEEP_ALIVE);
		else
			set(HTTP_ATOM_Connection, CONNECTION_CLOSE);
	}


	bool header::keep_alive() const
	{
		const string& keeyAlive=get(HTTP_ATOM_Connection);
		if (keeyAlive.empty())
			return  version() == HTTP_VERSION_1_1;
		else
			return keeyAlive==CONNECTION_KEEP_ALIVE;
	}


}
}
