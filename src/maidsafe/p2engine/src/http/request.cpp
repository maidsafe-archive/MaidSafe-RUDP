//
// request.cpp
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

#include <cctype>
#include <exception>
#include <iostream>
#include "p2engine/uri.hpp"
#include "p2engine/http/request.hpp"

using namespace std;
namespace p2engine { namespace http{

	request::request()
		:m_method(HTTP_METHORD_GET)
		,m_strUri("/")
	{
	}

	/*
	request::request(const request&h)
	:header(h)
	,m_method(h.m_method)
	,m_strUri(h.m_strUri)
	{
	}
	*/
	request::request(const std::string& version)
		:header(version)
		,m_method(HTTP_METHORD_GET)
		,m_strUri("/")
	{
	}


	request::request(const std::string& method, const std::string& u)
		:m_method(method)
	{
		url(u);
	}


	request::request(const std::string& method, const std::string& u, const std::string& version)
		:header(version)
		,m_method(method)
	{
		url(u);
	}


	request::~request()
	{
	}
	/*
	request& request::operator=(const request&h)
	{
	if (this!=&h)
	{
	m_method=h.m_method;
	m_strUri=h.m_strUri;
	header.operator=(h);
	}

	}
	*/

	void request::clear()
	{
		m_method.clear();
		m_strUri.clear();
		header::clear();
	}
	
	void request::url(const std::string& s)
	{
		error_code ec;
		p2engine::uri u=p2engine::uri::from_string(s,ec);
		if (!ec)//完整url
		{
			m_strUri = u.to_string(p2engine::uri::all_components
				&~p2engine::uri::protocol_component
				&~p2engine::uri::host_component);
			host(u.host());
		}
		else//不完整url
		{
			m_strUri = s;
		}
	}


	void request::host(const std::string& s, unsigned short port)
	{
		if (port !=80)//Http默认端口80
		{
			std::string v;
			try
			{
				v.reserve(s.length()+8);
				v+=s;
				v+=':';
				v+=boost::lexical_cast<std::string>(port);
			}
			catch (...)
			{
			}
			host(v);
		}
		host(s);
	}

	unsigned short request::port()const
	{
		const std::string& h=host();
		if (std::string::size_type pos=h.find(":")!=std::string::npos)
		{
			try
			{
				return boost::lexical_cast<unsigned short>(h.c_str()+pos+1);
			}
			catch (...)
			{
				return 80;
			}
		}
		return 80;
	}


	void request::get_credentials(std::string& scheme, std::string& authInfo) const
	{
		scheme.clear();
		authInfo.clear();
		const std::string& auth = get(HTTP_ATOM_Authorization);
		if (!auth.empty())
		{
			const std::string& auth = get(HTTP_ATOM_Authorization);
			std::string::const_iterator it  = auth.begin();
			std::string::const_iterator end = auth.end();
			while (it != end && std::isspace(*it)) 
				++it;
			while (it != end && !std::isspace(*it)) 
				scheme += *it++;
			while (it != end && std::isspace(*it)) 
				++it;
			while (it != end) 
				authInfo += *it++;
		}
	}


	void request::set_credentials(const std::string& scheme, const std::string& authInfo)
	{
		std::string auth;
		auth.reserve(scheme.length()+authInfo.length()+1);
		auth+=scheme;
		auth+=' ';
		auth+=authInfo;
		set(HTTP_ATOM_Authorization, auth);
	}

	int request::write(std::string& str) const
	{
		ostringstream ostr;
		int l=write(ostr);
		str=ostr.str();
		return l;
	}

	int request::write(std::ostream& ostr) const
	{
		std::ostream::off_type len=ostr.tellp();
		//OutputAssert(!host().empty());
		ostr << m_method << " " <<m_strUri<< " " << version() << "\r\n";
		if(header::write(ostr)<0)
			return -1;
		ostr << "\r\n";
		return static_cast<int>(ostr.tellp()-len);
	}

	int request::read(const char* begin,std::size_t len)
	{
		m_readPtr=begin;
		m_readEndPtr=begin+len;
		for (;m_readPtr!=m_readEndPtr;++m_readPtr)
		{
			switch (m_parseState)
			{
			case FIRSTLINE_1:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_method.empty())
						break;
					else if (m_method.length()>MAX_METHOD_LENGTH)
						return -1;
					else
					{
						m_parseState=FIRSTLINE_2;
						break;
					}
				}
				else if (!isupper(*m_readPtr))
				{
					return -1;
				}
				m_method+=*m_readPtr;
				break;
			case FIRSTLINE_2:
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_strUri.empty())
						break;
					else 
					{
						m_parseState=FIRSTLINE_3;
						break;
					}
				}
				m_strUri+=*m_readPtr;
				break;
			case FIRSTLINE_3:
				if (m_strUri.empty())
				{
					return -1;
				}
				if (*m_readPtr==' '||*m_readPtr=='\t')
				{
					if (m_version.empty())
						break;
					else
						m_parseState=PARSER_KEY;
					break;
				}
				if (*m_readPtr=='\r'||*m_readPtr=='\n')
				{
					m_parseState=PARSER_KEY;
					--m_readPtr;//使得header::read能正确计算连续的'\r''\n'的个数
					break;
				}
				m_version+=*m_readPtr;
				if (m_version.length()>MAX_VERSION_LENGTH)
					return -1;
				break;
			default:
				return header::read(m_readPtr,len-(m_readPtr-begin));
			}
		}
		return 0;
	}

	int request::read(std::istream& istr)
	{
		char eof=std::char_traits<char>::eof();
		std::istream::off_type len=istr.tellg();
		std::string m;
		std::string u;
		std::string v;
		int ch = istr.get();
		if (ch == eof) 
		{
			//OutputError("No Message!\n");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();
		if (ch == eof) 
		{
			//OutputError("No HTTP request header");
			return -1;
		}
		while (!std::isspace(ch) 
			&& ch != eof 
			&& m.length() < MAX_METHOD_LENGTH
			) 
		{
			m += (char) ch; 
			ch = istr.get(); 
		}
		if (!std::isspace(ch)) 
		{
			//OutputError("HTTP request method invalid or too long");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();
		while (!std::isspace(ch) 
			&& ch != eof 
			&& u.length() < MAX_URI_LENGTH
			) 
		{ 
			u += (char) ch; 
			ch = istr.get(); 
		}
		if (!std::isspace(ch)) 
		{
			//OutputError("HTTP request URI invalid or too long!\n");
			return -1;
		}
		while (std::isspace(ch)) 
			ch = istr.get();
		while (
			!std::isspace(ch) 
			&& ch != eof 
			&& v.length() < MAX_VERSION_LENGTH
			) 
		{ 
			v += (char) ch; 
			ch = istr.get(); 
		}
		if (!std::isspace(ch))
		{
			//OutputError("Invalid HTTP version string");
			return -1;
		}
		while (ch != '\n' && ch != eof) 
		{ 
			ch = istr.get(); 
		}
		if (header::read(istr)<0)
		{
			return -1;
		}
		ch = istr.get();
		while (ch != '\n' && ch != eof) 
		{ 
			ch = istr.get(); 
		}
		method(m);
		url(u);
		version(v);
		return static_cast<int>(istr.tellg()-len);
	}


}
}