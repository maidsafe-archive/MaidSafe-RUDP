//
// url.ipp
// ~~~~~~~
//
// Copyright (c) 2009 Christopher M. Kohlhoff (chris at kohlhoff dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//

#include <p2engine/push_warning_option.hpp>
#include <p2engine/config.hpp>
#include <cstring>
#include <cctype>
#include <cstdlib>
#include <boost/throw_exception.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem/path.hpp>
#include <p2engine/pop_warning_option.hpp>

#include "p2engine/uri.hpp"

namespace p2engine {

	unsigned short uri::port() const
	{
		if (!port_.empty())
			return std::atoi(port_.c_str());
		if (protocol_ == "http")
			return 80;
		if (protocol_ == "https")
			return 443;
		if (protocol_ == "ftp")
			return 21;
		if (protocol_ == "ftpes")
			return 21;
		if (protocol_ == "ftps")
			return 990;
		if (protocol_ == "tftp")
			return 69;
		return 0;
	}

	std::string uri::path() const
	{
		std::string tmp_path;
		unescape_path(path_, tmp_path);
		return tmp_path;
	}

	std::string uri::to_string(int components) const
	{
		std::string s;

		if ((components & protocol_component) != 0 && !protocol_.empty())
		{
			s = protocol_;
			s += "://";
		}

		if ((components & user_info_component) != 0 && !user_info_.empty())
		{
			s += user_info_;
			s += "@";
		}

		if ((components & host_component) != 0)
		{
			if (ipv6_host_)
				s += "[";
			s += host_;
			if (ipv6_host_)
				s += "]";
		}

		if ((components & port_component) != 0 && !port_.empty())
		{
			s += ":";
			s += port_;
		}

		if ((components & path_component) != 0 && !path_.empty())
		{
			s += path_;
		}

		if ((components & query_component) != 0 && !query_.empty())
		{
			s += "?";
			s += query_;
		}

		if ((components & fragment_component) != 0 && !fragment_.empty())
		{
			s += "#";
			s += fragment_;
		}

		return s;
	}

	uri uri::from_string(const char* p, boost::system::error_code& ec)
	{
		uri new_url;

		std::string str=normalize(p);
		const char* s=str.c_str();

		// Protocol.
		std::size_t length = std::strcspn(s, ":");
		if (length<str.length()&&(s[length]==':'))
		{
			new_url.protocol_.assign(s, s + length);
			boost::trim(new_url.protocol_);
			boost::to_lower(new_url.protocol_);
			s += length;

			// "://".
			if (*s++ != ':')
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
			if (*s++ != '/')
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
			if (*s++ != '/')
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
		}
		// UserInfo.
		length = std::strcspn(s, "@:[/?#");
		if (s[length] == '@')
		{
			new_url.user_info_.assign(s, s + length);
			s += length + 1;
		}
		else if (s[length] == ':')
		{
			std::size_t length2 = std::strcspn(s + length, "@/?#");
			if (s[length + length2] == '@')
			{
				new_url.user_info_.assign(s, s + length + length2);
				s += length + length2 + 1;
			}
		}
		if (!new_url.user_info_.empty())
		{
			std::string::size_type n=new_url.user_info_.find(':');
			if (n!=std::string::npos)
			{
				new_url.user_name_=new_url.user_info_.substr(0,n);
				if (n<new_url.user_info_.length())
					new_url.user_password_=new_url.user_info_.substr(n+1,new_url.user_info_.length()-n);
			}
		}


		// Host.
		if (*s == '[')
		{
			length = std::strcspn(++s, "]");
			if (s[length] != ']')
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
			new_url.host_.assign(s, s + length);
			new_url.ipv6_host_ = true;
			s += length + 1;
			if (std::strcspn(s, ":/?#") != 0)
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
		}
		else
		{
			length = std::strcspn(s, ":/?#");
			new_url.host_.assign(s, s + length);
			s += length;
		}

		// Port.
		if (*s == ':')
		{
			length = std::strcspn(++s, "/?#");
			if (length == 0)
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
			new_url.port_.assign(s, s + length);
			for (std::size_t i = 0; i < new_url.port_.length(); ++i)
			{
				if (!std::isdigit(new_url.port_[i]))
				{
					ec = make_error_code(boost::system::errc::invalid_argument);
					return uri();
				}
			}
			s += length;
		}

		// Path.
		if (*s == '/')
		{
			length = std::strcspn(s, "?#");
			new_url.path_.assign(s, s + length);
			std::string tmp_path;
			if (!unescape_path(new_url.path_, tmp_path))
			{
				ec = make_error_code(boost::system::errc::invalid_argument);
				return uri();
			}
			s += length;
		}
		else
			new_url.path_ = "/";

		// Query.
		if (*s == '?')
		{
			length = std::strcspn(++s, "#");
			new_url.query_.assign(s, s + length);
			s += length;

			const char* p=new_url.query_.c_str();
			std::vector<std::string> result;
			std::vector<std::string> result2;
			boost::split(result,p,boost::is_any_of("&"));
			for(std::size_t i=0;i<result.size();++i)
			{
				p=result[i].c_str();
				result2.clear();
				boost::split(result2,p,boost::is_any_of("="));
				if (result2.size()>0)
				{
					if(result2.size()>=2)
						new_url.query_map_[ result2[0] ]=result2[1];
					else
						new_url.query_map_[ result2[0] ]="";
				}
			}
		}

		// Fragment.
		if (*s == '#')
			new_url.fragment_.assign(++s);

		ec = boost::system::error_code();
		return new_url;
	}

	uri uri::from_string(const char* s)
	{
		boost::system::error_code ec;
		uri new_url(from_string(s, ec));
		if (ec)
		{
			boost::system::system_error ex(ec);
			boost::throw_exception(ex);
		}
		return new_url;
	}

	uri uri::from_string(const std::string& s, boost::system::error_code& ec)
	{
		return from_string(s.c_str(), ec);
	}

	uri uri::from_string(const std::string& s)
	{
		return from_string(s.c_str());
	}

	bool uri::unescape_path(const std::string& in, std::string& out)
	{
		out.clear();
		out.reserve(in.size());
		for (std::size_t i = 0; i < in.size(); ++i)
		{
			switch (in[i])
			{
			case '%':
				if (i + 3 <= in.size())
				{
					unsigned int value = 0;
					for (std::size_t j = i + 1; j < i + 3; ++j)
					{
						switch (in[j])
						{
						case '0': case '1': case '2': case '3': case '4':
						case '5': case '6': case '7': case '8': case '9':
							value += in[j] - '0';
							break;
						case 'a': case 'b': case 'c': case 'd': case 'e': case 'f':
							value += in[j] - 'a' + 10;
							break;
						case 'A': case 'B': case 'C': case 'D': case 'E': case 'F':
							value += in[j] - 'A' + 10;
							break;
						default:
							return false;
						}
						if (j == i + 1)
							value <<= 4;
					}
					out += static_cast<char>(value);
					i += 2;
				}
				else
					return false;
				break;
			case '-': case '_': case '.': case '!': case '~': case '*':
			case '\'': case '(': case ')': case ':': case '@': case '&':
			case '=': case '+': case '$': case ',': case '/': case ';':
				out += in[i];
				break;
			default:
				if (!std::isalnum(in[i]))
					return false;
				out += in[i];
				break;
			}
		}
		return true;
	}

	bool operator==(const uri& a, const uri& b)
	{
		return a.protocol_ == b.protocol_
			&& a.user_info_ == b.user_info_
			&& a.host_ == b.host_
			&& a.port_ == b.port_
			&& a.path_ == b.path_
			&& a.query_ == b.query_
			&& a.fragment_ == b.fragment_;
	}

	bool operator!=(const uri& a, const uri& b)
	{
		return !(a == b);
	}

	bool operator<(const uri& a, const uri& b)
	{
		if (a.protocol_ < b.protocol_)
			return true;
		if (b.protocol_ < a.protocol_)
			return false;

		if (a.user_info_ < b.user_info_)
			return true;
		if (b.user_info_ < a.user_info_)
			return false;

		if (a.host_ < b.host_)
			return true;
		if (b.host_ < a.host_)
			return false;

		if (a.port_ < b.port_)
			return true;
		if (b.port_ < a.port_)
			return false;

		if (a.path_ < b.path_)
			return true;
		if (b.path_ < a.path_)
			return false;

		if (a.query_ < b.query_)
			return true;
		if (b.query_ < a.query_)
			return false;

		return a.fragment_ < b.fragment_;
	}

	std::string uri::normalize (std::string const& in)
	{
		return normalize(in.c_str());
	}

	std::string uri::normalize (const char* in)
	{
		//清除两端空白
		std::string inpath(in);
		boost::trim(inpath);

		// #if BOOST_VERSION >= 103400
		boost::filesystem::path p (inpath);
		// #elses
		//       boost::filesystem::path p (remove_double_slash(inpath), boost::filesystem::no_check);
		// #endif

		// if path ends in ".." we must append a '/'
		if (inpath.size() > 1 && 
			inpath[inpath.size()-1] == '.' && 
			inpath[inpath.size()-2] == '.')
		{
			p /= ".";
		}

		// canonize and normalize to get rid of duplicate '/'
		// #if BOOST_VERSION >= 103400
		p.canonize();
		// #else
		//       canonize(p);
		// #endif
		p.normalize();

		boost::filesystem::path pp = p.root_path();   // includes drive on windows

		boost::filesystem::path::iterator end   = p.end   ();
		boost::filesystem::path::iterator iter  = p.begin ();

		bool absolute = !pp.empty();
		bool first    = true;

		if ( absolute )
		{
			++iter; // skip root entry, we got that above...
		}

		boost::filesystem::path remainder;
		int append_slash = (inpath.size() > 1 && inpath[inpath.size()-1] == '/') ? 1 : 0;

		// this loop removes leading '/..' and trailing '/.' elements.
		for ( ; iter != end; ++iter )
		{
			if ( first    &&
				absolute &&
				".."     == (*iter) )
			{
				// '/..' - we are skipping this one
			}
			else if ( "." == (*iter) )
			{
				remainder /= "."; // keep '/.' in case they are not trailing
				++append_slash;
			}
			else
			{
				// found something useful...
				if (!remainder.empty())
					pp /= remainder;
				pp /= *iter;

				first    = false;
				if (--append_slash < 0)
					append_slash = 0;
				remainder = "";
			}
		}

		// handle single "."
		if (pp.string().empty())
			return remainder.string();

		// #if BOOST_VERSION >= 103400
		pp.canonize  ();
		// #else
		//       canonize(pp);
		// #endif
		pp.normalize ();

		std::string rst((append_slash > 0) ? pp.string() + "/" : pp.string());
		std::string::size_type pos=rst.find(":");
		if (pos!=std::string::npos
			&&pos>=2&&rst.length()>pos+1//网络协议(如ftp:)，而不是磁盘符号(如 C:)，则在":"后加入一个/
			&&rst[pos+1]=='/'
			)
		{
			rst.insert(pos+1,1,'/');
		}
		return rst;
	}

} // namespace url

