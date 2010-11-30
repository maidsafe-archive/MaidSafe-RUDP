//
// logging.inl
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

#include "p2engine/logging.hpp"

#include "p2engine/push_warning_option.hpp"
#include <ctime>
#include <iostream>
#include <sstream>
#include <fstream>
#include <cstdarg>
#include "p2engine/pop_warning_option.hpp"

P2ENGINE_NAMESPACE_BEGIN

//P2ENGINE_INL
/*

const char** logging::s_loghead()
{
	static const char* s_loghead_[]=
	{
		"",
		"[致命错误]",
		"[严重错误]",
		"[一般错误]",

		"[警    告]",
		"[注    意]",
		"[消    息]",

		"[调试信息]",
		"[调试跟踪]"
	};
	return s_loghead_;
};
*/
const char** logging::s_loghead()
{
static const char* s_loghead_[]=
{
"",
"[FALTAL]     ",
"[CRITICAL]   ",
"[ERROR]      ",

"[WARRING]    ",
"[NOTICE]     ",
"[INFORMATION]",

"[DEBUG]      ",
"[TRACK]      "
};
return s_loghead_;
};

//P2ENGINE_INL
logging::logging()
:fp_(NULL)
,level_(LOG_TRACE)
,loged_size_(0)
{
	boost::mutex::scoped_lock lk(file_mutex_);
	if (!logging_thread_)
		logging_thread_.reset(new boost::thread(boost::bind(&logging::run,this)));
}

//P2ENGINE_INL
logging::~logging()
{
	if (fp_)
	{
		fclose(fp_);
		fp_=NULL;
	}
}

void logging::open_file()
{
	if (fp_)
	{
		fclose(fp_);
		fp_=NULL;
	}
	time_t t = time(NULL);
	struct tm *tp = localtime(&t);
	char buf[128];
	sprintf(buf,"[%d_%02d_%02d-%02d_%02d_%02d].log",
		tp -> tm_year + 1900,
		tp -> tm_mon + 1,
		tp -> tm_mday,
		tp -> tm_hour,tp -> tm_min,tp -> tm_sec
		);
	fp_=fopen(buf, "w");
}


//P2ENGINE_INL
void logging::run()
{
	while(1)
	{
		boost::this_thread::sleep(boost::posix_time::millisec(50));
		do_log();
	}
}

//P2ENGINE_INL
void logging::que_log(const char* msg)
{
	std::size_t len=strlen(msg);

	boost::mutex::scoped_lock lk(buf_mutex_);

	bufer_.push(std::string());
	std::string& s=bufer_.back();
	s.reserve(len+2);
	s.assign(msg,msg+len);
	s.append(1,'\n');
}

//P2ENGINE_INL
void logging::do_log() 
{
	std::string s;

	for(;;)
	{
		boost::mutex::scoped_lock lk(buf_mutex_);
		if (!bufer_.empty())
		{
			s+=bufer_.front();
			bufer_.pop();
		}
		else
		{
			break;
		}
	}

	if (!s.empty())
	{
		boost::mutex::scoped_lock lk(file_mutex_);
		if (!fp_||loged_size_>10*1024*1024)
		{
			open_file();
			loged_size_=0;
		}
		fwrite(s.c_str(),s.length(),1,fp_);
		fflush(fp_);
		loged_size_+=s.length();
	}

}

//P2ENGINE_INL
void logging::log(logging_level level,const char* fpath,long line,const char* format, ...)
{
	va_list args;

	time_t t = time(NULL);
	struct tm *tp = localtime(&t);
	char fname[256];
	path_to_name(fpath,fname);

	std::stringstream thr_id;
	thr_id<<boost::this_thread::get_id();
	char buf[2048];
	sprintf(buf,"%s [%d-%02d-%02d %02d:%02d:%02d] [%s:%d] [thread:%s]:\n  ",
		s_loghead()[level],
		tp -> tm_year + 1900,
		tp -> tm_mon + 1,
		tp -> tm_mday,
		tp -> tm_hour,tp -> tm_min,tp -> tm_sec,
		fname,line,
		thr_id.str().c_str()
		);

	va_start(args, format);
	vsprintf(buf+strlen(buf), format, args);
	va_end(args);
	que_log(buf);
}
//P2ENGINE_INL
void logging::path_to_name(const char* path,char* name)
{
	const char* start=path;
	const char* end=path;
	for (;;)
	{
		if (*end=='\\'||*end=='/')
			start=end;		
		else if(*end==0)
			break;
		++end;
	}
	if (*start=='/'||*start=='\\')
		++start;
	strcpy(name,start);
}
 

P2ENGINE_NAMESPACE_END

