//
// atom.hpp
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

#undef  HTTP_ATOM

#if defined(HTTP_ATOM_DEFINE)&&defined(HTTP_ATOM_DECLARE)
#   error("HTTP_ATOM_DEFINE or HTTP_ATOM_DECLARE can only be defined one!")
#endif

#ifdef  HTTP_ATOM_DECLARE
#	define HTTP_ATOM(name,s)  extern const std::string name;
#elif defined(HTTP_ATOM_DEFINE)
#	define HTTP_ATOM(name,s)  const std::string name=s; 
#else
#   error("HTTP_ATOM_DEFINE or HTTP_ATOM_DECLARE must be defined one!")
#endif

//方法
HTTP_ATOM(HTTP_METHORD_CONNECT,      "CONNECT")
	HTTP_ATOM(HTTP_METHORD_COPY,     "COPY")
	HTTP_ATOM(HTTP_METHORD_DELETE,   "DELETE")
	HTTP_ATOM(HTTP_METHORD_GET,      "GET")
	HTTP_ATOM(HTTP_METHORD_HEAD,     "HEAD")
	HTTP_ATOM(HTTP_METHORD_INDEX,    "INDEX")
	HTTP_ATOM(HTTP_METHORD_LOCK,     "LOCK")
	HTTP_ATOM(HTTP_METHORD_M_POST,   "M-POST")
	HTTP_ATOM(HTTP_METHORD_MKCOL,    "MKCOL")
	HTTP_ATOM(HTTP_METHORD_MOVE,     "MOVE")
	HTTP_ATOM(HTTP_METHORD_OPTIONS,  "OPTIONS")
	HTTP_ATOM(HTTP_METHORD_POST,     "POST")
	HTTP_ATOM(HTTP_METHORD_PROPFIND, "PROPFIND")
	HTTP_ATOM(HTTP_METHORD_PROPPATCH,"PROPPATCH")
	HTTP_ATOM(HTTP_METHORD_PUT,      "PUT")
	HTTP_ATOM(HTTP_METHORD_TRACE,    "TRACE")
	HTTP_ATOM(HTTP_METHORD_UNLOCK,   "UNLOCK")

	//atom
	HTTP_ATOM(HTTP_ATOM_Accept,                    "HTTP_ATOM_Accept")
	HTTP_ATOM(HTTP_ATOM_Accept_Charset,            "HTTP_ATOM_Accept-Charset")
	HTTP_ATOM(HTTP_ATOM_Accept_Encoding,           "HTTP_ATOM_Accept-Encoding")
	HTTP_ATOM(HTTP_ATOM_Accept_Language,           "HTTP_ATOM_Accept-Language")
	HTTP_ATOM(HTTP_ATOM_Accept_Ranges,             "HTTP_ATOM_Accept-Ranges")
	HTTP_ATOM(HTTP_ATOM_Age,                       "Age")
	HTTP_ATOM(HTTP_ATOM_Allow,                     "Allow")
	HTTP_ATOM(HTTP_ATOM_Authentication,            "Authentication")
	HTTP_ATOM(HTTP_ATOM_Authorization,             "Authorization")
	HTTP_ATOM(HTTP_ATOM_Cache_Control,             "Cache-Control")
	HTTP_ATOM(HTTP_ATOM_Connection,                "Connection")
	HTTP_ATOM(HTTP_ATOM_Content_Base,              "Content-Base")
	HTTP_ATOM(HTTP_ATOM_Content_Encoding,          "Content-Encoding")
	HTTP_ATOM(HTTP_ATOM_Content_Language,          "Content-Language")
	HTTP_ATOM(HTTP_ATOM_Content_Length,            "Content-Length")
	HTTP_ATOM(HTTP_ATOM_Content_Location,          "Content-Location")
	HTTP_ATOM(HTTP_ATOM_Content_MD5,               "Content-MD5")
	HTTP_ATOM(HTTP_ATOM_Content_Range,             "Content-Range")
	HTTP_ATOM(HTTP_ATOM_Content_Transfer_Encoding, "Content-Transfer-Encoding")
	HTTP_ATOM(HTTP_ATOM_Content_Type,              "Content-Type")
	HTTP_ATOM(HTTP_ATOM_Cookie,                    "Cookie")
	HTTP_ATOM(HTTP_ATOM_Date,                      "Date")
	HTTP_ATOM(HTTP_ATOM_DAV,                       "DAV")
	HTTP_ATOM(HTTP_ATOM_Depth,                     "Depth")
	HTTP_ATOM(HTTP_ATOM_Derived_From,              "Derived-From")
	HTTP_ATOM(HTTP_ATOM_Destination,               "Destination")
	HTTP_ATOM(HTTP_ATOM_ETag,                      "Etag")
	HTTP_ATOM(HTTP_ATOM_Expect,                    "Expect")
	HTTP_ATOM(HTTP_ATOM_Expires,                   "Expires")
	HTTP_ATOM(HTTP_ATOM_Forwarded,                 "Forwarded")
	HTTP_ATOM(HTTP_ATOM_From,                      "From")
	HTTP_ATOM(HTTP_ATOM_Host,                      "Host")
	HTTP_ATOM(HTTP_ATOM_If,                        "If")
	HTTP_ATOM(HTTP_ATOM_If_Match,                  "If-Match")
	HTTP_ATOM(HTTP_ATOM_If_Match_Any,              "If-Match-Any")
	HTTP_ATOM(HTTP_ATOM_If_Modified_Since,         "If-Modified-Since")
	HTTP_ATOM(HTTP_ATOM_If_None_Match,             "If-None-Match")
	HTTP_ATOM(HTTP_ATOM_If_None_Match_Any,         "If-None-Match-Any")
	HTTP_ATOM(HTTP_ATOM_If_Range,                  "If-Range")
	HTTP_ATOM(HTTP_ATOM_If_Unmodified_Since,       "If-Unmodified-Since")
	HTTP_ATOM(HTTP_ATOM_Keep_Alive,                "Keep-Alive")
	HTTP_ATOM(HTTP_ATOM_Last_Modified,             "Last-Modified")
	HTTP_ATOM(HTTP_ATOM_Lock_Token,                "Lock-Token")
	HTTP_ATOM(HTTP_ATOM_Link,                      "Link")
	HTTP_ATOM(HTTP_ATOM_Location,                  "Location")
	HTTP_ATOM(HTTP_ATOM_Max_Forwards,              "Max-Forwards")
	HTTP_ATOM(HTTP_ATOM_Message_Id,                "Message-Id")
	HTTP_ATOM(HTTP_ATOM_Mime,                      "Mime")
	HTTP_ATOM(HTTP_ATOM_Overwrite,                 "Overwrite")
	HTTP_ATOM(HTTP_ATOM_Pragma,                    "Pragma")
	HTTP_ATOM(HTTP_ATOM_Proxy_Authenticate,        "Proxy-Authenticate")
	HTTP_ATOM(HTTP_ATOM_Proxy_Authorization,       "Proxy-Authorization")
	HTTP_ATOM(HTTP_ATOM_Proxy_Connection,          "Proxy-Connection")
	HTTP_ATOM(HTTP_ATOM_Range,                     "Range")
	HTTP_ATOM(HTTP_ATOM_Referer,                   "Referer")
	HTTP_ATOM(HTTP_ATOM_Retry_After,               "Retry-After")
	HTTP_ATOM(HTTP_ATOM_Server,                    "Server")
	HTTP_ATOM(HTTP_ATOM_Set_Cookie,                "Set-Cookie")
	HTTP_ATOM(HTTP_ATOM_Set_Cookie2,               "Set-Cookie2")
	HTTP_ATOM(HTTP_ATOM_Status_URI,                "Status-URI")
	HTTP_ATOM(HTTP_ATOM_TE,                        "TE")
	HTTP_ATOM(HTTP_ATOM_Title,                     "Title")
	HTTP_ATOM(HTTP_ATOM_Timeout,                   "Timeout")
	HTTP_ATOM(HTTP_ATOM_Trailer,                   "Trailer")
	HTTP_ATOM(HTTP_ATOM_Transfer_Encoding,         "Transfer-Encoding")
	HTTP_ATOM(HTTP_ATOM_URI,                       "URI")
	HTTP_ATOM(HTTP_ATOM_Upgrade,                   "Upgrade")
	HTTP_ATOM(HTTP_ATOM_User_Agent,                "User-Agent")
	HTTP_ATOM(HTTP_ATOM_Vary,                      "Vary")
	HTTP_ATOM(HTTP_ATOM_Version,                   "Version")
	HTTP_ATOM(HTTP_ATOM_WWW_Authenticate,          "WWW-Authenticate")
	HTTP_ATOM(HTTP_ATOM_Warning,                   "Warning")

	HTTP_ATOM(HTTP_REASON_CONTINUE              ,"Continue")
	HTTP_ATOM(HTTP_REASON_SWITCHING_PROTOCOLS   ,"Switching Protocols")
	HTTP_ATOM(HTTP_REASON_OK                    ,"OK")
	HTTP_ATOM(HTTP_REASON_CREATED               ,"Created")
	HTTP_ATOM(HTTP_REASON_ACCEPTED              ,"Accepted")
	HTTP_ATOM(HTTP_REASON_NONAUTHORITATIVE      ,"Non-Authoritative Information")
	HTTP_ATOM(HTTP_REASON_NO_CONTENT             ,"No Content")
	HTTP_ATOM(HTTP_REASON_RESET_CONTENT          ,"Reset Content")
	HTTP_ATOM(HTTP_REASON_PARTIAL_CONTENT        ,"Partial Content")
	HTTP_ATOM(HTTP_REASON_MULTIPLE_CHOICES       ,"Multiple Choices")
	HTTP_ATOM(HTTP_REASON_MOVED_PERMANENTLY      ,"Moved Permanently")
	HTTP_ATOM(HTTP_REASON_FOUND                  ,"Found")
	HTTP_ATOM(HTTP_REASON_SEE_OTHER              ,"See Other")
	HTTP_ATOM(HTTP_REASON_NOT_MODIFIED           ,"Not Modified")
	HTTP_ATOM(HTTP_REASON_USEPROXY               ,"Use Proxy")
	HTTP_ATOM(HTTP_REASON_TEMPORARY_REDIRECT     ,"Temporary Redirect")
	HTTP_ATOM(HTTP_REASON_BAD_REQUEST            ,"Bad Request")
	HTTP_ATOM(HTTP_REASON_UNAUTHORIZED           ,"Unauthorized")
	HTTP_ATOM(HTTP_REASON_PAYMENT_REQUIRED       ,"Payment Required")
	HTTP_ATOM(HTTP_REASON_FORBIDDEN              ,"Forbidden")
	HTTP_ATOM(HTTP_REASON_NOT_FOUND              ,"Not Found")
	HTTP_ATOM(HTTP_REASON_METHOD_NOT_ALLOWED     ,"Method Not Allowed")
	HTTP_ATOM(HTTP_REASON_NOT_ACCEPTABLE         ,"Not Acceptable")
	HTTP_ATOM(HTTP_REASON_PROXY_AUTHENTICATION_REQUIRED,"Proxy Authentication Required")
	HTTP_ATOM(HTTP_REASON_REQUEST_TIMEOUT        ,"Request Time-out")
	HTTP_ATOM(HTTP_REASON_CONFLICT               ,"Conflict")
	HTTP_ATOM(HTTP_REASON_GONE                   ,"Gone")
	HTTP_ATOM(HTTP_REASON_LENGTH_REQUIRED        ,"Length Required")
	HTTP_ATOM(HTTP_REASON_PRECONDITION_FAILED    ,"Precondition Failed")
	HTTP_ATOM(HTTP_REASON_REQUESTENTITYTOOLARGE  ,"Request Entity Too Large")
	HTTP_ATOM(HTTP_REASON_REQUESTURITOOLONG      ,"Request-URI Too Large")
	HTTP_ATOM(HTTP_REASON_UNSUPPORTEDMEDIATYPE   ,"Unsupported Media Type")
	HTTP_ATOM(HTTP_REASON_REQUESTED_RANGE_NOT_SATISFIABLE, "Requested Range Not Satisfiable")
	HTTP_ATOM(HTTP_REASON_EXPECTATION_FAILED     ,"Expectation Failed")
	HTTP_ATOM(HTTP_REASON_INTERNAL_SERVER_ERROR  ,"Internal Server Error")
	HTTP_ATOM(HTTP_REASON_NOT_IMPLEMENTED        ,"Not Implemented")
	HTTP_ATOM(HTTP_REASON_BAD_GATEWAY            ,"Bad Gateway")
	HTTP_ATOM(HTTP_REASON_SERVICE_UNAVAILABLE    ,"Service Unavailable")
	HTTP_ATOM(HTTP_REASON_GATEWAY_TIMEOUT        ,"Gateway Time-out")
	HTTP_ATOM(HTTP_REASON_VERSION_NOT_SUPPORTED  ,"HTTP Version not supported")
	HTTP_ATOM(HTTP_REASON_UNKNOWN                ,"???")


	//一些值
	HTTP_ATOM(HTTP_VERSION_1_0,                  "HTTP/1.0")
	HTTP_ATOM(HTTP_VERSION_1_1,                  "HTTP/1.1")
	HTTP_ATOM(IDENTITY_TRANSFER_ENCODING,        "identity")
	HTTP_ATOM(CHUNKED_TRANSFER_ENCODING,         "chunked")
	HTTP_ATOM(CONNECTION_KEEP_ALIVE,             "")
	HTTP_ATOM(CONNECTION_CLOSE,                  "Close")