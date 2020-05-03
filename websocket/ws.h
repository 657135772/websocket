#ifndef WS_H_
#define WS_H_

#include <iostream>
#include <thread>

#include <websocketpp/config/asio_no_tls.hpp>
#include <websocketpp/server.hpp>
#include <boost/locale/encoding.hpp>

#include <boost/asio.hpp>

#include <boost/shared_ptr.hpp>
#include <boost/asio/placeholders.hpp>
#include <boost/system/error_code.hpp>
#include <boost/bind/bind.hpp>

#include <boost/algorithm/string/trim.hpp>
#include <boost/algorithm/string/trim_all.hpp>

#include <boost/log/core.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/expressions.hpp>
#include <boost/log/sinks/text_file_backend.hpp>
#include <boost/log/utility/setup/file.hpp>
#include <boost/log/utility/setup/common_attributes.hpp>
#include <boost/log/sources/severity_logger.hpp>
#include <boost/log/sources/record_ostream.hpp>

namespace logging = boost::log;
namespace src = boost::log::sources;
namespace sinks = boost::log::sinks;
namespace keywords = boost::log::keywords;

#include <chrono>
#include <string>
#include <memory>
#include <ctime>
#include <iomanip>
#include <sstream>

#include<stdio.h>
#include "json/CJsonObject.hpp"

using namespace boost::asio;

using namespace std;

using std::chrono::system_clock;

using namespace logging::trivial;

typedef websocketpp::server<websocketpp::config::asio> server;

// 通讯包头
typedef struct {
	unsigned char sLength[2];	// 数据长度
	unsigned char cMainType;
	unsigned char cSubType;
	unsigned char cState[5];
	unsigned char cNext;
	unsigned char cSignState;
	unsigned char cCompress;
	unsigned char cKeep[4];
	unsigned char sTraderNo[16];
} MTICommHead;

int GetheadBankLen(MTICommHead *head);
int SetheadBankLen(MTICommHead *head, int len);
int package_is_valid(char *msg, int mlen);

// H5字符包头
typedef struct {
	char	start;				// 开始标志 [
	char	APIType[4];			// 协议类型 如:F408
	char	length[4];			// 包体长度 0-9999
	char	next;				// 下一包标识 1-有下一包  0-无下一包
	char	compress;			// 压缩标识 1-压缩  0-不压缩
	char	terminal;			// 终端类型标识，固定W或T，W-移动websocket接口 T-平板TCP接口
	char	time[14];			// 当前时间 yyyyMMddhhmmss
	char	requestid[32];		// 请求标识 UUID
	char	reserve[22];		// 预留
	char	end;				// 结束标识 ]
}H5Head;

int GetH5headLen(H5Head *head);
int h5pkg_is_valid(char *msg, int mlen);

unsigned char GetHexType(char *hex2);
char *h5_time_trans_mti(char *h5time, char *mtime);
char *mti_time_trans_h5(char *mtime, char *h5time);
int H5_trans_mti(char *h5msg, char *mtimsg);
int mti_trans_h5(char *mtimsg, char *h5msg);

// socket客户端
#include <boost/asio.hpp>
#include <boost/bind.hpp>
#include <boost/shared_ptr.hpp>
#include <boost/date_time/posix_time/posix_time_types.hpp> 
using boost::asio::ip::tcp;

class wsserver;

class CAsioClient
{
public:
	CAsioClient(boost::asio::io_service& io_service, tcp::endpoint& endpoint, wsserver *_w, src::severity_logger<severity_level> *_lg, std::mutex *mtx);
	virtual ~CAsioClient(void);

	// 同步发送
	int msgsend(char *buff, int mlen);
	// 关闭连接
	int socketclose();

private:
	void handle_connect(const boost::system::error_code& error);
	
	void handle_read(const boost::system::error_code& error, std::size_t bytes_transferred);
	

	void handle_write(const boost::system::error_code& error, std::size_t bytes_transferred);

	void Timeout(boost::asio::deadline_timer *pt, const boost::system::error_code &ec);

private:
	tcp::socket socket;
	char sendBuffer[4096];
	char getBuffer[4096];

	std::string  readstream;

	boost::asio::deadline_timer *t;
	std::mutex *mt;

	wsserver *ws;

	src::severity_logger<severity_level>  *lg;
};

// ws服务
class wsserver {
public:
	wsserver(string chqip, int chqport, src::severity_logger<severity_level> &_lg);

	// 连接到来
	void on_open(websocketpp::connection_hdl hdl);

	// 连接关闭
	void on_close(websocketpp::connection_hdl hdl);

	// 消息接收
	void echo_handler(websocketpp::connection_hdl hdl, server::message_ptr msg);

	// 消息推送 测试
	void msg_push_handler(string chqip, int chqport);

	// ws消息反馈
	void msg_push_ws(char *msgbuf, int mlen, long sessionid);

	// 消息推送 测试
	void cllientrun();

	long get_sessionid();

	void run(uint16_t port);
private:
	server m_server;

	long	sessionid;	// 不能为0
	std::map<int, long> map_session;	// 会话map
	std::map<long, websocketpp::connection_hdl> map_hdl;	// 句柄map
	std::thread t;
	std::thread t1;

	// socket服务
	io_service *service;
	ip::tcp::endpoint *m_ep;
	CAsioClient *s;

	std::mutex mt;
	std::mutex mtx;

	src::severity_logger<severity_level>  *lg;
};

#endif

