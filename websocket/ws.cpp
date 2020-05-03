#include "ws.h"

#define NET_PWD "87654321"

// 取包头报文长度
int GetheadBankLen(MTICommHead *head)
{
	int len = ((unsigned char)(head->sLength[0])) * 256 + (unsigned char)(head->sLength[1]);
	return len;
}

// 设置包头报文长度
int SetheadBankLen(MTICommHead *head, int len)
{
	if (len < 0)
		len = 0;

	head->sLength[0] = (unsigned char)(len / 256);
	head->sLength[1] = (unsigned char)(len % 256);

	return 0;
}

// 判断报文是否完整 -1不完整 >0完整命令长度
int package_is_valid(char *msg, int mlen)
{
	if (mlen >= (int)sizeof(MTICommHead))
	{
		MTICommHead *head = (MTICommHead *)msg;
		int msglen = 0;

		msglen = GetheadBankLen(head);
		if (msglen > 4000)
		{
			return -2;
		}

		if (msglen > (mlen - (int)sizeof(MTICommHead)))
		{
			return -1;
		}
		else
		{
			return (msglen + (int)sizeof(MTICommHead));
		}
	}
	else
	{
		return -1;
	}
}

// 获取H5报文长度
int GetH5headLen(H5Head *head)
{
	int		len = 0;

	string str(head->length, sizeof(head->length));

	boost::trim(str);
	len = std::stoi(str);

	return len;
}

// 判断H5报文是否完整 -1不完整 >0完整命令长度
int h5pkg_is_valid(char *msg, int mlen)
{
	if (mlen >= (int)sizeof(H5Head))
	{
		H5Head *head = (H5Head *)msg;
		int msglen = 0;

		msglen = GetH5headLen(head);
		if (msglen > 4000)
		{
			return -2;
		}

		if (msglen > (mlen - (int)sizeof(H5Head)))
		{
			return -1;
		}
		else
		{
			return (msglen + (int)sizeof(H5Head));
		}
	}
	else
	{
		return -1;
	}
}

unsigned char GetHexType(char *hex2)
{
	char	buff[5] = { 0 };
	memcpy(buff, hex2, 2);

	unsigned char c;
	unsigned int x;
	sscanf(buff, "%02X", &x);
	c = x;
	
	return c;
}

char *h5_time_trans_mti(char *h5time, char *mtime)
{
	memcpy(mtime + 0, h5time + 0, 4);		// yyyy
	mtime[4] = '-';
	memcpy(mtime + 5, h5time + 4, 2);		// MM
	mtime[7] = '-';
	memcpy(mtime + 8, h5time + 6, 2);		// DD
	mtime[10] = ' ';
	memcpy(mtime + 11, h5time + 8, 2);		// HH
	mtime[13] = ':';
	memcpy(mtime + 14, h5time + 10, 2);		// MM
	mtime[16] = ':';
	memcpy(mtime + 17, h5time + 12, 2);		// MM

	return mtime;
}

char *mti_time_trans_h5(char *mtime, char *h5time)
{
	memcpy(h5time + 0, mtime + 0, 4);
	memcpy(h5time + 4, mtime + 5, 2);
	memcpy(h5time + 6, mtime + 8, 2);
	memcpy(h5time + 8, mtime + 11, 2);
	memcpy(h5time + 10, mtime + 14, 2);
	memcpy(h5time + 12, mtime + 17, 2);

	return h5time;
}

// H5报文转换为MTI报文
int H5_trans_mti(char *h5msg, char *mtimsg)
{
	H5Head *h5head = (H5Head *)h5msg;
	char *h5json = (char *)(h5head + 1);
	string gbkmsg;

	MTICommHead	*mtihead = (MTICommHead *)mtimsg;
	char *mtijson = (char *)(mtihead + 1);

	int mtilength = 0;
	char timebuf[32] = { 0 };

	//FILE *fp = fopen("aaa.txt", "a+");
	//fprintf(fp, "%s", h5msg);
	//fclose(fp);

	// 探测反馈0
	if (memcmp(h5head->APIType, "0000", 4) == 0)
		return 0;

	// 包体转换
	gbkmsg = boost::locale::conv::between(h5json, "GBK", "UTF-8");
	neb::CJsonObject oJson(gbkmsg);
	if (oJson["DATA"].GetArraySize() != 1)
	{
		cout << "H5ERR:" << h5msg << endl;
		cout << "报文格式错误_arraysize:" << oJson["DATA"].GetArraySize() << endl;
		return -1;
	}

	neb::CJsonObject j1 = oJson["DATA"][0];
	j1.Add("REQUESTID", string(h5head->requestid, sizeof(h5head->requestid)));
	j1.Add("TIME", h5_time_trans_mti(h5head->time, timebuf));
	//j1.Add("TERMINAL", h5head->terminal);
	j1.Add("TERMINAL", "W");
	mtilength = j1.ToString().length();
	memcpy(mtijson, j1.ToString().c_str(), mtilength);

	cout << "H5_MTI_A:" << h5msg << endl;
	cout << "H5_MTI_B:" << mtijson << endl;

	// 包头转换  
	memset(mtihead, 0, sizeof(MTICommHead));
	SetheadBankLen(mtihead, mtilength);
	mtihead->cMainType = GetHexType(h5head->APIType + 0);
	mtihead->cSubType = GetHexType(h5head->APIType + 2);
	memset(mtihead->cState, '0', sizeof(mtihead->cState));
	if (h5head->next == '1')
		mtihead->cNext = 'Y';
	else
		mtihead->cNext = 'N';

	mtihead->cSignState = ' ';

	if (h5head->compress == '1')
		mtihead->cCompress = 'Y';
	else
		mtihead->cCompress = 'N';

	return sizeof(MTICommHead) + mtilength;
}

// mti转换为h5
int mti_trans_h5(char *mtimsg, char *h5msg)
{
	MTICommHead	*mtihead = (MTICommHead *)mtimsg;
	char *mtijson = (char *)(mtihead + 1);

	H5Head *h5head = (H5Head *)h5msg;
	char *h5json = (char *)(h5head + 1);

	string timebuf;
	string reqid;
	string info;
	string utf8str;
	char tbf[32] = { 0 };
	char tb2[32] = { 0 };
	int h5len = 0;

	// 包体转换
	neb::CJsonObject oJson;
	oJson.Add("CODE", string((char *)(mtihead->cState), sizeof(mtihead->cState)));
	//if (memcmp(mtihead->cState, "00000", 5) != 0)
	//{
	//	oJson.Add("INFO", mtijson);
	//}
	//else
	//{
	//	if (GetheadBankLen(mtihead) < 1)
	//	{
	//		oJson.Add("INFO", "");
	//	}
	//	else
	//	{
	//		neb::CJsonObject j1(mtijson);
	//		oJson.AddEmptySubArray("DATA");
	//		oJson["DATA"].Add(j1);

	//		// 解析time reqid
	//		j1.Get("REQUESTID", reqid);
	//		j1.Get("TIME", timebuf);
	//	}
	//}

	if (GetheadBankLen(mtihead) < 1)
	{
		oJson.Add("INFO", "");
	}
	else
	{
		neb::CJsonObject j1(mtijson);
		oJson.AddEmptySubArray("DATA");
		oJson["DATA"].Add(j1);

		j1.Get("INFO", info);
		oJson.Add("INFO", info);

		// 解析time reqid
		j1.Get("REQUESTID", reqid);
		j1.Get("TIME", timebuf);
	}

	if (timebuf.length() < 1)	// 时间为空 取当前时间
	{
		//system_clock::time_point tp = system_clock::now();
		//time_t raw_time = system_clock::to_time_t(tp);
		//struct tm  *timeinfo = std::localtime(&raw_time);
		//std::stringstream ss;

		//ss << std::put_time(timeinfo, "%Y-%m-%d %H:%M:%S");
		//timebuf = ss.str(); 

		auto tt = std::chrono::system_clock::to_time_t
		(std::chrono::system_clock::now());
		struct tm* ptm = localtime(&tt);
		char date[60] = { 0 };
		sprintf(date, "%d-%02d-%02d %02d:%02d:%02d",
			(int)ptm->tm_year + 1900, (int)ptm->tm_mon + 1, (int)ptm->tm_mday,
			(int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec);

		timebuf = string(date);
	}
	memcpy(tbf, timebuf.c_str(), timebuf.length());
	mti_time_trans_h5(tbf, tb2);

	utf8str = boost::locale::conv::between(oJson.ToString(), "UTF-8", "GBK");
	h5len = utf8str.length();
	memcpy(h5json, utf8str.c_str(), h5len);

	cout << "MTI_H5_A:" << mtijson << endl;
	
	// 包头转换 时间
	h5head->start = '[';
	sprintf(h5head->APIType, "%02X%02X", mtihead->cMainType, mtihead->cSubType);
	sprintf(h5head->length, "%04d", h5len);
	if (mtihead->cNext == 'Y')
		h5head->next = '1';
	else
		h5head->next = '0';

	if (mtihead->cCompress == 'Y')
		h5head->compress = '1';
	else
		h5head->compress = '0';

	h5head->terminal = 'W';
	sprintf(h5head->time, tb2);
	if (reqid.length() > 0)
	{
		sprintf(h5head->requestid, "%032s", reqid.c_str());
	}
	else
	{
		memset(h5head->requestid, '0', sizeof(h5head->requestid));
	}
	memset(h5head->reserve, '0', sizeof(h5head->reserve));
	h5head->end = ']';

	cout << "MTI_H5_B:" << h5msg << endl;

	//FILE *fp = fopen("aaa.txt", "a+");
	//fprintf(fp, "%s", h5msg);
	//fclose(fp);

	return h5len + sizeof(H5Head);
}

// Y9解密
int Y9DeCode(char *ds, int dslen, char *ins, int len)
{
	int i, pos;

	for (i = 0; i < len; i++)
	{
		pos = (i + 1) % dslen;
		ins[i] = ins[i] ^ (ds[pos] + i % 7);
	}

	return 1;
}

// Y9加密
int Y9EnCode(char *ds, int dslen, char *ins, int len)
{
	int i, pos;

	for (i = 0; i < len; i++)
	{
		pos = (i + 1) % dslen;
		ins[i] = ins[i] ^ (ds[pos] + i % 7);
	}

	return 1;
}

std::string getThreadIdOfString(const std::thread::id & id)
{
	std::stringstream sin;
	sin << id;
	return sin.str();
}

CAsioClient::CAsioClient(boost::asio::io_service& io_service, tcp::endpoint& endpoint, wsserver *_w, src::severity_logger<severity_level>  *_lg, std::mutex *mtx)
	: socket(io_service), ws(_w), lg(_lg), mt(mtx)
{
	t = new boost::asio::deadline_timer(io_service, boost::posix_time::seconds(10)); //设置一个10s超时的定时器
	t->async_wait(bind(std::mem_fn(&CAsioClient::Timeout), this, t, ::_1));

	socket.async_connect(
		endpoint,
		boost::bind(&CAsioClient::handle_connect, this, boost::asio::placeholders::error)
	);
	memset(getBuffer, 0, sizeof(getBuffer));

	readstream.clear();

	BOOST_LOG_SEV(*lg, info) << "CAsioClient create success:" << getThreadIdOfString(std::this_thread::get_id());
}

CAsioClient::~CAsioClient(void)
{
	BOOST_LOG_SEV(*lg, info) << "CAsioClient 析构";
	delete t;
}

// 同步发送
int CAsioClient::msgsend(char *buff, int mlen)
{
	if (mlen <= 0)
		return 0;

	BOOST_LOG_SEV(*lg, info) << "CHQ发送消息TID:" << getThreadIdOfString(std::this_thread::get_id());
	int	len = 0;
	mt->lock();
	len = socket.send(buffer(buff, mlen));
	mt->unlock();
	return len;
}

int CAsioClient::socketclose()
{
	BOOST_LOG_SEV(*lg, info) << "关闭CHQ socket连接:" << getThreadIdOfString(std::this_thread::get_id());
	try
	{
		mt->lock();
		socket.close();
		mt->unlock();
	}
	catch (const std::exception& e)
	{
		cout << "CHQ close error:" << e.what() << endl;
	}
	
	return 0;
}

void CAsioClient::handle_connect(const boost::system::error_code& error)
{
	if (!error)
	{
		std::cout << "连接成功，登陆F4-0D:" <<  getThreadIdOfString(std::this_thread::get_id()) << std::endl;

		MTICommHead	head;
		int	mlen;
		memset(&head, 0, sizeof(head));
		head.cMainType = 0xF4;
		head.cSubType = 0x0D;
		head.cNext = 'N';

		mlen = sizeof(head);
		memcpy(sendBuffer, &head, sizeof(head));

		//// 异步写
		//socket.async_write_some(
		//	boost::asio::buffer(sendBuffer, mlen), 
		//	boost::bind(&CAsioClient::handle_write, this, boost::asio::placeholders::error
		//		, boost::asio::placeholders::bytes_transferred)
		//	);

		msgsend(sendBuffer, mlen);

		// 异步读
		socket.async_read_some(
			boost::asio::buffer(getBuffer, sizeof(getBuffer)),
			boost::bind(&CAsioClient::handle_read, this, boost::asio::placeholders::error
				, boost::asio::placeholders::bytes_transferred)
		);

	}
	else
	{
		std::cout << "socket连接失败" << std::endl;
		//socket.close();
	}
}

void CAsioClient::handle_read(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	BOOST_LOG_SEV(*lg, info) << "接收到CHQ数据 长度:" << bytes_transferred << " TID:" << getThreadIdOfString(std::this_thread::get_id());

	if (!error)
	{
		int msglen;
		char readmsg[4096] = { 0 };

		readstream.append(getBuffer, bytes_transferred);

		while (1)
		{
			msglen = package_is_valid((char *)readstream.c_str(), readstream.length());
			cout << "CHQ_LEN:" << msglen << endl;
			if (msglen > 0)
			{
				memcpy(readmsg, readstream.c_str(), msglen);
				MTICommHead *head = (MTICommHead *)readmsg;
				char *jsonmsg = (char *)(head + 1);
				long sessionid;

				// 报文解密
				Y9DeCode((char *)NET_PWD, strlen(NET_PWD), jsonmsg, msglen - sizeof(MTICommHead));

				//fprintf(stdout, "接收到服务端协议:[%02X][%02X][%.*s]\n", head->cMainType, head->cSubType
				//	, msglen - sizeof(MTICommHead), jsonmsg);
				if ((head->cMainType == 0xF4) && (head->cSubType == 0x0D))	// 登陆反馈
				{
					if (memcmp(head->cState, "00000", 5) == 0)
					{
						std::cout << "登陆成功" << std::endl;
					}
					else
					{
						std::cout << "登陆失败" << std::endl;
					}
				}
				else		// 反馈web端
				{
					// 解析sessionid
					sessionid = atol((char *)(head->sTraderNo));
					ws->msg_push_ws(readmsg, msglen, sessionid);
				}

				// 清除已发送字符
				std::string::iterator it1 = readstream.begin();
				std::string::iterator it2 = it1 + msglen;
				readstream.erase(it1, it2);

				if (readstream.length() < 1)
					break;
			}
			else if (msglen == -2)	// 格式错误
			{
				readstream.clear();
				BOOST_LOG_SEV(*lg, info) << "接收到CHQ数据格式错误";

				break;
			}
			else		// 不完整
			{
				BOOST_LOG_SEV(*lg, info) << "接收到CHQ数据不完整";
				break;
			}
		}
		
		socket.async_read_some(
			boost::asio::buffer(getBuffer, sizeof(getBuffer)),
			boost::bind(&CAsioClient::handle_read, this, boost::asio::placeholders::error
				, boost::asio::placeholders::bytes_transferred)
		);
	}
	else
	{
		BOOST_LOG_SEV(*lg, info) << "读CHQ数据失败:" << error.message();
	}
}

void CAsioClient::handle_write(const boost::system::error_code& error, std::size_t bytes_transferred)
{
	if (!error)
	{
		BOOST_LOG_SEV(*lg, info) << "CHQ发送数据成功:" << bytes_transferred << " TID:" << getThreadIdOfString(std::this_thread::get_id());
	}
	else
	{
		BOOST_LOG_SEV(*lg, info) << "CHQ发送数据失败:" << error.message();
		//socket.close();
	}
}

void CAsioClient::Timeout(boost::asio::deadline_timer *pt, const boost::system::error_code &ec)
{
	if (ec)
	{
		std::cout << "timer is cancel " << std::endl;
		return;
	}

	MTICommHead	head;
	int	mlen;
	memset(&head, 0, sizeof(head));
	head.cMainType = 0x00;
	head.cSubType = 0x00;
	head.cNext = 'N';

	mlen = sizeof(head);
	msgsend((char *)(&head), mlen);

	pt->expires_at(pt->expires_at() + boost::posix_time::seconds(10));
	pt->async_wait(bind(std::mem_fn(&CAsioClient::Timeout), this, pt, ::_1));
}


wsserver::wsserver(string chqip, int chqport, src::severity_logger<severity_level> &_lg) {
	lg = &_lg;
	
	// 设置log
	m_server.set_error_channels(websocketpp::log::elevel::all);
	m_server.set_access_channels(websocketpp::log::alevel::all ^ websocketpp::log::alevel::frame_payload);

	// 初始化Asio
	m_server.init_asio();

	// 打开连接处理
	m_server.set_open_handler(std::bind(
		&wsserver::on_open, this,
		std::placeholders::_1
	));

	// 连接关闭处理
	m_server.set_close_handler(std::bind(
		&wsserver::on_close, this,
		std::placeholders::_1
	));

	// 设置消息回调为echo_handler
	m_server.set_message_handler(std::bind(
		&wsserver::echo_handler, this,
		std::placeholders::_1, std::placeholders::_2
	));

	//m_server.set_fail_handler();

	//m_server.set_interrupt_handler();

	// 会话id
	sessionid = 1;

	t = std::thread(&wsserver::msg_push_handler, this, chqip, chqport);
	t.detach();

	//t1 = std::thread(&wsserver::cllientrun, this);
	//t1.detach();

	BOOST_LOG_SEV(*lg, info) << "wsserver create success";
}

// 连接到来
void wsserver::on_open(websocketpp::connection_hdl hdl)
{
	server::connection_ptr con = m_server.get_con_from_hdl(hdl);

	// 获取连接文件描述符 con->get_socket().native_handle()
	long sessionid = get_sessionid();
	map_session.insert(pair<int, long>(con->get_socket().native_handle(), sessionid));

	map_hdl.insert(pair<int, websocketpp::connection_hdl>(sessionid, hdl));

	BOOST_LOG_SEV(*lg, info) << "ws连接到来 sockid=" << con->get_socket().native_handle() << " sessionid=" << sessionid;
}

// 连接关闭
void wsserver::on_close(websocketpp::connection_hdl hdl)
{
	mt.lock();

	server::connection_ptr con = m_server.get_con_from_hdl(hdl);

	long sessionid = 0;
	// 获取连接文件描述符 con->get_socket().native_handle()
	std::map<int, long>::iterator it = map_session.find(con->get_socket().native_handle());
	if (it == map_session.end())
	{
		BOOST_LOG_SEV(*lg, info) << "ws_连接关闭错误 找不到会话 sockid=" << con->get_socket().native_handle();
	}
	else
	{
		sessionid = it->second;
		map_session.erase(it);
	}

	if (sessionid != 0)
	{
		std::map<long, websocketpp::connection_hdl>::iterator ip = map_hdl.find(sessionid);
		if (ip == map_hdl.end())
		{
			BOOST_LOG_SEV(*lg, info) << "ws_连接关闭错误 找不到句柄 sessionid=" << sessionid;
		}
		else
		{
			map_hdl.erase(ip);
		}
	}

	// 通知连接断开
	if (sessionid != 0)
	{
		char	sendbuf[256] = { 0 };
		MTICommHead *head = (MTICommHead *)sendbuf;
		int		pkglen = sizeof(MTICommHead);

		head->cMainType = 0xFF;
		head->cSubType = 0x05;
		head->cNext = 'N';
		snprintf((char *)(head->sTraderNo), sizeof(head->sTraderNo), "%ld", sessionid);
		SetheadBankLen(head, 0);

		s->msgsend(sendbuf, pkglen);
	}

	mt.unlock();
	
	BOOST_LOG_SEV(*lg, info) << "ws关闭连接 sessionid=" << sessionid;
}

// 消息接收
void wsserver::echo_handler(websocketpp::connection_hdl hdl, server::message_ptr msg) {
	//// 发送消息
	//m_server.send(hdl, msg->get_payload(), msg->get_opcode());

	// 消息打印
	if (msg->get_opcode() == websocketpp::frame::opcode::text) {
		//std::cout << "recv:" << "opcode:" << msg->get_opcode() << ",payload:"
		//	<< msg->get_payload() << std::endl;

		//std::cout << "recv:" << "opcode:" << msg->get_opcode() << ",payload:"
		//	<< websocketpp::utility::to_hex(msg->get_payload()) << std::endl;
	}
	else {
		//std::cout << "recv:" << "opcode:" << msg->get_opcode() << ",payload:"
		//	<< websocketpp::utility::to_hex(msg->get_payload()) << std::endl;
	}

	server::connection_ptr con = m_server.get_con_from_hdl(hdl);

	BOOST_LOG_SEV(*lg, info) << "sockid=" << con->get_socket().native_handle() << " 接收到ws消息:" << msg->get_payload();

	// 判断消息是否合法
	int pkglen = h5pkg_is_valid((char *)(msg->get_payload().c_str()), msg->get_payload().length());

	if (pkglen > 0)
	{
		char	sendbuf[4096] = { 0 };
		memcpy(sendbuf, (char *)(msg->get_payload().c_str()), pkglen);
		H5Head *h5head = (H5Head *)sendbuf;
		char *jsonmsg = (char *)(h5head + 1);

		char	mtibuff[4096] = { 0 };
		MTICommHead	*mtihead = (MTICommHead *)mtibuff;
		char *mtimsg = (char *)(mtihead + 1);

		// 协议转换
		int  mtilen;
		mtilen = H5_trans_mti(sendbuf, mtibuff);

		if (mtilen > 0)
		{
			long sessionid = 0;
			std::map<int, long>::iterator it = map_session.find(con->get_socket().native_handle());
			if (it == map_session.end())
			{
				BOOST_LOG_SEV(*lg, info) << "错误 sockid=" << con->get_socket().native_handle() << " 消息找不到会话";
			}
			else
			{
				sessionid = it->second;

				snprintf((char *)(mtihead->sTraderNo), sizeof(mtihead->sTraderNo), "%ld", sessionid);

				// 报文加密
				Y9EnCode((char *)NET_PWD, strlen(NET_PWD), mtimsg, mtilen - sizeof(MTICommHead));

				// 消息转发
				int  sendlen;
				sendlen = s->msgsend(mtibuff, mtilen);
			}
		}
	}
	else
	{
		BOOST_LOG_SEV(*lg, info) << "sockid=" << con->get_socket().native_handle() << " 接收ws消息非法";
	}
}

// 消息推送 测试
void wsserver::msg_push_handler(string chqip, int chqport) {

	char	buff[64] = { 0 };

	char  buff2[20] = {0};
	memcpy(buff2, chqip.c_str(), chqip.length());

	while (1)
	{
		try
		{
			if (mtx.try_lock())
			{
				mtx.unlock();
			}
			else
			{
				mtx.unlock();
			}
			// socket客户端
			service = new io_service();
			m_ep = new ip::tcp::endpoint(boost::asio::ip::address::from_string(buff2), chqport);
			s = new CAsioClient(*service, *m_ep, this, lg, &mtx);
			service->run();
		}
		catch (const std::exception& e)
		{
			BOOST_LOG_SEV(*lg, info) << "CHQ connect error:" << e.what();
			
			s->socketclose();
			service->reset();

			delete s;
			delete m_ep;
			delete service;
		}

		std::this_thread::sleep_for(std::chrono::seconds(3));
	}
}

// ws消息反馈
void wsserver::msg_push_ws(char *msgbuf, int mlen, long sessionid)
{
	mt.lock();
	std::map<long, websocketpp::connection_hdl>::iterator ip = map_hdl.find(sessionid);
	if (ip != map_hdl.end())
	{
		//std::cout << "send:" << "payload:"
		//	<< websocketpp::utility::to_hex(msgbuf, mlen) << std::endl;

		// 协议转换
		char  h5msg[4096] = { 0 };
		int hlen = mti_trans_h5(msgbuf, h5msg);

		try
		{
			BOOST_LOG_SEV(*lg, info) << "反馈ws消息:" << h5msg;
			m_server.send(ip->second, h5msg, websocketpp::frame::opcode::text);
		}
		catch (const std::exception& e)
		{
			BOOST_LOG_SEV(*lg, info) << "反馈ws消息异常:" << e.what();
		}
	}
	else
	{
		BOOST_LOG_SEV(*lg, info) << "反馈ws消息错误 找不到会话:" << sessionid;
	}

	mt.unlock();
}

// 消息推送 测试
void wsserver::cllientrun() {
	try
	{
		service->run();
	}
	catch (const std::exception& e)
	{
		std::cout << "socket异常:" << e.what() << std::endl;
	}
}

long wsserver::get_sessionid()
{
	long val;

	if (sessionid >= 999999999L)
	{
		sessionid = 0;
	}

	do
	{
		val = sessionid++;
	} while (val == 0);

	return val;
}

void wsserver::run(uint16_t port) {
	// 监听端口
	m_server.listen(port);
	// 接收连接
	m_server.start_accept();
	// 开始Asio事件循环
	m_server.run();

}