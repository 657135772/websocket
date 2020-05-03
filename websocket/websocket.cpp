// websocket.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "ws.h"
#include <fstream>

// g++ -o s websocket.cpp ws.cpp json/cJSON.c json/CJsonObject.cpp -I/root/install/websocketpp-master -std=c++11 -lpthread -lboost_thread -lboost_locale -Wl,-rpath,/usr/local/lib:./

void log_init() 
{
	logging::add_file_log
	(
		keywords::file_name = "log/wslog_%Y%m%d_%H%M%S_%5N.log",                                        /*< file name pattern >*/
		keywords::rotation_size = 100 * 1024 * 1024,                                   /*< rotate files every 10 MiB... >*/
		keywords::time_based_rotation = sinks::file::rotation_at_time_point(0, 0, 0), /*< ...or at midnight >*/
		keywords::format = "[%TimeStamp%]: %Message%"                                 /*< log record format >*/
	);
}

int main()
{
	int		lisport;
	string	chqip;
	int		chqport;

	char buf[1024];
	char jbf[1024] = { 0 };
	ifstream ifs;

	ifs.open("config.json", ios::in);
	if (!ifs.is_open())
	{
		cout << "配置文件打开失败！" << endl;
		return -1;
	}
	
	while (ifs.getline(buf, sizeof(buf)))
	{
		strcat(jbf, buf);
	}
	ifs.close();

	neb::CJsonObject oJson(jbf);
	lisport = atoi(oJson["LISPORT"].ToString().c_str());
	oJson.Get("CHQIP", chqip);
	chqport = atoi(oJson["CHQPORT"].ToString().c_str());

	log_init();
	logging::add_common_attributes();
	src::severity_logger<severity_level> lg;

	wsserver s(chqip, chqport, lg);
	try
	{
		s.run(lisport);
	}
	catch (const std::exception& e)
	{
		std::cout << e.what() << std::endl;
		BOOST_LOG_SEV(lg, info) << "异常退出:" << e.what();
	}

	return 0;
}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门使用技巧: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件
