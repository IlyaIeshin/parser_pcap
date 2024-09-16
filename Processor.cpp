#include "Processor.h"
#include <fstream>
#include <ctime>
#include <unistd.h>
#include <algorithm>

#include <thread>
#include <chrono>

void Processor::distribute(ParserPcap& parser)
{
	while (true)
	{
		auto [datapct, data] = parser.readRecord();
		if (parser.eof())
		{
			eof = true;
			break;
		}
		if (strToIP("11.0.0.3") <= datapct.dest_ip && datapct.dest_ip <= strToIP("11.0.0.200"))
			q1.push({ datapct, data });
		else if (strToIP("12.0.0.3") <= datapct.dest_ip && datapct.dest_ip <= strToIP("12.0.0.200") &&
			datapct.dest_port == 8080)
			q2.push({ datapct, data });
		else
			q3.push({ datapct, data });
	}
}

uint32_t Processor::strToIP(const char* ip)
{
	struct in_addr addr;
	inet_aton(ip, &addr);
	return ntohl(addr.s_addr);
}

void Processor::handler1()
{
	std::ofstream file("result_1.pcap", std::ios_base::binary | std::ios_base::trunc);
	file.write(reinterpret_cast<char*>(&pcaphdr), sizeof(pcaphdr));
	std::cout << "HANDLER 1 WRITE\n";
	int packet_num = 1;
	while (true)
	{
		if (!q1.empty())
		{
			std::cout << "handler 1: process\n";
			auto [datapct, data] = q1.front();
			q1.pop();
			if (datapct.dest_port == 7070)
				std::cout << "Обработчик 1: Пакет под номером " << packet_num << " игнорируется\n";
			else
				file.write(reinterpret_cast<char*>(data.data()), data.size());
			packet_num++;
		}
		else if (eof && q1.empty())
		{
			std::cout << "handler 1: break\n";
			break;
		}
		else
		{
			std::cout << "handler 1: wait\n";
		}
	}

	file.close();
}

void Processor::handler2()
{
	std::ofstream file("result_2.pcap", std::ios_base::binary | std::ios_base::trunc);
	file.write(reinterpret_cast<char*>(&pcaphdr), sizeof(pcaphdr));
	std::cout << "HANDLER 2 WRITE\n";
	while (true)
	{
		if (!q2.empty())
		{
			std::cout << "handler 2: process\n";
			auto [datapct, data] = q2.front();
			q2.pop();
			int l4data;
			if (datapct.protocol == IPPROTO_TCP)
				l4data = sizeof(PcapRecordHeader) + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(TCPHeader);
			else
				l4data = sizeof(PcapRecordHeader) + sizeof(EthernetHeader) + sizeof(IPHeader) + sizeof(UDPHeader);
			auto pos = std::find(data.begin() + l4data, data.end(), 'x');
			if (pos != data.end())
			{
				std::string str(data.begin(), pos);
				file.write(str.c_str(), str.size());
			}
			else
				file.write(reinterpret_cast<char*>(data.data()), data.size());
		}
		else if (eof && q2.empty())
		{
			std::cout << "handler 2: break\n";
			break;
		}
		else
		{
			std::cout << "handler 2: wait\n";
		}
	}
	file.close();
}

void Processor::handler3()
{
	std::ofstream file("result_3.pcap", std::ios_base::binary | std::ios_base::trunc);
	file.write(reinterpret_cast<char*>(&pcaphdr), sizeof(pcaphdr));
	std::cout << "HANDLER 3 WRITE\n";
	while (true)
	{
		if (!q3.empty())
		{
			std::cout << "handler 3: process\n";
			auto [datapct, data] = q3.front();
			q3.pop();
			if (datapct.protocol == IPPROTO_TCP)
			{
				std::this_thread::sleep_for(std::chrono::milliseconds(2000));
				time_t tm = time(nullptr);
				if (tm % 2 == 0)
					file.write(reinterpret_cast<char*>(data.data()), data.size());
			}
			else if (datapct.protocol == IPPROTO_UDP && datapct.src_port == datapct.dest_port)
			{
				file.write(reinterpret_cast<char*>(data.data()), data.size());
				std::cout << "Обработчик 3: Найдено совпадение port = " << datapct.dest_port << "\n";
			}
		}
		else if (eof && q3.empty())
		{
			std::cout << "handler 3: break\n";
			break;
		}
		else
		{
			std::cout << "handler 3: wait\n";
		}
	}

	file.close();
}
