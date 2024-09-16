#ifndef PROCESSOR_H
#define PROCESSOR_H

#include <vector>
#include <queue>
#include <atomic>
#include "ParserPcap.h"

class Processor
{
	using DataPacket = std::pair<Packet, std::vector<uint8_t>>;
public:
	Processor() : eof(false) { }

	void distribute(ParserPcap& parser);

	void handler1();
	void handler2();
	void handler3();
private:
	uint32_t strToIP(const char* ip);
	std::queue<DataPacket> q1;
	std::queue<DataPacket> q2;
	std::queue<DataPacket> q3;
	std::atomic<bool> eof;
};

#endif // !PROCESSOR_H


