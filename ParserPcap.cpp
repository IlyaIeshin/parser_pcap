#include "ParserPcap.h"
#include <stdexcept>
#include <cstring>

ParserPcap::ParserPcap(const std::string& path_file_pcap)
{
	setlocale(LC_ALL, "RU");
	file.open(path_file_pcap, std::ios_base::binary);
	if (!file.is_open())
	{
		throw std::runtime_error("Ошибка открытия файла: " + path_file_pcap);
	}
	if (path_file_pcap.substr(path_file_pcap.size() - 5) != ".pcap")
	{
		throw std::invalid_argument("Неправильный формат файла!");
	}
	file.read(reinterpret_cast<char*>(&pcaphdr), sizeof(pcaphdr));
	std::cout << "ctor ParserPcap\n";
}

ParserPcap::~ParserPcap()
{
	if (file.is_open())
	{
		file.close();
	}
}

std::pair<Packet, std::vector<uint8_t>> ParserPcap::readRecord()
{
	PcapRecordHeader recordhdr{0};
	file.read(reinterpret_cast<char*>(&recordhdr), sizeof(recordhdr));
	if (file.eof())
		return {};
	std::vector<uint8_t> data(sizeof(PcapRecordHeader) + recordhdr.incl_len);
	std::memcpy(data.data(), &recordhdr, sizeof(recordhdr));
	file.read(reinterpret_cast<char*>(data.data() + sizeof(PcapRecordHeader)), recordhdr.incl_len);

	IPHeader* iphdr = reinterpret_cast<IPHeader*>(data.data() + sizeof(PcapRecordHeader) + sizeof(EthernetHeader));

	Packet datapct;
	datapct.src_ip = ntohl(iphdr->src_addr);
	datapct.dest_ip = ntohl(iphdr->dest_addr);
	datapct.protocol = iphdr->protocol;
	if (iphdr->protocol == IPPROTO_TCP)
	{
		TCPHeader* tcphdr = reinterpret_cast<TCPHeader*>(data.data() + sizeof(PcapRecordHeader) + sizeof(EthernetHeader) + sizeof(IPHeader));
		datapct.src_port = ntohs(tcphdr->src_port);
		datapct.dest_port = ntohs(tcphdr->dest_port);
	}
	else if (iphdr->protocol == IPPROTO_UDP)
	{
		UDPHeader* udphdr = reinterpret_cast<UDPHeader*>(data.data() + sizeof(PcapRecordHeader) + sizeof(EthernetHeader) + sizeof(IPHeader));
		datapct.src_port = ntohs(udphdr->src_port);
		datapct.dest_port = ntohs(udphdr->dest_port);
	}
	std::cout << "readRecord\n";
	return { datapct, data };
}

bool ParserPcap::eof() const
{
	return file.eof();
}
