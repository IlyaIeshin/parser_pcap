#include <iostream>
#include <thread>
#include <locale>
#include "ParserPcap.h"
#include "Processor.h"

int main(int argc, char* argv[])
{
	setlocale(LC_ALL, "RU");
	if (argc != 2)
	{
		std::cout << "Использование: " << argv[0] << " <имя_файла.pcap>\n";
		exit(EXIT_FAILURE);
	}
	ParserPcap parser(argv[1]);

	//ParserPcap parser("generated_packets.pcap");

	Processor proc;

	std::thread t1(&Processor::handler1, &proc);
	std::thread t2(&Processor::handler2, &proc);
	std::thread t3(&Processor::handler3, &proc);

	proc.distribute(parser);

	t1.join();
	t2.join();
	t3.join();

	return EXIT_SUCCESS;
}