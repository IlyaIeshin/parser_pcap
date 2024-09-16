cmake_minimum_required(VERSION 3.10)

project(parser_pcap LANGUAGES CXX)

find_package(Threads REQUIRED)

set(CMAKE_CXX_STANDARD 17)

add_executable (parser_pcap "main.cpp" "ParserPcap.cpp" "Processor.cpp")

target_link_libraries(parser_pcap PRIVATE Threads::Threads)