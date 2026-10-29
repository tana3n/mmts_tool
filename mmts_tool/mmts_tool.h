#pragma once
void parse(char* input);
int parse_ipv6Packet(char* packet);
struct _source {
	char* fileName;

};

struct _udpHeader {
	int srcPort;
	int dstPort;
	int dataLength;
	int checksum;
};