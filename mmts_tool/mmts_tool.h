#pragma once
void parse(char* input);
int parse_ipv6Packet(char* packet);
struct _compressedIpPacket parse_compressedIpPacket(char* packet, int offset);
struct _udpHeader getUDPHeader(char* packet, int offset);
struct _mmtpHeader parseMmtpHeader(char* packet, int offset);
bool check_drop(struct _mmtpHeader Header, std::intmax_t* mMTPacketLastSequenceNumber, std::uintmax_t* mMTPacketDropCounter);

struct _source {
	char* fileName;

};

struct _udpHeader {
	int srcPort;
	int dstPort;
	int dataLength;
	int checksum;
};

struct _mmtpHeader {
	int version;
	bool packetCounterFlag;
	int fECType;
	int packetId;
	int packetSequenceNumber;
};


struct _particalUDPHeader {
	int srcPort;
	int dstPort;
};

// 本来のv6のヘッダーより2バイト小さくなる(38b+ExtensionHeader+UDP)
struct _particalIpv6Header {
	int version;
	int trafficClass;
	int flowLabel;
	//int payloadLength;
	int nextHeader; //このv6のヘッダーの後に何のHeaderがあるかを設定
	int hopLimit;
	int sourceAddress;
	int destinationAddress;
	int extensionHeader;

};

struct _particalHeader {
	struct _particalIpv6Header particalIpv6Header;
	struct _particalUDPHeader particalUDPHeader;
};

struct _compressedIpPacket {
	int contentId;
	int packetSequenceNumber;
	int headerType;
	struct _particalHeader compressedHeader;
};
