#pragma once
void parse(struct _args input);
struct _iPv6Header parse_ipv6Packet(struct _iPv6Header Header,  char* packet, int offset);
struct _compressedIpPacket parse_compressedIpPacket(struct _compressedIpPacket IpPacket, char* packet, int offset);
struct _udpHeader getUDPHeader(struct _udpHeader UDPHeader, char* packet, int offset);
struct _mmtpHeader parseMmtpHeader(char* packet, int offset);
struct _mmtpExtensionHeader parseMmtpExtensionHeader(char* packet, int offset);
bool check_drop(struct _mmtpHeader Header, struct _MmtPacketIdInformation* mmtpPacketsInfo);
bool check_scrambling(struct _mmtpExtensionHeader Header);

struct _args {
	char* inputFileName;
	const char* outputFileName;
	bool selectMode;
	int selectedTLVType;
	int outputSize;

};

struct _iPv6Header {
	int version;
	int payloadLength;
	int nextHeader;

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
	int payloadType;
	int packetId;
	int packetSequenceNumber;
	bool extensionHeaderFlag;
	int extensionHeaderType;
	int extensionHeaderLength;
};

struct _mmtpExtensionHeader {
	int headerType;
	int mmtScramblingControl;
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

struct _MmtPacketIdInformation {
	int total = 0;
	int dropTotal = 0;
	int scramblingTotal = 0;
	int errorTotal = 0;
	int lastSequenceNumber = -1;
	std::string packetIdName;

};