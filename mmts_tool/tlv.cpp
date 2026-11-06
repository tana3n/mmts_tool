#include <cstdint>
// TLVパケットの0x1を応答
int parse_packetType(char* packet) {
	return ((unsigned char*)packet)[0x1];
}
// TLVパケットのPayloadの長さを応答
int parse_tlvPayloadtSize(char* packet) {
	return ( (( ((unsigned char*)packet)[0x2]) & 0x1F) << 8 ) | ((unsigned char*)packet)[0x3];
}
// TLVの頭出し用
bool is_syncHeader(char packet) {
	if (packet == 0x7F) return true;
	else return false;
}