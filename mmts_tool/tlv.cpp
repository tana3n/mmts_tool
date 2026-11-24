#include <cstdint>
#include <iostream>
#include <windows.h>
#include <vector>

#include "tlv.hpp"
#include "common.h"
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
struct _tlvNIT_header parse_TlvNIT(char* packet, int offset) {
	_tlvNIT_header TLVNITHeader{};
	TLVNITHeader.table_id = (((unsigned char*)packet)[offset + 0]) & 0xFF;
	TLVNITHeader.section_syntax_indicator = (((unsigned char*)packet)[offset + 1] >> 7) & 0x1;
	TLVNITHeader.section_length = ((((unsigned char*)packet)[offset + 1] & 0x1F) << 8) | ((unsigned char*)packet)[offset + 2]; // 1021未満である必要がある
	TLVNITHeader.network_id = ((((unsigned char*)packet)[offset + 3] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 4];
	TLVNITHeader.version_number = (((unsigned char*)packet)[offset + 5] >> 1) & 0x3F;
	TLVNITHeader.network_descriptors_length = ((((unsigned char*)packet)[offset + 8] & 0x1F) << 8) | ((unsigned char*)packet)[offset + 9]; // 有効10Bit

	//std::cout << "TLVNITHeader.network_id: " << std::hex << TLVNITHeader.network_id << std::dec << std::endl;
	//std::cout << "TLVNITHeader.section_length: " << std::hex << TLVNITHeader.section_length << std::dec << std::endl; // 4-4にある。

	//std::cout << "TLVNITHeader.network_descriptors_length: " << std::hex << TLVNITHeader.network_descriptors_length << std::dec << std::endl; // 4-4にある。
	//std::cout << "TLVNITHeader.version_number: " << std::hex << TLVNITHeader.version_number << std::dec << std::endl; // 4-4にある。

	int i = 0;
	int offset2 = 10;
	while (i < TLVNITHeader.network_descriptors_length) {
		int Descriptor_tag = (((unsigned char*)packet)[offset + offset2]) & 0xFF;
		int Descriptor_length = (((unsigned char*)packet)[offset + 1 + offset2]) & 0xFF;
		/*std::cout << "TLVNITHeader.Descriptor_tag: " << std::hex << Descriptor_tag << std::dec << std::endl;
		std::cout << "TLVNITHeader.Descriptor_length: " << std::hex << Descriptor_length << std::dec << std::endl;
		std::cout << "TLVNITHeader.i: " << std::hex << i << std::dec << std::endl;*/
		if (Descriptor_length == 0) { break; } // 本当はCRCを見て跳ねるべき

		if (Descriptor_tag == 0x40) {
			//print_hex_to_utf8(packet, offset + offset2 + 2, Descriptor_length);

		}
		else if (Descriptor_tag == 0x41) { // あってるかは不明
			for (i = 0; i < Descriptor_length; i = i + 3) {
				int ServiceId = (((((unsigned char*)packet)[offset + i + offset2 + 2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + i + offset2 + 2 +1];
				int ServiceType = (((unsigned char*)packet)[offset + i + offset2 + 2 + 2]) & 0xFF;
				//std::cout << "[NIT-TLV]0x41 ServiceId: "  << ServiceId << std::dec << std::endl;
				//std::cout << "[NIT-TLV]0x41 ServiceType: " << std::hex << ServiceType << std::dec << std::endl;
			}
		} else if(Descriptor_tag == 0x43 || Descriptor_tag == 0xCD || Descriptor_tag == 0xFE){
			//std::cout << "Descriptor tag Id : 0x" << std::hex << Descriptor_tag << std::dec << std::endl;
		}

		offset2 = offset2 + 2 +Descriptor_length;
		i = i + 2+ Descriptor_length;

	}
	return TLVNITHeader;	
}