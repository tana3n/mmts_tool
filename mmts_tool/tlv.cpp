#include <cstdint>
#include "tlv.hpp"
#include <iostream>
#include <windows.h>
#include <vector>
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

	std::cout << "TLVNITHeader.network_id: " << std::hex << TLVNITHeader.network_id << std::dec << std::endl;
	std::cout << "TLVNITHeader.section_length: " << std::hex << TLVNITHeader.section_length << std::dec << std::endl; // 4-4にある。

	std::cout << "TLVNITHeader.network_descriptors_length: " << std::hex << TLVNITHeader.network_descriptors_length << std::dec << std::endl; // 4-4にある。
	std::cout << "TLVNITHeader.version_number: " << std::hex << TLVNITHeader.version_number << std::dec << std::endl; // 4-4にある。

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
			char* DescriptorName = new char[Descriptor_length];
			for (i = 0; i < Descriptor_length; i++) {
				DescriptorName[i] = (((unsigned char*)packet)[offset + i + offset2 + 2]) & 0xFF;
				//int nn_Descriptor_data = (((unsigned char*)packet)[offset + i + offset2 + 2]) & 0xFF;
				//DescriptorName[i] = nn_Descriptor_data;
				//std::cout << std::hex << nn_Descriptor_data << std::dec << std::endl;

			}
			// ref: http ://yukakumumu.blog.fc2.com/blog-entry-38.html

			std::string out = DescriptorName;

			int sizeU = MultiByteToWideChar(CP_UTF8, 0, out.c_str(), -1, NULL, 0);
			wchar_t* Unicode= new wchar_t[sizeU];
			MultiByteToWideChar(CP_UTF8, 0, out.c_str(), -1, Unicode, sizeU);

			int dest_size = WideCharToMultiByte(932, 0, Unicode, -1, NULL, 0, NULL, NULL);
			char* CP932 = new char[dest_size];
			WideCharToMultiByte(932, 0, Unicode, -1, CP932, dest_size, NULL, NULL);

			std::string out2 = CP932;
			std::cout << "[NIT-TLV]0x"<< std::hex << Descriptor_tag << std::dec << ": " << out2.c_str() << std::endl;

			delete[] DescriptorName;
			delete[] CP932;
			delete[] Unicode;
		}
		else if (Descriptor_tag == 0x41) { // あってるかは不明
			for (i = 0; i < Descriptor_length; i = i + 3) {
				int ServiceId = (((((unsigned char*)packet)[offset + i + offset2 + 2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + i + offset2 + 2 +1];
				int ServiceType = (((unsigned char*)packet)[offset + i + offset2 + 2 + 2]) & 0xFF;
				std::cout << "[NIT-TLV]0x41 ServiceId: "  << ServiceId << std::dec << std::endl;
				std::cout << "[NIT-TLV]0x41 ServiceType: " << std::hex << ServiceType << std::dec << std::endl;
			}
		} else if(Descriptor_tag == 0x43 || Descriptor_tag == 0xCD || Descriptor_tag == 0xFE){
			std::cout << "Descriptor tag Id : 0x" << std::hex << Descriptor_tag << std::dec << std::endl;
		}

		offset2 = offset2 + 2 +Descriptor_length;
		i = i + 2+ Descriptor_length;

	}
	return TLVNITHeader;	
}