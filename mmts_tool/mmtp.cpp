#include <string>
#include <iostream>

#include <windows.h>


#include "mmtp.h"
#include "common.h"
std::string packetid_meaning_text(int PID) {
	switch (PID) {
	case 0x0000:
		return "PA Message";
	case 0x0001:
		return "CA Message";
			  
	}
}

// 既に決まっているのは決め打ちで良いけど、ほかのMMT-SIはどうにかテーブルから持ってこないと肝心の映像音声とかはわかんにゃいかも
// STD-B60 4.3 

int check_single_pa_message_type(char* packet, int offset) {
	int types = ((unsigned char*)packet)[offset];
	return types;
};

int parse_plt(char* packet, int offset) {
	int length = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
	int number_of_package = ((unsigned char*)packet)[offset + 4];


	//std::cout << "length:" << length << std::endl;
	//std::cout << "number_of_package:" << number_of_package << std::endl;
	int offset2 = 5;
	int package_id_length = ((unsigned char*)packet)[offset + offset2];
	// 本当は複数あるが応答値が複数の時の事をちょっと考えておく必要があるので一旦1つの前提で
	//for (int i = 0; i < number_of_package; i++) {
	//	//std::cout << "MMT_package_id_length:" << package_id_length << std::endl;
	//}
	/*for (int i = 0; i < package_id_length; i++) {
		int package_id_length = ((unsigned char*)packet)[offset + offset2];
	}*/
	offset2 = offset2 + package_id_length + 1;
	// Location Info
	int location_type = ((unsigned char*)packet)[offset + offset2];

	return ((((unsigned char*)packet)[offset + offset2 + 1] & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 2];
};

struct _m2_section_message parse_m2_section(char* packet, int offset) {
	_m2_section_message _m2_section_message{};
	_m2_section_message.message_id = ((((unsigned char*)packet)[offset] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 1];
	_m2_section_message.length = ((((unsigned char*)packet)[offset + 3] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 4];
	_m2_section_message.table_id = ((unsigned char*)packet)[offset + 5];
	_m2_section_message.section_length = ((((unsigned char*)packet)[offset + 6] & 0x1F) << 8) | ((unsigned char*)packet)[offset + 7];

	return _m2_section_message; // 13Bytes + Data + 4Bytes
};

struct _mh_cdt parse_mh_cdt(char* packet, int offset) {
	_mh_cdt sdt_header{};
	sdt_header.table_id = ((((unsigned char*)packet)[offset] & 0xFF) << 8);
	std::cout << "parse_mh_sdt:" << sdt_header.table_id << std::endl;
	int a  = (((((unsigned char*)packet)[offset + 1]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 2];
	std::cout << "parse_mh_sdt section length:" << a
	<< std::endl;
	sdt_header.data_type = ((unsigned char*)packet)[offset + 10];
	std::cout << "parse_mh_sdt std_header.data_type:" << sdt_header.data_type << std::endl;

	sdt_header.descriptors_loop_length = ((((unsigned char*)packet)[offset] & 0x1F) << 11) | ((unsigned char*)packet)[offset + 12];
	std::cout << "parse_mh_sdt descriptors_loop_length:" << sdt_header.descriptors_loop_length << std::endl;
	// ここはDescriptorsが入っているに過ぎない
	dump_hex(packet, offset + 13, sdt_header.descriptors_loop_length);

	int offset2 = 13;
    int tag = (((((unsigned char*)packet)[offset + offset2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 1];
	int length = ((unsigned char*)packet)[offset + offset2 + 2];
	int mmt_package_id_length = ((unsigned char*)packet)[offset + offset2 + 3];
	print_hex_to_utf8(packet, offset + offset2 , sdt_header.descriptors_loop_length);
	//print_hex_to_utf8(packet, offset + 13, sdt_header.descriptors_loop_length);
	return sdt_header;
};

struct _mh_sdt parse_mh_sdt(char* packet, int offset) {
	_mh_sdt sdt_header{};
	sdt_header.table_id = ((((unsigned char*)packet)[offset] & 0xFF) << 8);
	std::cout << "parse_mh_sdt:" << sdt_header.table_id << std::endl;
	sdt_header.section_length = (((((unsigned char*)packet)[offset + 1]) & 0xF) << 8) | ((unsigned char*)packet)[offset + 2];
	std::cout << "parse_mh_sdt section length:" << sdt_header.section_length << std::endl;
	sdt_header.tlv_stream_id = (((((unsigned char*)packet)[offset + 3]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 4];
	std::cout << "parse_mh_sdt sdt_header.tlv_stream_id:" << sdt_header.tlv_stream_id << std::endl;

	sdt_header.original_network_id = ((((unsigned char*)packet)[offset + 8] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 9];

	std::cout << "parse_mh_sdt original_network_id:" << sdt_header.original_network_id << std::endl;
	//dump_hex(packet, offset + 13, sdt_header.section_length);

	int offset2 = 11;
	int sid = (((((unsigned char*)packet)[offset + offset2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 1];
	std::cout << "parse_mh_sdt sid:" << sid << std::endl;

	int descriptors_loop_length = (((((unsigned char*)packet)[offset + offset2 + 3]) & 0xF) << 8) | ((unsigned char*)packet)[offset + offset2 + 4];
	std::cout << "parse_mh_sdt descriptors_loop_length:" << descriptors_loop_length << std::endl;

	int descriptor_tag = (((((unsigned char*)packet)[offset + offset2 + 5]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 6];
	std::cout << "parse_mh_sdt descriptor_tag:" << std::hex << descriptor_tag << std::dec << std::endl;
	int descriptor_length = ((unsigned char*)packet)[offset + offset2 + 7];
	std::cout << "parse_mh_sdt descriptor_length:" << std::hex << descriptor_length << std::dec << std::endl;

	if (descriptor_tag == 0x8019) { // MH-Service_Descriptor
		_mh_service_descriptor serviceDescriptor{};
		serviceDescriptor.descriptor_tag = descriptor_tag;
		serviceDescriptor.descriptor_length = descriptor_length;
		serviceDescriptor.service_type= ((unsigned char*)packet)[offset + offset2 + 8];
		serviceDescriptor.service_provider_name_length = ((unsigned char*)packet)[offset + offset2 + 9];
		serviceDescriptor.service_name_length = ((unsigned char*)packet)[offset + offset2 + 10 + serviceDescriptor.service_provider_name_length];

		print_hex_to_utf8(packet, offset + offset2 + 10, serviceDescriptor.service_provider_name_length);
		dump_hex(packet, offset + offset2 + 10, serviceDescriptor.service_provider_name_length);
		print_hex_to_utf8(packet, offset + offset2 + 11 + serviceDescriptor.service_provider_name_length, serviceDescriptor.service_name_length);
		dump_hex(packet, offset + offset2 + 11 + serviceDescriptor.service_provider_name_length, serviceDescriptor.service_name_length);
		sdt_header.mh_service_descriptor = serviceDescriptor;

	}
	return sdt_header;
};