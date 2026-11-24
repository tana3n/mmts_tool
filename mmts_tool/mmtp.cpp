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
	return _m2_section_message; // 13Bytes + Data + 4Bytes
};

struct _mh_sdt parse_mh_sdt(char* packet, int offset) {
	_mh_sdt sdt_header{};
	sdt_header.table_id = ((((unsigned char*)packet)[offset] & 0xFF) << 8);
	std::cout << "parse_mh_sdt:" << sdt_header.table_id << std::endl;
	int a  = (((((unsigned char*)packet)[offset + 1]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 2];
	std::cout << "parse_mh_sdt section length:" << a
	<< std::endl;
	sdt_header.descriptors_loop_length = ((((unsigned char*)packet)[offset] & 0x1F) << 11) | ((unsigned char*)packet)[offset + 12];
	std::cout << "parse_mh_sdt descriptors_loop_length:" << sdt_header.descriptors_loop_length << std::endl;

	dump_hex(packet, offset, offset + sdt_header.descriptors_loop_length);
	print_hex_to_utf8(packet, offset + 13, sdt_header.descriptors_loop_length);

	// 14bytes目にdescriptorがいる、かも
	return sdt_header;
};