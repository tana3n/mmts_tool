#include <string>
#include <iostream>

#include <windows.h>

#include "mmts_tool.h"
#include "mmtp.h"
#include "common.h"


std::string get_asset_type_name(int input) {
	switch (input) {
	case 0x68657631: // hev1
		return "HEVC";
	case 0x6D703461: //mp4a
		return "MPEG4 Audio";
	case 0x61617070: // aapp
		return "Application"; // STD-B60 Table 7-8
	default:
		//std::cout << "get_asset_type_name"  << std::uppercase << std::hex << input << std::nouppercase << std::dec << std::endl;
		return "unknown Type";
	}
	
}


struct _MmtPacketIdInformation* set_hr_asset_type_name(_packet_id_info* packet_id_info, _MmtPacketIdInformation* mMTPacketsInfo) {
	for (int i = 0; i < 0xFFFF; i++) {
		if (mMTPacketsInfo[i].total != 0) {
			switch (i) {
			case 0x0000:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "PA Message";
				break;
			case 0x0001:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "CA Message";
				break;
			case 0x8000:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-EIT";
				break;
			case 0x8001:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-AIT";
				break;
			case 0x8002:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-BIT";
				break;
			case 0x8003:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-SDTT";
				break;
			case 0x8004:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-SDT";
				break;
			case 0x8005:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-TOT";
				break;
			case 0x8006:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-CDT";
				break;
			case 0x8007:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "Data Transmission Message";//これなに
				break;
			case 0x8008:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-DIT";
				break;
			case 0x8009:
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = "MH-SIT";
				break;
			default:
				std::string messageName = get_asset_type_name(packet_id_info[i].asset_type);
				mMTPacketsInfo[i].hr_packet_id_asset_type_name = messageName;

			}
		}
	}
	return mMTPacketsInfo;
}

// 既に決まっているのは決め打ちで良いけど、ほかのMMT-SIはどうにかテーブルから持ってこないと肝心の映像音声とかはわかんにゃいかも
// STD-B60 4.3 

int check_single_pa_message_type(char* packet, int offset) {
	int types = ((unsigned char*)packet)[offset];
	return types;
};
// 
int parse_plt(char* packet, int offset) {
	int length = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
	int number_of_package = ((unsigned char*)packet)[offset + 4];


	//std::cout << "length:" << length << std::endl;
	//std::cout << "number_of_package:" << number_of_package << std::endl;
	int offset2 = 5;
	int package_id_length = ((unsigned char*)packet)[offset + offset2];
	// 本当は複数の時の事をちょっと考えておく必要があるが一旦1つの前提で
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
struct _packet_id_info* parse_mpt(_packet_id_info* packet_id_info, char* packet, int offset) {
	_mmt_package_table table{};
	table.length = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
	//dump_hex(packet, offset + 4, table.length);

	table.mpt_mode = (((unsigned char*)packet)[offset + 4]) & 0x3;
	table.mmt_package_id_length = ((unsigned char*)packet)[offset + 5];
	//std::cout << "table.mmt_package_id_length:" << table.mmt_package_id_length << std::endl;

	//dump_hex(packet, offset + 6, table.mmt_package_id_length);
	table.mpt_descriptors_length = ((unsigned char*)packet)[offset + 7 + table.mmt_package_id_length];
	//std::cout << "table.mpt_descriptors_length:" << table.mpt_descriptors_length << std::endl;

	//dump_hex(packet, offset + 8 + table.mmt_package_id_length, table.mpt_descriptors_length);
	table.number_of_assets = ((unsigned char*)packet)[offset + 8 + table.mmt_package_id_length + table.mpt_descriptors_length];
	//std::cout << "table.number_of_assets:" << table.number_of_assets << std::endl;

	// assetは14バイト+asset_id_type+MMT_general_location_info+asset_descriptors_length
	// 固定長ではなさそう
	int current = offset + 9 + table.mmt_package_id_length + table.mpt_descriptors_length;
	while (current - offset - 4 < table.length) {
		int identifier_type = ((unsigned char*)packet)[current];
		//std::cout << "table.identifier_type:" << identifier_type << std::endl;
		int asset_id_scheme = ((((unsigned char*)packet)[current + 1] & 0xFF) << 24) |
			((((unsigned char*)packet)[current + 2] & 0xFF) << 16) |
			((((unsigned char*)packet)[current + 3] & 0xFF) << 8) |
			((unsigned char*)packet)[current + 4];
		int asset_id_length = ((unsigned char*)packet)[current + 5];
		int asset_id_byte;
		if (asset_id_length == 2) {
			asset_id_byte = ((((unsigned char*)packet)[current + 6] & 0xFF) << 8) | ((unsigned char*)packet)[current + 7];
		}
		else {
			std::cout << "table.asset_id_length: 0x" << std::hex << asset_id_length << std::dec << std::endl;
		};

		//std::cout << "table.asset_id_byte: 0x" << std::hex << asset_id_byte << std::dec << std::endl;
		int asset_type = ((((unsigned char*)packet)[current + 6 + asset_id_length] & 0xFF) << 24) |
			((((unsigned char*)packet)[current + 6 + asset_id_length + 1] & 0xFF) << 16) |
			((((unsigned char*)packet)[current + 6 + asset_id_length + 2] & 0xFF) << 8) |
			((unsigned char*)packet)[current + 6 + asset_id_length + 3];
		//dump_hex(packet, current + 6 + asset_id_length, 4);
		//std::cout << "table.asset_type: 0x" << std::hex << asset_type << std::dec << std::endl;

		int location_count = ((unsigned char*)packet)[current + 6 + asset_id_length + 4 + 1];
		current = current + 7 + asset_id_length + 4 + 1;
		//std::cout << "location_count: " << location_count << std::endl;
		
		//ちゃんとチェックしないとまずい気はするが…
		packet_id_info[asset_id_byte].asset_type = asset_type;

		for (int i = 0; i < location_count; i++) {
			int location_type = ((unsigned char*)packet)[current];
			if (location_type == 0x00)
			{
				//std::cout << "packet_id" << std::endl;
				//dump_hex(packet, current + 1, 2);
				current = current + 3;
			}
			else if (location_type == 0x01) {
				current = current + 13;
			}
			else if (location_type == 0x02) {
				current = current + 37;
			}
			else if (location_type == 0x03) {
				current = current + 7;
			}
			else if (location_type == 0x04) {
				current = current + 37;
			}
			else if (location_type == 0x05) {
				int url_length = ((unsigned char*)packet)[current + 1];
				current = current + url_length + 1;
			}
		}
		int asset_descriptors_length = ((((unsigned char*)packet)[current] & 0xFF) << 8) | ((unsigned char*)packet)[current +1];
		//dump_hex(packet, current + 2, asset_descriptors_length);
		current = current  + 2 + asset_descriptors_length;
	}
	return packet_id_info;
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
	//print_hex_to_utf8(packet, offset + offset2 , sdt_header.descriptors_loop_length);
	//print_hex_to_utf8(packet, offset + 13, sdt_header.descriptors_loop_length);
	return sdt_header;
};

struct _mh_sdt parse_mh_sdt(char* packet, int offset) {
	_mh_sdt sdt_header{};
	sdt_header.table_id = ((((unsigned char*)packet)[offset] & 0xFF) << 8);
	//std::cout << "parse_mh_sdt:" << sdt_header.table_id << std::endl;
	sdt_header.section_length = (((((unsigned char*)packet)[offset + 1]) & 0xF) << 8) | ((unsigned char*)packet)[offset + 2];
	//std::cout << "parse_mh_sdt section length:" << sdt_header.section_length << std::endl;
	sdt_header.tlv_stream_id = (((((unsigned char*)packet)[offset + 3]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 4];
	//std::cout << "parse_mh_sdt sdt_header.tlv_stream_id:" << sdt_header.tlv_stream_id << std::endl;

	sdt_header.original_network_id = ((((unsigned char*)packet)[offset + 8] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 9];

	//std::cout << "parse_mh_sdt original_network_id:" << sdt_header.original_network_id << std::endl;
	//dump_hex(packet, offset + 13, sdt_header.section_length);

	int offset2 = 11;
	int sid = (((((unsigned char*)packet)[offset + offset2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 1];
	//std::cout << "parse_mh_sdt sid:" << sid << std::endl;

	int descriptors_loop_length = (((((unsigned char*)packet)[offset + offset2 + 3]) & 0xF) << 8) | ((unsigned char*)packet)[offset + offset2 + 4];
	//std::cout << "parse_mh_sdt descriptors_loop_length:" << descriptors_loop_length << std::endl;

	int descriptor_tag = (((((unsigned char*)packet)[offset + offset2 + 5]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 6];
	//std::cout << "parse_mh_sdt descriptor_tag:" << std::hex << descriptor_tag << std::dec << std::endl;
	int descriptor_length = ((unsigned char*)packet)[offset + offset2 + 7];
	//std::cout << "parse_mh_sdt descriptor_length:" << std::hex << descriptor_length << std::dec << std::endl;

	if (descriptor_tag == 0x8019) { // MH-Service_Descriptor
		_mh_service_descriptor serviceDescriptor{};
		serviceDescriptor.descriptor_tag = descriptor_tag;
		serviceDescriptor.descriptor_length = descriptor_length;
		serviceDescriptor.service_type= ((unsigned char*)packet)[offset + offset2 + 8];
		serviceDescriptor.service_provider_name_length = ((unsigned char*)packet)[offset + offset2 + 9];
		serviceDescriptor.service_name_length = ((unsigned char*)packet)[offset + offset2 + 10 + serviceDescriptor.service_provider_name_length];
		//std::cout << "\n" << std::endl;
		//print_hex_to_utf8(packet, offset + offset2 + 10, serviceDescriptor.service_provider_name_length);
		//dump_hex(packet, offset + offset2 + 10, serviceDescriptor.service_provider_name_length);
		//print_hex_to_utf8(packet, offset + offset2 + 11 + serviceDescriptor.service_provider_name_length, serviceDescriptor.service_name_length);
		//dump_hex(packet, offset + offset2 + 11 + serviceDescriptor.service_provider_name_length, serviceDescriptor.service_name_length);
		sdt_header.mh_service_descriptor = serviceDescriptor;

	}
	return sdt_header;
};