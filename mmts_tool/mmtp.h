#pragma once

int check_single_pa_message_type(char* packet, int offset);
int parse_plt(char* packet, int offset);
struct _mmt_package_table parse_mpt(char* packet, int offset);
struct _m2_section_message parse_m2_section(char* packet, int offset);
struct _mh_sdt parse_mh_sdt(char* packet, int offset);
struct _mmtp_payload {

};

struct _mpu_payload {
	int payload_length;
	int fragment_type;
	int timed_flag;

};

struct _pa_table {
	int table_id;
	int table_version;
	int table_length;
};

struct _pa_message {
	int message_id;
	int version;
	int length;
	std::uintmax_t number_of_tables;
	_pa_table pa_table[0xFF];
};

struct _mmt_package_table {
	int table_id;
	int length;
	int mpt_mode;
	int mmt_package_id_length;
	int mpt_descriptors_length;
	// descriptor;
	int number_of_assets;
    // struct assets;
};


struct _table_Plt{};

struct _signaling_message {
	int fragmentation_indicator = 0;
	bool length_extension_flag = false;
	bool aggregation_flag = false;
	int fragment_counter = 0;
};

struct _plt {

};

struct _m2_section_message {
	int message_id;
	int version;
	int length;
	int table_id;
	bool section_syntax_indicator;
	int section_length;
    
};

struct _mh_cdt {
	int table_id;
	int data_type;
	int descriptors_loop_length;
};

struct _mh_service_descriptor {
	int descriptor_tag;
	int descriptor_length;
	int service_type;
	int service_provider_name_length;
	std::string service_provider_name;
	int service_name_length;
	std::string service_name;
};

struct _mh_sdt {
	int table_id;
	int section_length;
	int tlv_stream_id;
	int original_network_id;
	_mh_service_descriptor mh_service_descriptor;
};

struct _mh_sdt_infomation {

};