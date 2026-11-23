#pragma once

int check_single_pa_message_type(char* packet, int offset);
int parse_plt(char* packet, int offset);

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

struct _table_Mpt{

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