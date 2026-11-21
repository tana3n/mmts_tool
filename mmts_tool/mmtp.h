#pragma once

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
	int fragmentation_indicator;
	bool length_extension_flag;
	bool aggregation_flag;
	int fragment_counter;
};