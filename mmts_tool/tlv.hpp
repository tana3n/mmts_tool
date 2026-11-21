int parse_packetType(char* packet);
int parse_tlvPayloadtSize(char* packet);
bool is_syncHeader(char packet);
struct _tlvNIT_header parse_TlvNIT(char* packet, int offset);
struct _tlv_nit_descriptor{};

struct _tlv_nit_stream {
};

struct _tlvNIT_header {
	int table_id;
	bool section_syntax_indicator;
	int section_length ;
	int network_id;
	int version_number;
	int current_next_indicator;
	int section_number;
	int last_section_number;
	int network_descriptors_length;
	_tlv_nit_descriptor descritor[0xFF];
	int TLV_stream_loop_length;
	_tlv_nit_stream stream[0xFF];
	int crc32;
};