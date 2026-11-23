#include <string>
#include <iostream>

#include "mmtp.h"
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
}
