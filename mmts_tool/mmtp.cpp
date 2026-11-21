#include <string>

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