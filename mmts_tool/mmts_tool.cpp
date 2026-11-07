#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include <filesystem>
#include <regex>

#include "tlv.hpp"
#include "mmts_tool.h"

using namespace std::filesystem;

int main(int argc, char* argv[])
{
    //std::cout << "loas-tools Version " << Version << "\n\n";


    if (!argv[1]) {
        std::cout << "[Error]No Input\n\n";
        //usage();

        return 0;
    }
    //cli_parser(argv, argc);
    std::cout << argv[1] << "\n\n";

    parse(argv[1]);
    return 0;
}

void parse(char* input)

{ 
    /* Search Sync Header (ex. 7f)
    STD-B32 Part3 3.5
    int SYNC_TLV = 0x7F
    Packet Type 1b
    Data Length 2b
    honhe ex. 0x5A6

    */

    std::uintmax_t* tlvPacketCount = new std::uintmax_t[0x100]{};
    int tlvPacketTotalCount = 0;
    int tlvPacketResyncCount = 0;

    std::uintmax_t* mMTPacketCount = new std::uintmax_t[0xFFFF]{};
    std::intmax_t* mMTPacketLastSequenceNumber = new std::intmax_t[0xFFFF]{-1}; // 0になるけど、どうする？ストリームとしては0ではないはずだよ？// 後でtsselectみにいこう
    std::uintmax_t* mMTPacketDropCounter = new std::uintmax_t[0xFFFF]{ 0 };
    std::intmax_t unknownTLVPacketType = 0;
    std::intmax_t nullTLVPacket = 0;

    // 多分Structかなんかで構造体でファイル情報渡してからParseした方が良さそうな気がする
    char* hBuf = new char[2000];

    std::intmax_t size = file_size(input);

    std::ifstream source(input, std::ios::in | std::ios::binary);
    if (!source) {
        std::cout << "Can not open source: " << input;
        return;
    }

    int packetType = 0xFD;
    std::uintmax_t payloadSize = 0;
    std::intmax_t  current = source.tellg();
    int UDPPayloadEnd = 0;

    struct _iPv6Header IPv6Header {};
    struct _udpHeader UDPHeader {};
    struct _mmtpHeader MmtpHeader {};
    struct _compressedIpPacket compressedIpHeader {};

    while (current < size) {
        source.seekg(current);
        source.read(hBuf, 2000);
        //if (!is_syncHeader(hBuf[0])) {
        if (!(hBuf[0] == 0x7F)) {

            source.seekg(current + 1);
            tlvPacketResyncCount++;
            continue;
        }
        packetType = ((unsigned char*)hBuf)[0x1];/* parse_packetType(hBuf)*/;
        //std::cout << "TLV Packet packetType hbuf[1]:"  << hBuf[1] << std::endl;
        //std::cout << "TLV Packet packetType a:" << std::hex << packetType << std::endl;      

        if (packetType <= 0xFF) {
            tlvPacketCount[packetType]++;
            tlvPacketTotalCount++;
        } else {
            std::cout << "TLV Packet packetType:" << packetType << std::endl;
            current++;
            tlvPacketResyncCount++;
            continue;
        }
        current = current + 4; //たまたまSyncHeaderが生きてるだけの可能性を考慮してここで判定する
        //parse_tlvPayloadtSize(hBuf);
        payloadSize = parse_tlvPayloadtSize(hBuf);

        //std::cout << "TLV Packet payloadSize2:" << payloadSize << std::endl;
        current = current + payloadSize;
        //source.read(hBuf, 4 + payloadSize);

        if (packetType == 0x2) {
            IPv6Header = parse_ipv6Packet(IPv6Header, hBuf, 4);

            // UDPHeaderを何とかしてPayloadを触れるようにする
            //char* udpPacket = getPayload(pBuf, 40, v6Payload); // 256+64 = 320bit
            // nextHeaderがUDPだったらそのまま処理する
            UDPHeader = getUDPHeader(UDPHeader, hBuf, 4 + 40);
            UDPPayloadEnd = UDPHeader.dataLength + 40;
            if (!(payloadSize == UDPPayloadEnd)) {
                std::cout << "TLV Payload Size: " << payloadSize << "  UDP Payload + 40 + 8 : " << UDPPayloadEnd 
                    << std::endl;
                // TLV(4Byte) + IPv6Header(40Byte) + UDP(8Byte) + UDPPayload(?) = TLV(4Byte) + TLVPayload(96Byte)
                // v6Header(40) + v6Payload(56bytes) = 96bytes
            }
            MmtpHeader =  parseMmtpHeader(hBuf, 4 + 40 + 8);
            //std::cout << "PID: " << MmtpHeader.packetId << "  Detect version : " << MmtpHeader.version << std::endl;

            // 帰ってきたHeaderからPIDと前回とのカウンターを比較して何とかする。初回はどうするかなあ……
            if (check_drop(MmtpHeader, mMTPacketLastSequenceNumber, mMTPacketDropCounter) == true) {
                mMTPacketDropCounter[MmtpHeader.packetId] += 1;
                //std::cout << "PID: " << MmtpHeader.packetId << "Detect Packet Drop Address : " << current << std::endl;
            }
            mMTPacketLastSequenceNumber[MmtpHeader.packetId] = MmtpHeader.packetSequenceNumber;
            mMTPacketCount[MmtpHeader.packetId] += 1;

        //    // diff取ったときに未設定の値だった場合はどうこうとか？

        }
        else if (packetType == 0x3) {
            compressedIpHeader = parse_compressedIpPacket(compressedIpHeader, hBuf, 4 + 0);

            if (compressedIpHeader.headerType == 0x61) {

                MmtpHeader = parseMmtpHeader(hBuf, 4 + 4);
                //std::cout << "PID: " << MmtpHeader.packetId << "  Detect version : " << MmtpHeader.version << std::endl;

                // 帰ってきたHeaderからPIDと前回とのカウンターを比較して何とかする。初回はどうするかなあ……
                if (check_drop(MmtpHeader, mMTPacketLastSequenceNumber, mMTPacketDropCounter) == true) {
                    mMTPacketDropCounter[MmtpHeader.packetId] += 1;
                    //std::cout << "PID: " << MmtpHeader.packetId << "Detect Packet Drop Address : " << current << std::endl;


                }
                mMTPacketLastSequenceNumber[MmtpHeader.packetId] = MmtpHeader.packetSequenceNumber;
                mMTPacketCount[MmtpHeader.packetId] += 1;
            }
            //continue;
        } else if (packetType == 0xFE) {
        } else if (packetType == 0xFF) {
        } else {
            std::cout << "unknownTLVPacketType: 0x" << packetType << std::endl;

            unknownTLVPacketType += 1;
        }
        if (tlvPacketTotalCount % 100 == 0) {
            std::cout << "\r" << "progress:" << current / 1024 << " kBytes.";
        }
        //std::cout << "TLV Packet tell:" << source.tellg() << std::endl;

        //std::cout << "TLV Packet payloadSize:" << current << std::endl;
        //std::cout << "Size:" << size << std::endl;

        //std::cout << "TLV Packet Type :" << packetType << std::endl;

        //std::cout << "TLV Packet Total:" << tlvPacketTotalCount << std::endl;
        //std::cout << "TLV Packet Resync Total:" << tlvPacketResyncCount << std::endl;

        // PayloadSize分次回シークしたい。
        // parse_packetTypeの応答値で配列をアレして
    }
    std::cout << "\n\n\n" << std::endl;
    std::cout << "TLV Packet Total:" << tlvPacketTotalCount << std::endl;
    std::cout << "TLV Packet Resync Total:" << tlvPacketResyncCount << std::endl;
    std::cout << "unknownTLVPacketType Total:" << unknownTLVPacketType << std::endl;

    for (int i = 0; i < 0xFF; i++) {
        if (tlvPacketCount[i] != 0) {
            std::cout << "TLV Packet Type 0x" << std::setw(2) << std::setfill('0') << std::hex << i << std::dec << ": " << tlvPacketCount[i] << " packets" << std::endl;
        }
    }
    std::cout << "\n\nMMT Packets"  << std::endl;

    for (int i = 0; i < 0xFFFF; i++) {
        if (mMTPacketCount[i] != 0) {
            std::cout << "0x" << std::setw(4) << std::setfill('0') << std::hex <<  i << "\tTotal = " << std::dec << mMTPacketCount[i] << " packets" <<
            "\tDrops = " << mMTPacketDropCounter[i] << " packets" << std::endl;

        }
    }
    return;
}

// 今はvoidで返しているが、ほしいデータはstructで応答できると良さそう（ペイロード区間などが応答出来れば切り出さなくても処理できると思う）
// 戻した際にオフセットを要求元で掛けてあげれば、算出できる
// ライブラリとしては元データのポインタと始点を渡してあげられるとペイロード切り出さなくて良いんじゃないのかなと思う

bool check_drop(struct _mmtpHeader Header, std::intmax_t* mMTPacketLastSequenceNumber, std::uintmax_t* mMTPacketDropCounter) {
    //mMTPacketDropCounter[Header.packetId];
    if (mMTPacketLastSequenceNumber[Header.packetId] + 1 == (Header.packetSequenceNumber)) {
        return false;
    }
    else if(mMTPacketLastSequenceNumber[Header.packetId] == (-1)) {
        return false; // 初期値の-1だと評価不能なため
    }
    else {
        return true;
    }

}

struct _iPv6Header  parse_ipv6Packet(struct _iPv6Header Header, char* packet, int offset) {
    // v6の固定長区間を何とかする
    Header.version =  (((unsigned char*)packet)[0 + offset] >> 4 )& 0xF;
    //std::cout << "IPv6 Packet Version:" << Header.version << std::endl;
    Header.payloadLength = (((((unsigned char*)packet)[offset + 4]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 5];
    //std::cout << "IPv6 Packet Payload length:" << Header.payloadLength << std::endl;
    Header.nextHeader = ((unsigned char*)packet)[offset + 6];
    //std::cout << "IPv6 Packet NextHeader:" << Header.nextHeader << std::endl; // (0x11)UDP
    
    return Header;
   

}

struct _compressedIpPacket parse_compressedIpPacket(struct _compressedIpPacket IpPacket,  char* packet, int offset) {
    IpPacket.contentId = ((((unsigned char*)packet)[offset + 0] & 0x1F) << 8) | ((unsigned char*)packet)[offset + 1];
    //std::cout << "ComppressedIp ContentId:" << IpPacket.contentId << std::endl;
    IpPacket.packetSequenceNumber = (((unsigned char*)packet)[offset + 1] ) & 0x0F;
    IpPacket.headerType = (((unsigned char*)packet)[offset + 2]) & 0xFF;
    if (IpPacket.headerType == 0x61) {
        return IpPacket;
    }
    else if (IpPacket.headerType == 0x60) {
        return IpPacket;
    }
    else {
        std::cout << "ComppressedIp not Supported headerType:" << IpPacket.headerType << std::endl;

        return IpPacket;
    }
    
}

struct _mmtpHeader parseMmtpHeader(char* packet, int offset) {
    _mmtpHeader MMTPHeader {};
    MMTPHeader.version = (((unsigned char*)packet)[offset + 0] >> 6) & 0xFF;
    // counterはPacketIDを区別しないでMMTP通しでの数字っぽい。
    MMTPHeader.packetCounterFlag = (((unsigned char*)packet)[offset + 0] >> 5) & 0x01;
    MMTPHeader.payloadType = (((unsigned char*)packet)[offset + 1] >> 2) & 0x1F; 
    MMTPHeader.packetId = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
    MMTPHeader.packetSequenceNumber = ((((unsigned char*)packet)[offset + 8] & 0xFF) << 24) | 
                                      ((((unsigned char*)packet)[offset + 9] & 0xFF) << 16) |
                                      ((((unsigned char*)packet)[offset + 10] & 0xFF) << 8) |
                                      ((unsigned char*)packet)[offset + 11];

    // structでヘッダーを応答してあげる

    return MMTPHeader;
}
// 効率的ではないが、可読性のため一部の関数ではペイロードを切り出してから対応するようにする
// 具体的には↑の応答形式が思いついてなかった頃に書いてた関数
// とはいうものの多分全体からこっからここまでって感じで切り出すって思想の方が分かりやすい気もする
char* getPayload(char* packet, int a, int size) {
    char* newPacket = new char[size];
    for (int i = 0; i < size ; i++) {
        newPacket[i] = packet[i + a];
    }
    return newPacket;
}

struct _udpHeader getUDPHeader(struct _udpHeader UDPHeader, char* packet, int offset) {
    UDPHeader.srcPort = (((((unsigned char*)packet)[offset + 0]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 1];
    UDPHeader.dstPort = (((((unsigned char*)packet)[offset + 2]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
    UDPHeader.dataLength = (((((unsigned char*)packet)[offset + 4]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 5];
    UDPHeader.checksum = (((((unsigned char*)packet)[offset + 6]) & 0xFF) << 8) | ((unsigned char*)packet)[offset + 7];
    return UDPHeader;
}

// v6のヘッダーから始まるデータ渡して可読な値にする
//char parse_ipv6_srcip(char* packet) {
//    //std::cout << "IPv6 Packet Src:" << ((unsigned char*)packet)[8] <<
//    //    ((unsigned char*)packet)[9] << 
//    //    ((unsigned char*)packet)[10] << 
//    //    ((unsigned char*)packet)[11] << 
//    //    ((unsigned char*)packet)[12] << 
//    //    ((unsigned char*)packet)[13] << 
//    //    ((unsigned char*)packet)[14] <<
//    //    ((unsigned char*)packet)[15] <<
//    //    ((unsigned char*)packet)[16] <<
//    //    ((unsigned char*)packet)[17] <<
//    //    ((unsigned char*)packet)[18] <<
//    //    ((unsigned char*)packet)[19] <<
//    //    ((unsigned char*)packet)[20] <<
//    //    ((unsigned char*)packet)[21] <<
//    //    ((unsigned char*)packet)[22] <<
//    //    ((unsigned char*)packet)[23] <<
//    //    std::endl; 
//}
void usage() {
    std::cout << "Usage: loas-tools [options] <input> \n";
    std::cout << "Options:\n";
    std::cout << "-D\tDecode mode(FakeWave to latm)\n";
    std::cout << "-F\tFake mode (latm to FakeWave)\n\n";
    std::cout << "--bitdepth\tSelecting WaveHeader blocksize (for Fake mode)\n\t8:\t8bit\n\t16:\t16bit\n\t24:\t24bit(default)\n";

    std::cout << "--overwrite\tIf it exists in the output destination, it will be overwritten\n";
    std::cout << "--exact\tOutputs the deviation correction information of the start point(This is vaild for matroska)\n";

    return;
}
