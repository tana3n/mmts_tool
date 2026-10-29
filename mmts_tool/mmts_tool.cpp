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

    std::uintmax_t tlvPacketCount[0x100] = {};
    int tlvPacketTotalCount = 0;
    int tlvPacketResyncCount = 0;

    std::uintmax_t CIDCount[0x0FFF] = {};


    // 多分Structかなんかで構造体でファイル情報渡してからParseした方が良さそうな気がする
    char* hBuf = new char[5];
    char* pBuf = new char[50000];

    std::uintmax_t size = file_size(input);

    std::ifstream source(input, std::ios::in | std::ios::binary);
    if (!source) {
        std::cout << "Can not open source: " << input;
        return;
    }

    source.seekg(0);
    while (source.tellg() < size) {
        std::uintmax_t  current = source.tellg();
        source.read(hBuf, 5);
        if (!is_syncHeader(hBuf[0])) {
            source.seekg(current + 1);
            tlvPacketResyncCount++;
            continue;
        }
        int packetType = parse_packetType(hBuf);
        //std::cout << "TLV Packet payloadSize:" << hBuf[1] << std::endl;

        if (packetType <= 0xFF) {

            tlvPacketCount[packetType]++;
            tlvPacketTotalCount++;
        }
        else if (packetType == 0xFF) {

            tlvPacketCount[packetType]++;
            tlvPacketTotalCount++;
        }
        else {
            //std::cout << "TLV Packet packetType:" << packetType << std::endl;
            source.seekg(current + 1);
            tlvPacketResyncCount++;
            continue;
        }
        //parse_tlvPayloadtSize(hBuf);
        std::uintmax_t payloadSize = parse_tlvPayloadtSize(hBuf);
        
        // TLV区間を読み終わったのでシーク
        current = current + 4;
        source.seekg(current);

        // MMT / NTPをここで何とかする
        if (payloadSize <= 50000) {
            source.read(pBuf, payloadSize);
        }
        else
        {
            std::cout << "TLV Payload buffer overflow : " << payloadSize << std::endl;
            std::cout << "Current Address : " << current << std::endl;

            break;
        }
        
        if (packetType == 0x2) {
            int v6Payload = parse_ipv6Packet(pBuf);

            // UDPHeaderを何とかしてPayloadを触れるようにする
            //char* udpPacket = getPayload(pBuf, 40, v6Payload); // 256+64 = 320bit
            struct _udpHeader UDPHeader = getUDPHeader(pBuf, 40);
            int UDPPayloadEnd = UDPHeader.dataLength + 40 + 8;
            parseMmtpHeader(pBuf, 48);
        }
        else if (packetType == 0x3) {
            //parse_compressedIpPacket(pBuf);
            continue;
        }

        current = current + payloadSize;
        source.seekg(current);
        //std::cout << "TLV Packet payloadSize:" << payloadSize << std::endl;
        //std::cout << "TLV Packet Type :" << packetType << std::endl;

        //std::cout << "TLV Packet Total:" << tlvPacketTotalCount << std::endl;
        //std::cout << "TLV Packet Resync Total:" << tlvPacketResyncCount << std::endl;

        // PayloadSize分次回シークしたい。
        // parse_packetTypeの応答値で配列をアレして
    }
    std::cout << "TLV Packet Total:" << tlvPacketTotalCount << std::endl;
    std::cout << "TLV Packet Resync Total:" << tlvPacketResyncCount << std::endl;

    for (int i = 0; i < 0xFF; i++) {
        if (tlvPacketCount[i] != 0) {
            std::cout << "TLV Packet Type 0x" << i << ": " << tlvPacketCount[i] << " packets" << std::endl;
        }
    }
    /*
    IP Packet
    NTP+MMT?
    CID 12b
    Seq 4b(確かに連続してる）
    CID Header Type 0x61（v6の圧縮ヘッダーなし）
    ペイロード

    */
    return;
}

// 今はvoidで返しているが、ほしいデータはstructで応答できると良さそう（ペイロード区間などが応答出来れば切り出さなくても処理できると思う）
// 戻した際にオフセットを要求元で掛けてあげれば、算出できる
// ライブラリとしては元データのポインタと始点を渡してあげられるとペイロード切り出さなくて良いんじゃないのかなと思う


int parse_ipv6Packet(char* packet) {

    // v6の固定長区間を何とかする
    std::uintmax_t Version =  (((unsigned char*)packet)[0] >> 4 )& 0xFF;
    std::cout << "IPv6 Packet Version:" << Version << std::endl;
    int v6Payload = (((((unsigned char*)packet)[4]) & 0x1F) << 8) | ((unsigned char*)packet)[5];
    std::cout << "IPv6 Packet Payload length:" << v6Payload << std::endl;
    int NextHeader = ((unsigned char*)packet)[6];
    std::cout << "IPv6 Packet NextHeader:" << NextHeader << std::endl; // (0x11)UDP
    
    return v6Payload;
   

}

void parseMmtpHeader(char* packet, int offset) {
    int version = (((unsigned char*)packet)[offset = 0] >> 6) & 0xFF;
    return;
}
// 効率的ではないが、可読性のため一部の関数ではペイロードを切り出してから対応するようにする
// 具体的には↑の応答形式が思いついてなかった頃に書いてた関数
char* getPayload(char* packet, int a, int size) {
    char* newPacket = new char[size];
    for (int i = 0; i < size ; i++) {
        newPacket[i] = packet[i + a];
    }
    return newPacket;
}

struct _udpHeader getUDPHeader(char* packet, int offset) {
    struct _udpHeader UDPHeader {};
    UDPHeader.srcPort = (((((unsigned char*)packet)[offset + 0]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 1];
    UDPHeader.dstPort = (((((unsigned char*)packet)[offset + 2]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 3];
    UDPHeader.dataLength = (((((unsigned char*)packet)[offset + 4]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 5];
    UDPHeader.checksum = (((((unsigned char*)packet)[offset + 6]) & 0x1F) << 8) | ((unsigned char*)packet)[offset + 7];
    return UDPHeader;
}

// v6のヘッダーから始まるデータ渡して可読な値にする
char parse_ipv6_srcip(char* packet) {
    //std::cout << "IPv6 Packet Src:" << ((unsigned char*)packet)[8] <<
    //    ((unsigned char*)packet)[9] << 
    //    ((unsigned char*)packet)[10] << 
    //    ((unsigned char*)packet)[11] << 
    //    ((unsigned char*)packet)[12] << 
    //    ((unsigned char*)packet)[13] << 
    //    ((unsigned char*)packet)[14] <<
    //    ((unsigned char*)packet)[15] <<
    //    ((unsigned char*)packet)[16] <<
    //    ((unsigned char*)packet)[17] <<
    //    ((unsigned char*)packet)[18] <<
    //    ((unsigned char*)packet)[19] <<
    //    ((unsigned char*)packet)[20] <<
    //    ((unsigned char*)packet)[21] <<
    //    ((unsigned char*)packet)[22] <<
    //    ((unsigned char*)packet)[23] <<
    //    std::endl; 
}
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
