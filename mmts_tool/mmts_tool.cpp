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

    std::uintmax_t* iPv6MMTPacketCount = new std::uintmax_t[0xFFFF]{};
    std::uintmax_t* mMTPacketCount = new std::uintmax_t[0xFFFF]{};

    std::intmax_t* mMTPacketLastSequenceNumber = new std::intmax_t[0xFFFF]{};
    for (int i = 0; i < 0xFFFF; i++) {
        mMTPacketLastSequenceNumber[i] = -1;
    }
    
    std::uintmax_t* iPv6MMTPacketDropCounter = new std::uintmax_t[0xFFFF]{ 0 };
    std::uintmax_t* mMTPacketDropCounter = new std::uintmax_t[0xFFFF]{ 0 };

    std::uintmax_t* iPv6MMTPacketLastSequenceNumber = new std::uintmax_t[0xFFFF]{ 0 };
    std::uintmax_t* contextIdSequenceNumber = new std::uintmax_t[0xFFFF]{ 0 };

    std::intmax_t unknownTLVPacketType = 0;
    std::intmax_t nullTLVPacket = 0;

    // 多分Structかなんかで構造体でファイル情報渡してからParseした方が良さそうな気がする
    char* hBuf = new char[2000];
    std::filesystem::path Input = input;
    std::intmax_t size = file_size(Input);
    std::cout << "filesize: " << size << " bytes" << std::endl;
    std::ifstream source(Input, std::ios::in | std::ios::binary);
    if (!source) {
        std::cout << "Can not open source: " << Input;
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
        if (!(hBuf[0] == 0x7F)) {
            std::cout << "\rResync TLV Header: " << current << " bytes";
            source.seekg(current + 1);
            tlvPacketResyncCount++;
            current++;
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
        //parse_tlvPayloadtSize(hBuf);
        payloadSize = parse_tlvPayloadtSize(hBuf);

        //std::cout << "TLV Packet payloadSize2:" << payloadSize << std::endl;
        //source.read(hBuf, 4 + payloadSize);

        if (packetType == 0x2) {
            IPv6Header = parse_ipv6Packet(IPv6Header, hBuf, 4);

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

            if (check_drop(MmtpHeader, mMTPacketLastSequenceNumber, payloadSize) == true) {
                iPv6MMTPacketDropCounter[MmtpHeader.packetId] += 1;
                //std::cout << "PID: " << MmtpHeader.packetId << "Detect Packet Drop Address : " << current << std::endl;
            }
            iPv6MMTPacketLastSequenceNumber[MmtpHeader.packetId] = MmtpHeader.packetSequenceNumber;
            iPv6MMTPacketCount[MmtpHeader.packetId] += 1;

        }
        else if (packetType == 0x3) {
            compressedIpHeader = parse_compressedIpPacket(compressedIpHeader, hBuf, 4 + 0);


            if (compressedIpHeader.headerType == 0x61) {

                MmtpHeader = parseMmtpHeader(hBuf, 4 + 3);
                //std::cout << "PID: " << MmtpHeader.packetId << "  Detect versio2n : " << MmtpHeader.version << std::endl;

                if (check_drop(MmtpHeader, mMTPacketLastSequenceNumber, payloadSize) == true) {
                    mMTPacketDropCounter[MmtpHeader.packetId] += 1;
                    std::cout << "PID: 0x" << std::hex << MmtpHeader.packetId << std::dec << " Drop Address : " << current << std::endl;


                }
                mMTPacketLastSequenceNumber[MmtpHeader.packetId] = MmtpHeader.packetSequenceNumber;
                mMTPacketCount[MmtpHeader.packetId] += 1;
            }
            else if (compressedIpHeader.headerType == 0x60) {
                MmtpHeader = parseMmtpHeader(hBuf, 4 + 3 + 38 + 4);

                if (check_drop(MmtpHeader, mMTPacketLastSequenceNumber, payloadSize) == true) {
                    mMTPacketDropCounter[MmtpHeader.packetId] += 1;
                    std::cout << "PID: 0x" << MmtpHeader.packetId <<  " Drop Address : " << current << "bytes" << std::endl;


                }
                mMTPacketLastSequenceNumber[MmtpHeader.packetId] = MmtpHeader.packetSequenceNumber;
                mMTPacketCount[MmtpHeader.packetId] += 1;
            }
            else {
                std::cout << "unknowncompressedIpHeaderPacketType: 0x" << std::hex <<compressedIpHeader.headerType << std::dec << std::endl;

            }
            //continue;
        } else if (packetType == 0xFE) {
        } else if (packetType == 0xFF) {
        } else {
            std::cout << "unknownTLVPacketType: 0x" << packetType << std::endl;
            std::cout << "Resync" << std::endl;
            current++;
            unknownTLVPacketType += 1;
            continue;
        }
        current = current + 4; //たまたまSyncHeaderが生きてるだけの可能性を考慮してここで判定する
        current = current + payloadSize;

        if (tlvPacketTotalCount % 100 == 0) {
            std::cout <<  "progress:" << current / 1024  << " kBytes." << "\r";
        }

    }
    std::cout << "TLV Packet Total:" << tlvPacketTotalCount << std::endl;
    std::cout << "TLV Packet Resync Total:" << tlvPacketResyncCount << std::endl;
    std::cout << "TLV Null Packet Total:" << tlvPacketCount[0xFF] << "\n" << std::endl;
    std::cout << "TLV Unknown Packet Total:" << unknownTLVPacketType << "\n"  << std::endl;


    for (int i = 0; i < 0xFF; i++) {
        if (tlvPacketCount[i] != 0) {
            std::cout << "TLV Packet Type 0x" << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << i << std::nouppercase << std::dec << ": " << tlvPacketCount[i] << " packets" << std::endl;
        }
    }
    std::cout << "\nCompressed IP Header MMT Packets"  << std::endl;

    for (int i = 0; i < 0xFFFF; i++) {
        if (mMTPacketCount[i] != 0) {
            std::cout << "\tPacketId: 0x" << std::setw(4) << std::setfill('0') << std::uppercase << std::hex <<  i << "\tTotal = " << std::nouppercase << std::dec << mMTPacketCount[i] << " packets" <<
            "\tDrop = " << mMTPacketDropCounter[i] << " packets" << std::endl;

        }
    }
    return;
}

bool check_drop(struct _mmtpHeader Header, std::intmax_t* mMTPacketLastSequenceNumber, std::uintmax_t mMTPacketDropCounter) {
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
    MMTPHeader.version = (((unsigned char*)packet)[offset + 0] >> 6) & 0x3;
    MMTPHeader.packetCounterFlag = (((unsigned char*)packet)[offset + 0] >> 5) & 0x01;
    MMTPHeader.payloadType = (((unsigned char*)packet)[offset + 1] >> 2) & 0x1F; 
    MMTPHeader.packetId = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
    MMTPHeader.packetSequenceNumber = ((((unsigned char*)packet)[offset + 8] & 0xFF) << 24) | 
                                      ((((unsigned char*)packet)[offset + 9] & 0xFF) << 16) |
                                      ((((unsigned char*)packet)[offset + 10] & 0xFF) << 8) |
                                      ((unsigned char*)packet)[offset + 11];

    return MMTPHeader;
}
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


void usage() {
    std::cout << "Usage: mmts-tools [options] <input> \n";
    std::cout << "Options:\n";
    std::cout << "\n\n";
    return;
}
