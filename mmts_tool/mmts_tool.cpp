#include <iostream>
#include <fstream>
#include <bitset>
#include <string>
#include <filesystem>
#include <regex>

#include "tlv.hpp"
#include "mmts_tool.h"
#include "mmtp.h"
#include "common.h"
using namespace std::filesystem;

int main(int argc, char* argv[])
{
    //std::cout << "mmts_tools Version " << Version << "\n\n";


    if (!argv[1]) {
        std::cout << "[Error]No Input\n\n";
        //usage();

        return 0;
    }
    //cli_parser(argv, argc);
    std::cout << argv[1] << "\n\n";
    struct _args Args {};
    Args.inputFileName = argv[1];
    //Args.outputFileName = "D:\output.mmts";
    Args.selectMode = false;
    //Args.selectedTLVType = 0xFE;
    //Args.outputFileName = std::to_string(argv[1]) ++ .selected.mmts
    //};
    parse(Args);
    return 0;
}

void parse(struct _args args)
{ 
    std::uintmax_t* tlvPacketCount = new std::uintmax_t[0x100]{};
    int tlvPacketTotalCount = 0;
    int tlvPacketResyncCount = 0;

    _MmtPacketIdInformation* mMTPacketsInfo = new _MmtPacketIdInformation[0xFFFF]{};
    _MmtPacketIdInformation* v6mMTPacketsInfo = new _MmtPacketIdInformation[0xFFFF]{};


    std::uintmax_t* contextIdSequenceNumber = new std::uintmax_t[0xFFFF]{ 0 };

    std::intmax_t unknownTLVPacketType = 0;
    std::intmax_t nullTLVPacket = 0;

    // 多分Structかなんかで構造体でファイル情報渡してからParseした方が良さそうな気がする
    char* hBuf = new char[5000];
    char* input = args.inputFileName;
    std::filesystem::path Input = input;
    //std::filesystem::path Output = args.outputFileName;

    std::intmax_t size = file_size(Input);
    std::ifstream source(Input, std::ios::in | std::ios::binary);
    if (!source) {
        std::cout << "Can not open source: " << Input;
        return;
    }
     //std::ofstream dest(Output, std::ios::out | std::ios::binary | std::ios::trunc);
     //   if (!dest) {
     //       std::cout << "Can not open output: " << Output;
     //       return;
     //   }
    int packetType = 0xFD;
    std::uintmax_t payloadSize = 0;
    std::intmax_t  current = source.tellg();
    int UDPPayloadEnd = 0;

    struct _iPv6Header IPv6Header {};
    struct _udpHeader UDPHeader {};
    struct _mmtpHeader MmtpHeader {};
    struct _mmtpExtensionHeader MmtpExtensionHeader {};

    struct _compressedIpPacket compressedIpHeader {};

    while (current < size) {
        source.seekg(current);
        // 終端のバッファ処理
        if (size - current >= 5000) {
            source.read(hBuf, 5000);
        }
        else {
            source.read(hBuf, size - current);
        }
        if (!(hBuf[0] == 0x7F)) {
            std::cout << "\rResync TLV Header: " << current << " bytes" << std::endl;
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
        payloadSize = parse_tlvPayloadtSize(hBuf);
        if (payloadSize >= 5000) {
            std::cout << "TLV Payload Size is overflow hBuf" << payloadSize << std::endl;
        }
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

            if (check_drop(MmtpHeader, v6mMTPacketsInfo) == true) {
                v6mMTPacketsInfo[MmtpHeader.packetId].dropTotal += 1;
            }
            v6mMTPacketsInfo[MmtpHeader.packetId].lastSequenceNumber = MmtpHeader.packetSequenceNumber;
            v6mMTPacketsInfo[MmtpHeader.packetId].total += 1;

        }
        else if (packetType == 0x3) {
            compressedIpHeader = parse_compressedIpPacket(compressedIpHeader, hBuf, 4 + 0);

            int offset;
            if (compressedIpHeader.headerType == 0x61) {
                offset = 4 + 3;
            }
            else if (compressedIpHeader.headerType == 0x60) {
                //std::cout << "compressedIpHeader.headerType: 0x" << std::hex << compressedIpHeader.headerType << std::dec << std::endl;
                // 256 + 48
                offset = 4 + 3 + 38 + 4;
            }
            else {
                std::cout << "unknown compressedIpHeader PacketType: 0x" << std::hex << compressedIpHeader.headerType << std::dec << std::endl;
                continue;
            }
            if (compressedIpHeader.headerType == 0x60 || compressedIpHeader.headerType == 0x61 ) {
                MmtpHeader = parseMmtpHeader(hBuf, offset);
                int offset2 = 12;
                if (MmtpHeader.packetCounterFlag) {
                    offset2 = offset2 + 4;
                }
                if (MmtpHeader.extensionHeaderFlag) {
                    offset2 = offset2 + 4;
                    MmtpExtensionHeader = parseMmtpExtensionHeader(hBuf, offset + offset2);
                    if (check_scrambling(MmtpExtensionHeader)) {
                        mMTPacketsInfo[MmtpHeader.packetId].scramblingTotal += 1;
                    }
                    offset2 = offset2 + MmtpHeader.extensionHeaderLength;

                }
               
                if (check_drop(MmtpHeader, mMTPacketsInfo) == true) {
                    mMTPacketsInfo[MmtpHeader.packetId].dropTotal += 1;

                    std::cout << "PID: 0x" << std::hex << MmtpHeader.packetId << std::dec << " Drop : " << current << " bytes" << std::endl;
                }

                mMTPacketsInfo[MmtpHeader.packetId].lastSequenceNumber = MmtpHeader.packetSequenceNumber;
                mMTPacketsInfo[MmtpHeader.packetId].total += 1;

                //std::cout << "payload offset: " << offset + offset2 << std::endl;

                if (MmtpHeader.payloadType == 0x0002) {

                    _signaling_message MMTPSignalingMessage{};
                    MMTPSignalingMessage = parseMmtpMessages(hBuf, offset + offset2);

                    if ((!MMTPSignalingMessage.aggregation_flag) )  {
                        // offsetに+2
                        if (MmtpHeader.packetId == 0x0000) {
                            _pa_message A =  parsePAMessage(hBuf, offset + offset2 + 2);
                            if (A.number_of_tables == 0) {
                                // 0x00の場合は1つだけみたいな
                                // offset + offset2 + MmtpHeader.extensionHeaderLength + 2 に +8することになりそう
            
                                if (check_single_pa_message_type(hBuf, offset + offset2  + 2 + 8) == 0x80) {
                                    int a = parse_plt(hBuf, offset + offset2 + 2 + 8);
                                    std::cout << "[PA Message] MMT General Location Info: 0x" << std::hex << a << std::dec << std::endl;

                                }
                                else {
                                    int i = hBuf[offset + offset2 + 2 + 8];
                                    std::cout << "PA Message table ID: 0x" << std::hex << i << std::dec << std::endl;

                                }
                            }
                        }
                        else if ((MmtpHeader.packetId == 0x8004)) {
                            _m2_section_message _m2_section_message = parse_m2_section(hBuf, offset + offset2 + 2);
                            std::cout << "_m2_section_message:" << _m2_section_message.message_id << std::endl;
                            std::cout << "_m2_section_message.table_id:" << _m2_section_message.table_id << std::endl;
                            // 自局のSDTだけまずはみれるようにしたい。
                            int offset3 = offset + offset2 + 2 + 13;
                            parse_mh_sdt(hBuf, offset3);
                        }
                    }
                    else {
                        std::cout << "fragment_counter: 0x" << std::hex << MMTPSignalingMessage.fragment_counter << std::dec << std::endl;

                    }
                }

            }
            
        } else if (packetType == 0xFE) {
            if (hBuf[4] == 0x40) { // TLV-NIT
                std::cout << " TLV-NIT TLV PacketType: 0x" << packetType << "\n" << std::endl;
                parse_TlvNIT(hBuf, 4);
            } else             if (hBuf[4] == 0x41) { // TLV-NIT
                std::cout << " TLV-NIT TLV PacketType: 0x" << packetType << "\n" << std::endl;
                //parse_TlvNIT(hBuf, 4);
            }
            else if (hBuf[4] == 0xFE) { //AMT
                std::cout << "AMT TLV PacketType: 0x" << packetType << "\n" << std::endl;

            }

        } else if (packetType == 0xFF) { // NULLパケットのサイズを計算してみてもいいかも
        } else {
            std::cout << "unknown TLV PacketType: 0x" << packetType << " try resync" << std::endl;
            current++;
            unknownTLVPacketType += 1;
            continue;
        }


        current = current + 4; //たまたまSyncHeaderが生きてるだけの可能性を考慮してここで判定する
        current = current + payloadSize;
        //if (packetType == args.selectedTLVType) {
        //    // hbufをget
        //    dest.write(hBuf, payloadSize + 4);
        //    args.outputSize = args.outputSize + payloadSize + 4;
        //    std::cout << "debug progress:" << current  << " / " << size  << " / " << payloadSize <<" = " << args.outputSize<<   std::endl;

        //}
        if (tlvPacketTotalCount % 10000 == 0) {
            std::cout <<  "progress:" << current   << " / " << size  << " Bytes." << "\r";
        }

    }
    std::cout << "progress:" << current  << " / " << size  << " Bytes." << std::endl;
    std::cout << "\nTLV Packet Total:" << tlvPacketTotalCount << std::endl;
    std::cout << "TLV Null Packet Total:" << tlvPacketCount[0xFF] << std::endl;
    std::cout << "TLV Unknown Packet Total:" << unknownTLVPacketType << "\n"  << std::endl;
    std::cout << "TLV Resync Total:" << tlvPacketResyncCount << "\n" << std::endl;


    for (int i = 0; i < 0xFF; i++) {
        if (tlvPacketCount[i] != 0) {
            std::cout << "TLV Packet Type 0x" << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << i << std::nouppercase << std::dec << ": " << tlvPacketCount[i] << " packets" << std::endl;
        }
    }
    std::cout << "\nIPv6 Header MMT Packets" << std::endl;

    for (int i = 0; i < 0xFFFF; i++) {
        if (v6mMTPacketsInfo[i].total != 0) {
            std::cout << "\tPacketId: 0x" << std::setw(4) << std::setfill('0') << std::uppercase << std::hex << i << "\tTotal = " << std::nouppercase << std::dec << v6mMTPacketsInfo[i].total << " packets" <<
                "\tDrop = " << v6mMTPacketsInfo[i].dropTotal <<
                "\tScramble = " << v6mMTPacketsInfo[i].scramblingTotal << std::endl;

        }
    }
    // 本
    std::cout << "\nCompressed IP Header MMT Packets"  << std::endl;

    for (int i = 0; i < 0xFFFF; i++) {
        if (mMTPacketsInfo[i].total != 0) {
            std::cout << "\tPacketId: 0x" << std::setw(4) << std::setfill('0') << std::uppercase << std::hex <<  i << "\tTotal = " << std::nouppercase << std::dec << mMTPacketsInfo[i].total << " packets" <<
            "\tDrop = " << mMTPacketsInfo[i].dropTotal  <<
            "\tScramble = " << mMTPacketsInfo[i].scramblingTotal << std::endl;

        }
    }
    // 本当は諸々解放する必要あり
    return;
}

bool check_drop(struct _mmtpHeader Header, struct _MmtPacketIdInformation* mmtpPacketsInfo) {
    if (mmtpPacketsInfo[Header.packetId].lastSequenceNumber + 1 == (Header.packetSequenceNumber)) {
        return false;
    }
    else if(mmtpPacketsInfo[Header.packetId].lastSequenceNumber == (-1)) {
        return false; // 初期値の-1だと評価不能なため
    }
    else {
        return true;
    }

}

bool check_scrambling(struct _mmtpExtensionHeader Header) {
    if (Header.mmtScramblingControl == 0) {
        return false;
    }
    else if (Header.mmtScramblingControl == 2 || Header.mmtScramblingControl == 3 ) {
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
// B32よりB60の6.4章とか見た方が良いと思う
struct _mmtpHeader parseMmtpHeader(char* packet, int offset) {
    _mmtpHeader MMTPHeader {};
    int offset2 = 0;
    MMTPHeader.version = (((unsigned char*)packet)[offset + 0] >> 6) & 0x3;
    MMTPHeader.packetCounterFlag = (((unsigned char*)packet)[offset + 0] >> 5) & 0x01;
    MMTPHeader.extensionHeaderFlag = (((unsigned char*)packet)[offset + 0] >> 1) & 0x01;
    MMTPHeader.payloadType = (((unsigned char*)packet)[offset + 1]) & 0x1F; 
    MMTPHeader.packetId = ((((unsigned char*)packet)[offset + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 3];
    MMTPHeader.packetSequenceNumber = ((((unsigned char*)packet)[offset + 8] & 0xFF) << 24) | 
                                      ((((unsigned char*)packet)[offset + 9] & 0xFF) << 16) |
                                      ((((unsigned char*)packet)[offset + 10] & 0xFF) << 8) |
                                      ((unsigned char*)packet)[offset + 11];
    if (MMTPHeader.packetCounterFlag == true) {
        offset2 += 8;
    }

    if (MMTPHeader.extensionHeaderFlag == true) {
        MMTPHeader.extensionHeaderType = ((((unsigned char*)packet)[offset + offset2 + 12] & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 13];
        MMTPHeader.extensionHeaderLength = ((((unsigned char*)packet)[offset + offset2 + 14] & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 15];
    }

    return MMTPHeader;
}
// HeaderってかいてあるけどMMTPPacketのExtensionHeaderTypeとかは関係ない。
struct _mmtpExtensionHeader parseMmtpExtensionHeader(char* packet, int offset) {
    _mmtpExtensionHeader MMTPExtensionHeader{};
    MMTPExtensionHeader.headerType = ((((unsigned char*)packet)[offset] & 0x7F) << 8) | ((unsigned char*)packet)[offset + 1];
    if (MMTPExtensionHeader.headerType == 0x0001) {
        MMTPExtensionHeader.mmtScramblingControl = (((unsigned char*)packet)[offset + 4] >> 3) & 0x3;
    }
    else
    {
        std::cout << "MMTPExtensionHeader.headerType:  " << MMTPExtensionHeader.headerType << std::endl;

    }
    return MMTPExtensionHeader;
}

struct _mmtp_payload parseMmtpPayload(char* packet, int offset, int payloadType) {
    if (payloadType == 0x00) {

    }
};
// 事実上Signaling Message(payload_type == 0x02)専用と化してる
struct _signaling_message parseMmtpMessages(char* packet, int offset) {
    _signaling_message MMTPSignalingMessage{};
    MMTPSignalingMessage.fragmentation_indicator = (((unsigned char*)packet)[offset + 0] >> 6) & 0x3;
    MMTPSignalingMessage.length_extension_flag = (((unsigned char*)packet)[offset + 0] >> 1) & 0x1;
    MMTPSignalingMessage.aggregation_flag = (((unsigned char*)packet)[offset + 0]) & 0x1;
    MMTPSignalingMessage.fragment_counter = (((unsigned char*)packet)[offset + 1]) & 0xFF;

    if (!MMTPSignalingMessage.aggregation_flag) {
    }
    else {
        std::cout << "aggregation_flag is true " << std::endl;
        //        if (!MMTPSignalingMessage.fragmentation_indicator)

    }
    //std::cout << "fragmentation_indicator is " << MMTPSignalingMessage.fragmentation_indicator << std::endl;

    //std::cout << "MMTPSignalingMessage.fragmentation_indicator: 0x" << MMTPSignalingMessage.fragmentation_indicator << std::endl;
    //std::cout << "MMTPSignalingMessage.length_extension_flag: 0x" << MMTPSignalingMessage.length_extension_flag << std::endl;
    //std::cout << "MMTPSignalingMessage.fragment_counter: 0x" << MMTPSignalingMessage.fragment_counter << std::endl;

    return MMTPSignalingMessage;
};

struct _pa_message parsePAMessage(char* packet, int offset) {
    _pa_message PAMessage{};
    PAMessage.message_id = ((((unsigned char*)packet)[offset + 0] & 0xFF) << 8) | ((unsigned char*)packet)[offset + 1];
    PAMessage.version = (((unsigned char*)packet)[offset + 2]) & 0xFF;
    PAMessage.length = ((((unsigned char*)packet)[offset + 3] & 0xFF) << 24) |
        ((((unsigned char*)packet)[offset + 4] & 0xFF) << 16) |
        ((((unsigned char*)packet)[offset + 5] & 0xFF) << 8) |
        ((unsigned char*)packet)[offset + 6] & 0xFF;
    PAMessage.number_of_tables = (((unsigned char*)packet)[offset + 7]) & 0xFF;
    //std::cout << std::setw(4) << std::setfill('0') << std::uppercase << std::hex << "PAMessage of message_id  0x" << PAMessage.message_id << std::endl;
    //std::cout << "PAMessage of version  0x" << PAMessage.version << std::endl;
    //std::cout << "PAMessage of length  0x" << PAMessage.length << std::endl;
    //std::cout << "PAMessage of number_of_tables  0x" << PAMessage.number_of_tables << std::nouppercase << std::dec << std::endl;

    int offset2 = 8;
    for (int i = 0; i < PAMessage.number_of_tables; i++) {
        PAMessage.pa_table[i].table_id = (((unsigned char*)packet)[offset + offset2]); // PA MessageだったらMPT/PLT/LCTしかあり得ないはず(0x11~1Fと80/81) //STD-B60 Table4-8
        PAMessage.pa_table[i].table_version = (((unsigned char*)packet)[offset + offset2 + 1]);
        PAMessage.pa_table[i].table_length = ((((unsigned char*)packet)[offset + offset2 + 2] & 0xFF) << 8) | ((unsigned char*)packet)[offset + offset2 + 3];
        offset2 = offset2 + 4;
        std::cout << "PAMessage of table  0x" << std::setw(2) << std::setfill('0') << std::uppercase << std::hex << PAMessage.pa_table[i].table_id << std::endl;

    }
    //for (int i = 0; i < PAMessage.number_of_tables; i++) {
    //    // parse_pa_table(packet, offset + offset2);
    //    //
    //}
    return PAMessage;
};

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
    std::cout << "Usage: mmts_tools [options] <input> \n";
    std::cout << "Options:\n";
    std::cout << "\n\n";
    return;
}

