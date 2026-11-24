#include <iostream>
#include <filesystem>
#include <windows.h>

// バッファの始点から次のTLVパケットの手前までデバッグ用に出力する
// dump_hex(hBuf, payloadSize);みたいに渡すと良い
void dump_hex(char* packet, int length) {
    for (int i = 0; i < length + 4; i++) {
        int j = ((unsigned char*)packet)[i] & 0xFF;
        if (i % 16 == 0) {
            std::cout << std::endl;
        }
        else {
            std::cout << " ";
        }
        std::cout << std::setw(2) << std::setfill('0') << std::hex << j << std::dec;

    }
    std::cout << std::endl;

};

void dump_hex(char* packet, int offset, int length) {
    for (int i = offset; i < length + offset; i++) {
        int j = ((unsigned char*)packet)[i] & 0xFF;
        if (i-offset % 16 == 0) {
            std::cout << std::endl;
        }
        else {
            std::cout << " ";
        }
        std::cout << std::setw(2) << std::setfill('0') << std::hex << j << std::dec;

    }
    std::cout << std::endl;

};

std::string print_hex_to_utf8(char* packet, int offset,  int length){
    char* DescriptorName = new char[length];
    for (int i = 0; i < length; i++) {
        DescriptorName[i] = (((unsigned char*)packet)[offset + i]) & 0xFF;
    }
    // ref: http://yukakumumu.blog.fc2.com/blog-entry-38.html

    std::string out = DescriptorName;

    int sizeU = MultiByteToWideChar(CP_UTF8, 0, out.c_str(), -1, NULL, 0);
    wchar_t* Unicode = new wchar_t[sizeU];
    MultiByteToWideChar(CP_UTF8, 0, out.c_str(), -1, Unicode, sizeU);

    int dest_size = WideCharToMultiByte(932, 0, Unicode, -1, NULL, 0, NULL, NULL);
    char* CP932 = new char[dest_size];
    WideCharToMultiByte(932, 0, Unicode, -1, CP932, dest_size, NULL, NULL);

    std::string out2 = CP932;
    std::cout << "[MH-SDT]: " << out2.c_str() << std::endl;

    delete[] DescriptorName;
    delete[] CP932;
    delete[] Unicode;
    return out2;
}