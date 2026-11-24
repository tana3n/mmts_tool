#pragma once
void dump_hex(char* packet, int length);
void dump_hex(char* packet, int offset, int length);
std::string print_hex_to_utf8(char* packet, int offset, int length);