#pragma once
#include <cstdint>
#include "mac.h"

#define SUBTYPE_DEAUTH 0xc;

#pragma pack(push, 1)
struct radiotap {
    uint8_t it_version;     
    uint8_t it_pad;        
    uint16_t it_len;     
    uint32_t it_present; 

    enum presentFlag: uint32_t {
        Tsft = 0,
        Flags = 1,
        Rate = 2,
        Channel = 3,
        Fhss = 4,
        AntennaSignal = 5,
        AntennaNoise = 6,
        LockQuality = 7,
        TxAttenuation = 9,
        DbTxAttenuation = 9,
        DbmTxPower = 10,
        Antenna = 11,
        DbAntennaSignal = 12,
        DbAntennaNoise = 13,
        RxFlags = 14,
        TxFlags = 15,
        RtsRetries = 16,
        DataRetries = 17,
        XChannel = 18,
        Mcs = 19,
        AMpdu = 20,
        Vht = 21,
        Timestamp = 22,
        He = 23,
        HeMu = 24,
        HeMuOtherUser = 25,
        ZeroLenghPsdu = 26,
        LSig = 27,
        Tlv = 28,
        RadiotapNamespace = 29,
        VendorNamespace = 30,
        Ext = 31
    };

    radiotap() = default;
    uint8_t getVersion() const { this->it_version; }
    uint8_t getPad() const { this->it_pad; }
    uint16_t getLen() const { this->it_len; }
    presentFlag getPresent() const { this->it_present; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct Dot11 {
    uint8_t version:2;
    uint8_t type:2;
    uint8_t subtype:4;
    uint8_t flags;
    uint16_t duration;
    Mac addr1_;
    Mac addr2_;
    Mac addr3_;
    uint8_t frag:4;
    uint16_t seq:12;

    enum Type: uint8_t {
        MANAGEMENT_FRAMES       = 0,
        CONTROL_FRAMES          = 1, 
        DATA_FRAMES             = 2, 
        EXTENSION_FRAME         = 3 
    };

    enum Subtype: uint8_t {

        Association_request     = 0x0,
        Association_response    = 0x1,
        Reassociation_request   = 0x2,
        Reassociation_response  = 0x3,
        Probe_request           = 0x4,
        Probe_response          = 0x5,
        Timing_Advertisemant    = 0x6,
        Beacon                  = 0x8,
        ATIM                    = 0x9,
        Disassociation          = 0xa,
        Authentication          = 0xb,
        Deauthentication        = 0xc,
        Action                  = 0xd,
        Action_no_ack           = 0xe,

        Beamforming_report_poll = 0x14,
        VHT_NDP_Announcement    = 0x15,
        Control_frame_extension = 0x16,
        Control_wrapper         = 0x17,
        Block_ACK_request       = 0x18,
        Block_ACK               = 0x19,
        PS_Poll                 = 0x1a,
        Ready_To_Send           = 0x1b,
        Clear_To_Send           = 0x1c,
        ACK                     = 0x1d,
        CF_End                  = 0x1e,
        CF_End_CF_Ack           = 0x1f,

        Data                    = 0x20,
        Data_CF_Ack             = 0x21,
        Data_CF_Poll            = 0x22,
        Data_CF_Ack_CF_Poll     = 0x23,
        Null                    = 0x24,
        CF_Ack                  = 0x25,
        CF_Poll                 = 0x26,
        CF_Ack_CF_Poll          = 0x27,
        QoS_Data                = 0x28,
        QoS_Data_CF_Ack         = 0x29,
        QoS_Data_CF_Poll        = 0x2a,
        QoS_Data_CF_Ack_CF_Poll = 0x2b,
        QoS_Null                = 0x2c,
        QoS_CF_Poll             = 0x2e,
        QoS_CF_Ack_CF_Poll      = 0x2f,

        DMG_Beacon              = 0x30,
        S1G_Beacon              = 0x31
    };

    Dot11() = default;

    uint8_t getTypeSubtype() { return ((type << 4) or (subtype)); }
    uint8_t getType() { return type; }
    uint8_t getSubtype() { return subtype; }

    Mac getReceiverMac() const { return addr1_; }
    Mac getTargetMac() const { return addr2_; }
    Mac getBSSID() const { return addr3_; }
};
#pragma pack(pop)

#pragma pack(push, 1)
struct beaconHeader : Dot11Hdr {
    struct Fix {
        uint64_t timestamp;
        uint16_t beaconInterval;
        uint16_t capabilities;
    } fix;

    struct Tag {
        uint8_t identifier;
        uint8_t length;

        void* value() { return (uint8_t*)this + sizeof(Tag); }

        Tag* next() {
            uint8_t* res = (uint8_t*)this;
            res += sizeof(Tag) + this->length;
            
            return (Tag*)res;
        }
    };

    Tag* firstTag() {
        uint8_t* pointer = (uint8_t*)this;
        pointer += sizeof(beaconHeader);
        
        return (Tag*)pointer;
    }

	enum : uint8_t {
		TagSsidParameterSet = 0,
		TagSupportedRated = 1,
		TagDsParameterSet = 3,
		TagTrafficIndicationMap = 5,
		TagCountryInformation = 7,
		TagQbssLoadElement = 11,
		TagHtCapabilities = 45,
		TagRsnInformation = 48,
		TagHtInformation = 61,
		TagVendorSpecific = 221
	};

    struct TrafficIndicationMap : Tag {
        uint8_t DITMCount;
        uint8_t DITMPeriod;
        uint8_t bitmapControl;
        uint8_t partialVirtiualBitmap;
    };

    struct HtCapabilities : Tag {
        uint16_t capabilitiesInfo;
        uint8_t mpduParameters;
        uint8_t mcsSet[16];
        uint16_t extCapabilities;
        uint32_t txbfCapabilities;
        uint8_t aselCapabilities;
    };

    struct HtInformation : Tag {
        uint8_t primaryChannel;
        uint8_t htInformationSubset1;
        uint16_t htInformationSubset2;
        uint16_t htInformationSubset3;
        uint8_t basicMcsSet[16];
    };
};
#pragma pack(pop)