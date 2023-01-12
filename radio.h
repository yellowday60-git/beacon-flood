#pragma once
#include <cstdint>

#pragma pack(push,1)
struct RadioTapHdr
{
    uint8_t     revision;
    uint8_t     pad;
    uint16_t    hdr_len;
    uint32_t    present_flag;
};
#pragma pack(pop)