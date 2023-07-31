/*
*   copyright delcaration
*/

/*
* Homa Header
* https://github.com/PlatformLab/HomaModule
*/
#include "netdissect.h"


#ifndef HOMA_H
#define HOMA_H

#define HOMA_MIN_PKT_LENGTH 26
#define HOMA_MAX_HEADER 90
#define HOMA_MAX_PRIORITYIES 8
#define HOMA_NUM_PEER_UNACKED_IDS 5
#define RPCID_MASK 0x0000000000000001

/*
*  The common part of header for all Homa Packet types
*  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Source Port         |       Destination Port         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Unused                                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Unused                                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |     Offset   |      Type     |        Unused                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Checksum           |        Unused                  |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             RPCID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         PRCID(continue)                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct hm_common_hdr{
    nd_uint16_t hmch_sport;
    nd_uint16_t hmch_dport;
    nd_uint32_t hmch_unused1;
    nd_uint32_t hmch_unused2;
    nd_uint8_t hmch_doff; /* higher order 4 bits represent the size of DATA header in 32bits word(only used for DATA packet), lower order bits not used*/
    nd_uint8_t hmch_type; /*type of Homa pakcet */
    nd_uint16_t hmch_unused3;
    nd_uint16_t hmch_checksum; /*not used by Homa actually*/
    nd_uint16_t hmch_unused4;
    nd_uint64_t hmch_rpcid;
};
#define HOMA_COMMON_HDR_LEN 28

/**
 * The ACK portion, this can be both part of DATA packet segment or an indenpendent ACK packet
 *  0                   1                   2                   3 
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             RPCID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         PRCID(continue)                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Client Port         |       Server Port              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct hm_ack{
    nd_uint64_t hmack_rpcid; /* client side rpc id, 0 means this ack is invalid*/
    nd_uint16_t hmack_clientport;
    nd_uint16_t hmack_serverport;
};
#define HOMA_ACK_LEN 12


/*
*  The Data Packet header (exclude the common header part)
*  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Message Length                         |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Transmission Offset                     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |           Cutoff Version     |   Retran Flag |    Padding     |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct hm_data_hdr{
    struct hm_common_hdr common_header;
    nd_uint32_t hmdata_message_len; /* in bytes*/
    nd_uint32_t hmdata_incmoing; /*the intend-to-transmit offset within message*/
    nd_uint16_t hmdata_cutoff; /* the most recent cut off version from receiver, 0 means no CUTOFF packet is received by sender*/
    nd_uint8_t hmdata_retranflag; 
    nd_uint8_t pad;
};
#define HOMA_DATA_HDR_LEN 40

/**
 * Data Packet Segemnt header
 * Data Packet is consist of a Data header and several(at least one) Data segments
 * Each Data segemnt also contains a subheader
 *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Offset                                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                       Payload Length                          |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                             RPCID                             |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                         PRCID(continue)                       |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |          Client Port         |       Server Port              |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
struct hm_data_seg{
    nd_uint32_t hmseg_offset;
    nd_uint32_t hmseg_length; /*in bytes*/
    struct hm_ack gmseg_ack;
};
#define HOMA_DATA_SEG_HDR_LEN 20

/**
 * GRANT Packet header(exclude the common header part)  
 * GRANT Packet sent by receiver to authorise sender the transmission of additional bytes of message
 * 
  *  0                   1                   2                   3   
 *  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |                        Offset                                 |
 * +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 * |   Priority   |
 * +-+-+-+-+-+-+-+-+
*/
struct hm_grant_hdr{
    struct hm_common_hdr common_header;
    nd_uint32_t hmgrant_offset; /*in bytes*/
    nd_uint8_t hmgrant_priority; /* the priority level for future Data Packet*/
};
#define HOMA_GRANT_HDR_LEN 33

/**
 * RESEND Packet header(exclude common part)
 * RESEND Packet is sent by receiver when it believe some bytes of message have lost
 * 
*/
struct hm_resend_hdr{
    struct hm_common_hdr common_header;
    nd_uint32_t hmre_offset; /*offset within the message of the first byte if data should be retransmitted*/
    nd_uint32_t hmre_length; /* in bytes, length of retransmission data*/
    nd_uint8_t hmre_priority;
};
#define HOMA_RESEND_HDR_LEN 37


/**
 * UKNOWN Packet header
 * Sent by clinet or server when it received a packet with an unknown RPC ID
*/
struct hm_unknown_hdr{
    struct hm_common_hdr common_header;
};
#define HOMA_UNKNOWN_HDR_LEN 28

/**
 * BUSY Packet header
 * Sent by sender to indicate the delat of retransmission
*/
struct hm_busy_hdr{
    struct hm_common_hdr common_header;
};
#define HOMA_BUSY_HDR_LEN 28

/**
 * FREEZE Packet header
 * This type of packet is only used for debugging, tell the recipient to freeze the timetrace
*/
struct hm_freeze_hdr{
    struct hm_common_hdr common_header;
};
#define HOMA_FREEZE_HDR_LEN 28

/**
 * NEED_ACK Packet header
 * Sent by server to reqest client to ack the recipent of response message explicitly
*/
struct hm_need_ack_hdr{
    struct hm_common_hdr common_header;
};

/**
 * ACK Packet header
 * Sent by client to acknowledge the recipient of response for a set of RPCs, such that server can clean the state
*/
struct hm_ack_hdr{
    struct hm_common_hdr common_header;
    nd_uint16_t hmack_acknum; /*number of valid acks*/
    struct hm_ack acks[HOMA_NUM_PEER_UNACKED_IDS];
};



/**
 * CUTOFFS Packet header(exclude the common header)
 * CUTOFFS packet tell the recipent how to allocate priority for unscheduled bytes to the sender
 * 
*/
struct hm_cutoffs_hdr{
    struct hm_common_hdr common_header;
    nd_uint32_t hmcut_cutoffs[HOMA_MAX_PRIORITYIES];
    nd_uint16_t hmcut_version;
};
#define HOMA_CUTOFFS_LEN 62














/*
* Define Homa packets(Homa header + data payload) types
*/
#ifndef HOMA_DATA
#define HOMA_DATA 0x10
#endif 
#ifndef HOMA_GRANT
#define HOMA_GRANT 0x11
#endif
#ifndef HOMA_RESEND
#define HOMA_RESEND 0x12
#endif
#ifndef HOMA_UNKNOWN
#define HOMA_UNKONWN 0x13
#endif
#ifndef HOMA_BUSY
#define HOMA_BUSY 0x14
#endif
#ifndef HOMA_CUTOFFS
#define HOMA_CUTOFFS 0x15
#endif
#ifndef HOMA_FREEZE
#define HOMA_FREEZE 0x16
#endif
#ifndef HOMA_NEED_ACK
#define HOMA_NEED_ACK 0x17
#endif
#ifndef HOMA_ACK
#define HOMA_ACK 0x18
#endif
#ifndef HOMA_BOGUS
#define HOMA_BOGUS 0x19 /*This is still not defined*/
#endif


#endif /*!HOMA_H*/