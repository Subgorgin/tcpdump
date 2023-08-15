/*
Copyright declaration to be declared
*/

/* \summary: Homa Printer*/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef HAVE_NET_IF_H
/*
 * Include diag-control.h before <net/if.h>, which too defines a macro
 * named ND_UNREACHABLE.
 */
#include "diag-control.h"
#include <net/if.h>
#endif

#include "netdissect-stdinc.h"

/* This Marcos is defined so that we can jump back to main method of tcpdump.c if the packet is truncated(i.e. the packe is not complete) */
#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "addrtoname.h"
#include "ethertype.h"
#include "extract.h"
#include "homa.h"
#include "ip.h"


static const struct tok hm_pkt_types[] ={
    {HOMA_DATA, "DATA"},
    {HOMA_GRANT, "GRANT"},
    {HOMA_RESEND, "RESEND"},
    {HOMA_UNKONWN, "UNKNOWN RPCID"},
    {HOMA_BUSY, "BUSY"},
    {HOMA_CUTOFFS, "CUTOFFS"},
    {HOMA_FREEZE, "FREEZE"},
    {HOMA_NEED_ACK, "NEED ACK"},
    {HOMA_ACK, "ACK"},
    {HOMA_BOGUS, "BOGUS"},
    {0,NULL}
};

static int common_header_print(netdissect_options *ndo, const struct hm_common_hdr *hm_common, uint ipv, const u_char *iph)
{
    
    uint8_t type, priority;
    uint16_t sport,dport;
    uint64_t RPCid;
    const struct ip *ip4;
    const struct ip6_hdr *ip6;
    type = GET_U_1(hm_common->hmch_type);
    sport = GET_BE_U_2(hm_common->hmch_sport);
    dport = GET_BE_U_2(hm_common->hmch_dport);
    RPCid = GET_BE_U_8(hm_common->hmch_rpcid);

    if(!ndo->ndo_vflag)
    {
        /*currently if ipv4 is used, homa specify packet priorities at the top-3 bits of DSCP */
        if(ipv==4)
        {
            ip4 = (const struct ip*)iph;
            priority = GET_U_1(ip4->ip_tos)>>5;
            ND_PRINT("Priority %u,  ", priority);
        }
        else if(ipv==6)
        {
            ip6 = (const struct ip6_hdr *)iph;
            priority = (GET_U_1(ip6->ip6_ctlun.ip6_un2_vfc)&IPV6_TC_MASK);
            ND_PRINT("Priority %u, ", priority);
        }
        else 
        {
            return -1;
        }
    }
    
    ND_PRINT("%u > %u ",sport,dport);

    ND_PRINT("%s, ",tok2str(hm_pkt_types, "UNKONWN", type));
    if(!ndo->ndo_qflag)
    {
        if(RPCid&RPCID_MASK)
            ND_PRINT("Server > Client ");
        else 
            ND_PRINT("Client > Server ");
        ND_PRINT("RPCid %llu ", RPCid);
    }
    
    return type;
}

static void data_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    const struct hm_data_hdr * hm_data_hdr;
    uint32_t message_length, bytes_sent;
    uint16_t cutoff_version;
    uint8_t is_retransmit;

    


    if(length<HOMA_DATA_HDR_LEN)
        nd_print_trunc(ndo);
    hm_data_hdr = (const struct hm_data_hdr *) bp;
    message_length = GET_BE_U_4(hm_data_hdr->hmdata_message_len);
    bytes_sent = GET_BE_U_4(hm_data_hdr->hmdata_incmoing);
    cutoff_version = GET_BE_U_2(hm_data_hdr->hmdata_cutoff);
    is_retransmit = GET_U_1(hm_data_hdr->hmdata_retranflag);

    ND_PRINT("(");
    if(is_retransmit)
        ND_PRINT("Retransmission, ");
    ND_PRINT("Message Length %u, ", message_length);
    ND_PRINT("%u bytes is sent, ", bytes_sent);
    ND_PRINT("cutoff version %u", cutoff_version);
    ND_PRINT(") ");

    /* print even more information */
    if(ndo->ndo_vflag>1)
    {
        
        length -=HOMA_DATA_HDR_LEN;
        struct hm_data_seg *seg;
        struct hm_ack *ack;
        uint32_t offset, segment_length;
        uint64_t ack_rpcid;
        uint16_t ack_clientprot, ack_serverport;
        seg = (struct hm_data_seg *)(bp+HOMA_DATA_HDR_LEN);

        while(length>=HOMA_DATA_SEG_HDR_LEN)
        {
            offset = GET_BE_U_4(seg->hmseg_offset);
            segment_length = GET_BE_U_4(seg->hmseg_length);
            ack = &(seg->hmseg_ack);
            ack_rpcid = GET_BE_U_8(ack->hmack_rpcid);
            ack_clientprot = GET_BE_U_2(ack->hmack_clientport);
            ack_serverport = GET_BE_U_2(ack->hmack_serverport);


            ND_PRINT("[");
            ND_PRINT("offset %u, ",offset);
            ND_PRINT("length %u",segment_length);
            if(ack_rpcid!=0)
            {
                ND_PRINT("(ACK ");
                ND_PRINT("RPCid %llu, ",ack_rpcid);
                if(ndo->ndo_nflag)
                    ND_PRINT("%u > %u ", ack_clientprot, ack_serverport);
                else
                    ND_PRINT("%s > %s ", tcpport_string(ndo,ack_clientprot),tcpport_string(ndo,ack_serverport));
                ND_PRINT(")");
            }
            ND_PRINT("] ");

            length -= HOMA_DATA_SEG_HDR_LEN;
            length -= segment_length;
            seg = (struct hm_data_seg *)((u_char*)seg + HOMA_DATA_SEG_HDR_LEN + segment_length);
        }
    }
}


static void grant_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    const struct hm_grant_hdr *hm_grant;
    uint32_t offset;
    uint8_t priority;

    if(length<HOMA_GRANT_HDR_LEN)
        nd_print_trunc(ndo);
    hm_grant = (const struct hm_grant_hdr *)bp;
    offset = GET_BE_U_4(hm_grant->hmgrant_offset);
    priority = GET_U_1(hm_grant->hmgrant_priority);

    ND_PRINT("(offset %u, ", offset);
    ND_PRINT("priority %u)", priority);
}

static void resend_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    const struct hm_resend_hdr *hm_resend;
    uint32_t offset, resend_length;
    uint8_t priority;

    if(length<HOMA_RESEND_HDR_LEN)
        nd_print_trunc(ndo);
    hm_resend = (const struct hm_resend_hdr *) bp;
    offset = GET_BE_U_4(hm_resend->hmre_offset);
    resend_length = GET_BE_U_4(hm_resend->hmre_length);
    priority = GET_U_1(hm_resend->hmre_priority);

    ND_PRINT("(offset %u, length %u, priority %u)", offset, resend_length, priority);
}

static void ack_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
    const struct hm_ack_hdr *hm_ack_hdr;
    struct hm_ack *hm_ack;
    uint16_t num_acks;
    uint64_t ack_rpcid;
    uint16_t ack_clientport, ack_serverport;
    

    if(length< HOMA_ACK_HDR_LEN)
        nd_print_trunc(ndo);
    hm_ack_hdr = (const struct hm_ack_hdr *) bp;
    num_acks = GET_BE_U_2(hm_ack_hdr->hmack_acknum);

    length -=HOMA_ACK_HDR_LEN;
    hm_ack = (struct hm_ack *)((u_char *)hm_ack_hdr + HOMA_ACK_HDR_LEN);

    while(length>=HOMA_ACK_LEN && num_acks>0 )
    {
        ack_rpcid = GET_BE_U_8(hm_ack->hmack_rpcid);
        ack_clientport = GET_BE_U_2(hm_ack->hmack_clientport);
        ack_serverport = GET_BE_U_2(hm_ack->hmack_serverport);
        if(ack_rpcid!=0)
        {
            ND_PRINT("[RPCid %llu, ",ack_rpcid);
            if(ndo->ndo_nflag)
                ND_PRINT("%u > %u]", ack_clientport, ack_serverport);
            else 
                ND_PRINT("%s > %s]", tcpport_string(ndo,ack_clientport), tcpport_string(ndo,ack_serverport));
        }
        num_acks--;
        length -=HOMA_ACK_LEN;
        hm_ack ++;
    }

}





/**
 * -v(v) print more information
 * -n do not conver port to name
 * -q print less information
 * todo: test priority parse for ipv6 header;
 * 
 * bp is a pointer to the first byte of homa packet
 * length is the captured length of homa packet
 * ipv is the version of ip protocol
 * iph is the pointer to ip protocl header
*/
void homa_print(netdissect_options *ndo, const u_char * bp, u_int length , uint ipv , const u_char * iph)
{

    uint8_t type;
    const struct hm_common_hdr *hm_common;

    ndo->ndo_protocol="homa";

    if(length<HOMA_COMMON_HDR_LEN)
        nd_print_trunc(ndo);
    ND_PRINT("Homa ");
    hm_common = (const struct hm_common_hdr *)bp;
    type = common_header_print(ndo,hm_common,ipv,iph);
    
    if(type<0)
    {
        nd_print_invalid(ndo);
        return;
    }

    if(ndo->ndo_vflag)
    { 
        switch(type){
            case HOMA_DATA:
            /* finished */
            data_print(ndo,bp,length);
            break;

            case HOMA_GRANT:
            /* finished but not test yet*/
            grant_print(ndo,bp,length);
            break;

            case HOMA_RESEND:
            /* finished but not test yet*/
            resend_print(ndo,bp,length);
            break;

            case HOMA_UNKONWN:
            /*finished but not test yet*/
            break;

            case HOMA_BUSY:
            /*finished but not test yet*/
            break; 

            case HOMA_CUTOFFS: 
            break;

            case HOMA_FREEZE: 
            /*finished but not test yet*/
            break; 

            case HOMA_NEED_ACK: 
            /*finished*/
            break;

            case HOMA_ACK: 
            /*finished but not test yet*/
            ack_print(ndo,bp,length);
            break;

            case HOMA_BOGUS: 
            break;

            default:
            nd_print_invalid(ndo);
            return;

        }


    }


    

    
}

