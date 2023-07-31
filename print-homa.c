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
/* to be deleted */
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

static int common_header_print(netdissect_options *ndo, const struct hm_common_hdr *hm_common)
{
    uint8_t type;
    uint16_t sport,dport;
    uint64_t RPCid;
    type = GET_U_1(hm_common->hmch_type);
    sport = GET_BE_U_2(hm_common->hmch_sport);
    dport = GET_BE_U_2(hm_common->hmch_dport);
    RPCid = GET_BE_U_8(hm_common->hmch_rpcid);
    if(ndo->ndo_nflag)
        ND_PRINT("%u > %u ",sport,dport);
    else 
        ND_PRINT("%s > %s ",tcpport_string(ndo,sport),tcpport_string(ndo,dport));

    ND_PRINT("%s ",tok2str(hm_pkt_types, "UNKONWN", type));
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
    

    if(length<HOMA_DATA_HDR_LEN)
        nd_print_trunc(ndo);
    


}



/**
 * -v(vv) print more information
 * -n do not conver port to name
 * -q print less information
 * 
 * bp is a pointer to the first byte of homa packet
 * length is the length of homa packet
*/
void homa_print(netdissect_options *ndo, const u_char * bp, u_int length)
{

    uint8_t type;
    const struct hm_common_hdr *hm_common;

    ndo->ndo_protocol="homa";

    if(length<HOMA_COMMON_HDR_LEN)
        nd_print_trunc(ndo);
    ND_PRINT("Homa ");
    hm_common = (const struct hm_common_hdr *)bp;
    type = common_header_print(ndo,hm_common);

    if(ndo->ndo_vflag)
    { 
        switch(type){
            case HOMA_DATA:
            break;

            case HOMA_GRANT:
            break;

            case HOMA_RESEND:
            break;

            case HOMA_UNKONWN:
            break;

            case HOMA_BUSY:
            break; 

            case HOMA_CUTOFFS: 
            break;

            case HOMA_FREEZE: 
            break; 

            case HOMA_NEED_ACK: 
            break;

            case HOMA_ACK: 
            break;

            case HOMA_BOGUS: 
            break;
        }


    }


    

    
}

