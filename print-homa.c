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
/* to be deleted */
#include "ip.h"




/* The top level routine */
void homa_print(netdissect_options *ndo, const u_char * bp, u_int length)
{
    ND_PRINT("thevalue of vflag: %d\n",ndo->ndo_vflag);
}

