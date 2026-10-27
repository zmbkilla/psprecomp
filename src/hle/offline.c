/* psprecomp — PSN, NP matching and ad hoc: not available.
 *
 * This toolkit carries no PSN, matching or ad hoc implementation. A game
 * still imports those libraries, and an unanswered import returns 0 (which
 * a game takes for success and then waits on), so each one is answered here
 * the way a PSP without those services answers: starting and stopping a
 * library succeeds, every request fails with SCE_KERNEL_ERROR_ERROR
 * (pspsdk pspkerror.h). A game normally never gets this far: with the
 * network off (psp_net_set_forced_off) it stops at its own "WLAN switch"
 * check, and the ad hoc actions of the network dialog fail (net.c). */

#include "psprecomp/hle.h"

#include <stdio.h>

#define SCE_KERNEL_ERROR_ERROR 0x80020001u

static void ok(void)   { psp_ret(0); }
static void fail(void) { psp_ret(SCE_KERNEL_ERROR_ERROR); }

/* name: the firmware name where it is known, else NULL. */
static const struct { uint32_t nid; const char *lib, *name; int succeeds; } STUBS[] = {
    /* NP, NP auth, NP service, NP commerce 2, the PSN dialog */
    { 0x857B47D3, "sceNp", NULL, 1 }, { 0x37E1E274, "sceNp", NULL, 1 },
    { 0x633B5F71, "sceNp", NULL, 0 }, { 0xBB069A87, "sceNp", NULL, 0 }, { 0x1D60AE4B, "sceNp", NULL, 0 },
    { 0x0F8F5821, "sceNpService", NULL, 1 }, { 0x00ACFAC3, "sceNpService", NULL, 1 },
    { 0x0E9956E3, "sceNpCommerce2", NULL, 1 }, { 0xA5A34EA4, "sceNpCommerce2", NULL, 1 },
    { 0xA1DE86F8, "sceNpAuth", NULL, 1 }, { 0x4EC1F667, "sceNpAuth", NULL, 1 },
    { 0xCD86A656, "sceNpAuth", NULL, 0 }, { 0x3F1C1F70, "sceNpAuth", NULL, 0 },
    { 0xD99455DD, "sceNpAuth", NULL, 0 }, { 0x72BB0467, "sceNpAuth", NULL, 0 },
    { 0xA7BB7C67, "sceUtility", "sceUtilityPsnInitStart", 0 },
    { 0x094198B8, "sceUtility", "sceUtilityPsnGetStatus", 0 },
    { 0x0940A1B9, "sceUtility", "sceUtilityPsnUpdate", 0 },
    { 0xC130D441, "sceUtility", "sceUtilityPsnShutdownStart", 0 },
    /* NP matching 2 */
    { 0x2E61F6E1, "sceNpMatching2", NULL, 1 }, { 0x8BF37D8C, "sceNpMatching2", NULL, 1 },
    { 0x5030CC53, "sceNpMatching2", NULL, 0 }, { 0x3DE70241, "sceNpMatching2", NULL, 0 },
    { 0x190FF903, "sceNpMatching2", NULL, 0 }, { 0x2B3892FC, "sceNpMatching2", NULL, 0 },
    { 0xF47342FC, "sceNpMatching2", NULL, 0 }, { 0x4EE3A8EC, "sceNpMatching2", NULL, 0 },
    { 0xA53E7C69, "sceNpMatching2", NULL, 0 }, { 0xA3C298D1, "sceNpMatching2", NULL, 0 },
    { 0x6D6D0C75, "sceNpMatching2", NULL, 0 }, { 0xFADBA9DB, "sceNpMatching2", NULL, 0 },
    { 0xAAD0946A, "sceNpMatching2", NULL, 0 }, { 0x7BBFC427, "sceNpMatching2", NULL, 0 },
    { 0xC870535A, "sceNpMatching2", NULL, 0 }, { 0x81C13E6D, "sceNpMatching2", NULL, 0 },
    { 0x12C5A111, "sceNpMatching2", NULL, 0 }, { 0xD7D4AEB2, "sceNpMatching2", NULL, 0 },
    { 0xE6C93DBD, "sceNpMatching2", NULL, 0 }, { 0xF940D9AD, "sceNpMatching2", NULL, 0 },
    { 0x97529ECC, "sceNpMatching2", NULL, 0 }, { 0xC8FC5D41, "sceNpMatching2", NULL, 0 },
    /* ad hoc */
    { 0xE1D621D7, "sceNetAdhoc", "sceNetAdhocInit", 1 }, { 0xA62C6F57, "sceNetAdhoc", "sceNetAdhocTerm", 1 },
    { 0x6F92741B, "sceNetAdhoc", "sceNetAdhocPdpCreate", 0 }, { 0xABED3790, "sceNetAdhoc", "sceNetAdhocPdpSend", 0 },
    { 0xDFE53E03, "sceNetAdhoc", "sceNetAdhocPdpRecv", 0 }, { 0x7F27BB5E, "sceNetAdhoc", "sceNetAdhocPdpDelete", 0 },
    { 0xC7C1FC57, "sceNetAdhoc", "sceNetAdhocGetPdpStat", 0 }, { 0x877F6D66, "sceNetAdhoc", "sceNetAdhocPtpOpen", 0 },
    { 0xE08BDAC1, "sceNetAdhoc", "sceNetAdhocPtpListen", 0 }, { 0x9DF81198, "sceNetAdhoc", "sceNetAdhocPtpAccept", 0 },
    { 0xFC6FC07B, "sceNetAdhoc", "sceNetAdhocPtpConnect", 0 }, { 0x4DA4C788, "sceNetAdhoc", "sceNetAdhocPtpSend", 0 },
    { 0x8BEA2B3E, "sceNetAdhoc", "sceNetAdhocPtpRecv", 0 }, { 0x9AC2EEAC, "sceNetAdhoc", "sceNetAdhocPtpFlush", 0 },
    { 0x157E6225, "sceNetAdhoc", "sceNetAdhocPtpClose", 0 }, { 0xB9685118, "sceNetAdhoc", "sceNetAdhocGetPtpStat", 0 },
    { 0x73BFD52D, "sceNetAdhoc", "sceNetAdhocSetSocketAlert", 0 },
    { 0xE26F226E, "sceNetAdhocctl", "sceNetAdhocctlInit", 0 }, { 0x9D689E13, "sceNetAdhocctl", "sceNetAdhocctlTerm", 1 },
    { 0x20B317A0, "sceNetAdhocctl", "sceNetAdhocctlAddHandler", 0 }, { 0x6402490B, "sceNetAdhocctl", "sceNetAdhocctlDelHandler", 1 },
    { 0x34401D65, "sceNetAdhocctl", "sceNetAdhocctlDisconnect", 0 }, { 0x0AD043ED, "sceNetAdhocctl", "sceNetAdhocctlConnect", 0 },
    { 0xEC0635C1, "sceNetAdhocctl", "sceNetAdhocctlCreate", 0 }, { 0x5E7F79C9, "sceNetAdhocctl", "sceNetAdhocctlJoin", 0 },
    { 0x08FFF7A0, "sceNetAdhocctl", "sceNetAdhocctlScan", 0 }, { 0x75ECD386, "sceNetAdhocctl", "sceNetAdhocctlGetState", 0 },
    { 0xDED9D28E, "sceNetAdhocctl", "sceNetAdhocctlGetParameter", 0 }, { 0x362CBE8F, "sceNetAdhocctl", "sceNetAdhocctlGetAdhocId", 0 },
    { 0x81AEE1BE, "sceNetAdhocctl", "sceNetAdhocctlGetScanInfo", 0 }, { 0xE162CB14, "sceNetAdhocctl", "sceNetAdhocctlGetPeerList", 0 },
    { 0x8DB83FDC, "sceNetAdhocctl", "sceNetAdhocctlGetPeerInfo", 0 }, { 0x8916C003, "sceNetAdhocctl", "sceNetAdhocctlGetNameByAddr", 0 },
    { 0x941B3877, "sceNetAdhocDiscover", "sceNetAdhocDiscoverInitStart", 0 },
    { 0x52DE1B97, "sceNetAdhocDiscover", "sceNetAdhocDiscoverUpdate", 0 },
    { 0x944DDBC6, "sceNetAdhocDiscover", "sceNetAdhocDiscoverGetStatus", 0 },
    { 0xA2246614, "sceNetAdhocDiscover", "sceNetAdhocDiscoverTerm", 1 },
    { 0xF7D13214, "sceNetAdhocDiscover", "sceNetAdhocDiscoverStop", 1 },
    { 0xA423A21B, "sceNetAdhocDiscover", "sceNetAdhocDiscoverRequestSuspend", 0 },
    { 0x2A2A1E07, "sceNetAdhocMatching", "sceNetAdhocMatchingInit", 0 },
    { 0x7945ECDA, "sceNetAdhocMatching", "sceNetAdhocMatchingTerm", 1 },
    { 0xCA5EDA6F, "sceNetAdhocMatching", "sceNetAdhocMatchingCreate", 0 },
    { 0x93EF3843, "sceNetAdhocMatching", "sceNetAdhocMatchingStart", 0 },
    { 0x32B156B3, "sceNetAdhocMatching", "sceNetAdhocMatchingStop", 1 },
    { 0xF16EAF4F, "sceNetAdhocMatching", "sceNetAdhocMatchingDelete", 1 },
    { 0x5E3D4B79, "sceNetAdhocMatching", "sceNetAdhocMatchingSelectTarget", 0 },
    { 0xEA3C6108, "sceNetAdhocMatching", "sceNetAdhocMatchingCancelTarget", 0 },
    { 0x8F58BEDF, "sceNetAdhocMatching", "sceNetAdhocMatchingCancelTargetWithOpt", 0 },
    { 0xB5D96C2A, "sceNetAdhocMatching", "sceNetAdhocMatchingGetHelloOpt", 0 },
    { 0xB58E61B7, "sceNetAdhocMatching", "sceNetAdhocMatchingSetHelloOpt", 0 },
    { 0xF79472D7, "sceNetAdhocMatching", "sceNetAdhocMatchingSendData", 0 },
    { 0xEC19337D, "sceNetAdhocMatching", "sceNetAdhocMatchingAbortSendData", 0 },
};

void psp_offline_register(void) {
    for (size_t i = 0; i < sizeof STUBS / sizeof STUBS[0]; i++)
        psp_hle_register(STUBS[i].nid, STUBS[i].lib, STUBS[i].name, STUBS[i].succeeds ? ok : fail);
}
