# PPSSPP cleanup

Goal: nothing in psprecomp relies on PPSSPP (upstream or any fork) for its
behaviour, layouts, constants or wire formats. Each item is re-derived from a
source psprecomp may use (see README, "Relationship to Other Projects"):

1. the game's own code and behaviour (PSP2i's EBOOT: what it passes, what its
   handlers read -- addresses cited in the code),
2. uofw (MIT), pspsdk (BSD), pspautotests' hardware-recorded results,
3. public specifications (MIPS32, S3TC), RPCS3's PS3 headers for NP
   numbering, the RPCN server source for its protocol, packet captures of
   other clients,
4. upstream PPSSPP only as a last resort, and said so where it is used.

Licenses. Every source's license is checked before it is used, and only
facts are taken (numbers, layouts, protocol formats) -- never code or text:
- pspsdk: BSD-style (tools/PrxEncrypter is GPL-3.0 and not used); uofw: MIT.
- pspautotests: no license (LICENSE.txt is a placeholder). Its recorded
  hardware behaviour may be cited; none of its test data is copied -- our
  tests use their own values.
- RPCS3: GPL-2.0; RPCN: AGPL-3.0. Facts only, license noted where used.
- psx-spx: no license and, by its maintainers' account, derived from Sony's
  confidential documents: not used.

Ad hoc and RPCN (infrastructure) play are on hold (the network rows below),
so the aemu ad hoc server source is not used either.

Using PPSSPP as an external oracle (docs/ORACLE.md: run as a separate process
and compared against) is not reliance and stays.

| Where | Was based on | Re-derived from | Status |
|---|---|---|---|
| src/hle/net_sock.c constants | Komak57/ppsspp NetInetConstants.h | newlib errno, 4.4BSD socket.h, PSP2i's socket/setsockopt calls | done |
| src/hle/np2.c events, layouts, errors | Komak57/ppsspp sceNp2 | PSP2i's matching2 handlers; RPCS3 sceNp2.h / sceNp.h (GPL-2.0, numbers only) | done |
| src/hle/np.c NP / auth error codes | (no source given) | PSP2i's checks, RPCS3 sceNp.h | on hold (RPCN dropped for now) |
| src/hle/http.c (comment) | credits a fix in Komak57/ppsspp | describe the technique only | done |
| include/psprecomp/recomp_rt.h float -> word | "as PPSSPP does" | pspautotests tests/cpu/fpu/fpu.expected (test_runtime matches it) | done |
| src/vfpu.c vtfm / vmmul order | PPSSPP Int_Vtfm / Int_Vmmul | behaviour recorded on hardware (pspautotests vfpu/matrix, cited, no data copied) and the instruction's encoding; test_vfpu checks it with its own data; PSP2i's vhtfm sites | done |
| src/hle/gpu.c DXT 565 expansion | "as PPSSPP does" | S3TC layout, PSP2i's billboard; widened as our c5650 | done |
| src/hle/sascore.c VAG flags, ADSR packing | PPSSPP VagDecoder / sceSas | PSP2i: its SetSimpleADSR call (08DE02B8: 0x000F / 0x5FC0, an on/off gate), its looping and one-shot sounds | done, except release rates 29 / 30 (no source yet) |
| src/hle/utility.c crypt mode, GETSIZE layout | PPSSPP DetermineCryptMode / GetSizes | pspsdk psputility_savedata.h | layout done; secureVersion -> mode table and the SAVEDATA_PARAMS byte codes still need a source (psdevwiki refuses fetches; a save made on a real PSP would do) |
| include/psprecomp/hle.h, utility.c wording | "interchangeable with PPSSPP" | reword | done |
| include/psprecomp/ge_vertex.h lighting reference | PPSSPP software transform | GE docs, pspautotests gpu | to do |
| src/hle/atrac.c context model | PPSSPP sceAtrac | pspautotests atrac, PSP2i's use | to do |
| src/hle/mpeg.c layouts, errors, timing | PPSSPP sceMpeg | pspautotests mpeg, PSP2i's use | to do |
| src/hle/p2p.c, net_sock.c P2P streams | Komak57/ppsspp RPCNSigAgent, SocketManager | packet captures of PPSSPP players | on hold (online dropped for now) |
| src/hle/adhoc.c, adhoc_matching.c | Komak57/ppsspp sceNetAdhoc | captures (aemu not used) | on hold (ad hoc dropped for now) |
| tests/test_hle.c (comment) | credits the Komak fix | reword | done |
| tests/test_p2p.c, test_adhoc.c (comments) | as the code above | follow the code | on hold |
| include/psprecomp/net.h mode names (PPSSPP_DIRECT / _RELAY) | naming only | rename once adhoc is redone | on hold |
