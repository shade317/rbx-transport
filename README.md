# RbxTransport (QUIC / HTTP3 Replacement for RakNet)

`version-4ea8e85481e34f46`

`RBX::RbxTransport` replaces legacy RakNet (`RakPeer`) with a QUIC (ngtcp2) and HTTP/3 WebTransport (nghttp3) stack using OpenSSL 3.x TLS 1.3 Raw Public Keys (RFC 7250), optional X25519MLKEM768 key exchange, and a custom UDP routing header (RUPP, magic `0x52555050`).

> Addresses are tied to the build above and will shift on new clients — read the structure, not the numbers.

## Offsets & Pointer Chain

```cpp
#include <cstdint>

namespace RbxTransport {
    // NetworkClient (vftable 0x728FA78) -> ClientReplicator (vftable 0x728D1B8) -> RbxTransportConnection* (0x490A846)
    constexpr uintptr_t ClientReplicator  = 0xF50;   // [nc+0xF50] = ClientReplicator*
    constexpr uintptr_t TransportFallback = 0xF58;   // [nc+0xF58] = fallback ConnectionInternal* when [nc+0xF50] == 0
    constexpr uintptr_t TransportConn     = 0x108;   // [cr+0x108] = RbxTransportConnection* (0x7206440) / RakNetConnection* (0x7293E58)

    // RbxTransportConnection (vftable 0x7206440, size 0xA48 at 0x3B539DC)
    constexpr uintptr_t ChannelArray      = 0x010;   // 14 channels (Ch 0..13, 8B stride)
    constexpr uintptr_t ReadyMask         = 0xA30;   // uint16_t (0x3FFF when all 14 open)
    constexpr uintptr_t ReceiveModeFlag   = 0xA38;   // uint8_t checked in vt[21] popPacket
    constexpr uintptr_t RtcAppConn        = 0xA40;   // [conn+0xA40] = Impl::RtcAppConnection* (vftable 0x7193940)

    // Impl::RtcAppConnection (0x7193940) -> Impl::RtcIoClientConnection (vftable 0x7193710)
    constexpr uintptr_t RtcIoClientConn   = 0x068;   // [app+0x068] = Impl::RtcIoClientConnection* (0x7193710)
    constexpr uintptr_t QuicMuxConn       = 0x10E28; // [io+0x10E28] = Impl::QuicMultiplexedConnection* (0x7193B08)
    constexpr uintptr_t RuppTokenTlv      = 0x10F50; // [io+0x10F50] = Rupp::TokenTlv* (0x71966F8, +0x08 = 16B TToken)
    constexpr uintptr_t TlsSeedBlock      = 0x11C40; // [io+0x11C40] -> [+0x08..0xD0] = 0xC8B PeerClock seed
    constexpr uintptr_t RpkClientCtx      = 0x11C70; // [io+0x11C70] = Protocol::QuicCryptoRpkClientContext* (0x71962D0)
    constexpr uintptr_t QuicClientConn    = 0x11C80; // [io+0x11C80] = Protocol::QuicClientConnection* (0x7196298, also [mux+0x28])
    constexpr uintptr_t RuppProcessor     = 0x11C88; // [io+0x11C88] = Impl::RtcIoClientPrefixProcessor* (0x7193F70)

    // Protocol::QuicClientConnection (0x7196298) -> Detail::ClientConnCtx (vftable 0x7195E90) -> ngtcp2_conn
    constexpr uintptr_t DetailQuicConnPtr = 0x050;   // [qconn+0x050] = Detail::QuicClientConnection* (inline at +0x060, vt 0x7196210)
    constexpr uintptr_t ClientConnCtx     = 0x1B0;   // [qconn+0x1B0] (or [detail+0x150]) = Detail::ClientConnCtx* (0x7195E90)
    constexpr uintptr_t ConnSeq           = 0x008;   // [ctx+0x008] uint64_t connSeq
    constexpr uintptr_t Ngtcp2ConnPtr     = 0x020;   // [ctx+0x020] ngtcp2_conn*
    constexpr uintptr_t OsslContextPtr    = 0x0C8;   // [ctx+0x0C8] Tls::OsslContext* (0x71934A8)
    constexpr uintptr_t OsslSessionPtr    = 0x0D0;   // [ctx+0x0D0] Tls::OsslSession* (0x7196498)

    // ngtcp2_conn 1-RTT AEAD Key Material (0x225ECF0..0x2260180)
    constexpr uintptr_t OneRttTxCkm       = 0x388;   // [ngtcp2+0x388] active 1-RTT tx ngtcp2_crypto_km*
    constexpr uintptr_t OneRttTxHpCtx     = 0x390;   // [ngtcp2+0x390] tx header protection EVP_CIPHER_CTX*
    constexpr uintptr_t OneRttRxCkm       = 0x3A0;   // [ngtcp2+0x3A0] active 1-RTT rx ngtcp2_crypto_km* (read at 0x225EEFD)
    constexpr uintptr_t OneRttRxHpCtx     = 0x3A8;   // [ngtcp2+0x3A8] rx header protection EVP_CIPHER_CTX*
    constexpr uintptr_t NewTxCkm          = 0x1DF8;  // [ngtcp2+0x1DF8] pre-derived next KEY_PHASE tx ngtcp2_crypto_km*
    constexpr uintptr_t NewRxCkm          = 0x1E00;  // [ngtcp2+0x1E00] pre-derived next KEY_PHASE rx ngtcp2_crypto_km*
    constexpr uintptr_t OldRxCkm          = 0x1E08;  // [ngtcp2+0x1E08] previous KEY_PHASE rx ngtcp2_crypto_km*

    // ngtcp2_crypto_km Layout
    constexpr uintptr_t CkmSecretBase     = 0x00;    // uint8_t* secret.base (points to +0x40, 32B/48B traffic secret)
    constexpr uintptr_t CkmSecretLen      = 0x08;    // size_t secret.len (0x20 or 0x30)
    constexpr uintptr_t CkmAeadCtx        = 0x10;    // void* aead_ctx (EVP_CIPHER_CTX*)
    constexpr uintptr_t CkmIvBase         = 0x18;    // uint8_t* iv.base (points to +0x40 + secret.len, 12B AEAD IV)
    constexpr uintptr_t CkmIvLen          = 0x20;    // size_t iv.len (0x0C = 12B)
    constexpr uintptr_t CkmPktNum         = 0x28;    // int64_t pkt_num (-1 initially)
    constexpr uintptr_t CkmFlags          = 0x38;    // uint8_t flags (0x00 = KEY_PHASE_ZERO, 0x01 = KEY_PHASE_ONE)
}
```

## How These Offsets Are Derived

### NetworkClient -> ClientReplicator -> ConnectionInternal (`0x490A825`)

In `RBX::Network::Client`'s (`NetworkClient`, vftable `0x728FA78`) packet receive loop (`0x490A825`, rcx = rdi = NetworkClient), `0x490A846` reads `ClientReplicator` (vftable `0x728D1B8`) at `[rcx + 0xF50]` and dereferences `[rax + 0x108]` (`0x490A852`) to get the polymorphic `RBX::NetworkBase::ConnectionInternal` (falling back to `[rcx + 0xF58]` at `0x490A85B` when `[rcx + 0xF50] == 0`). On RbxTransport servers (`FFlagRbxTransportBranchSelection` `0x82749D8 == 2`), `[cr + 0x108]` is `RBX::NetworkBase::RbxTransportConnection` (vftable `0x7206440`, vs `0x7293E58` `RBX::Network::RakNetConnection` on legacy RakNet servers), and `0x490A897` invokes `vtable[21]` (`[rax + 0xA8] = 0x3B53110` `popPacket`):

```asm
0x490A846: 48 8B 81 50 0F 00 00   mov  rax, qword ptr [rcx + 0xF50] ; -> [NetworkClient + 0xF50] = ClientReplicator*
0x490A84D: 48 85 C0               test rax, rax
0x490A850: 74 09                  je   0x490A85B
0x490A852: 48 8B 80 08 01 00 00   mov  rax, qword ptr [rax + 0x108] ; -> [ClientReplicator + 0x108] = ConnectionInternal*
0x490A859: EB 07                  jmp  0x490A862
0x490A85B: 48 8B 81 58 0F 00 00   mov  rax, qword ptr [rcx + 0xF58] ; -> [NetworkClient + 0xF58] fallback if +0xF50 == 0
0x490A897: FF 90 A8 00 00 00      call qword ptr [rax + 0xA8]       ; -> vtable[21] popPacket (0x3B53110 on RbxTransportConnection)
```

### RbxTransportConnection -> RtcAppConnection -> RtcIoClientConnection -> QuicClientConnection -> ClientConnCtx -> ngtcp2_conn

Cross-referencing `RBX::NetworkBase::RbxTransportConnection`'s vftable (`0x7206440`, allocated with size `0xA48` at `0x3B539DC`) and live RTTI:

- `0x3B533F7` writes `0x3FFF` to `[rcx + 0xA30]` (`ReadyMask`) once all 14 channels (0..13) are initialized.
- `vtable[19]` (`0x3B52270`) and `vtable[21]` (`0x3B53110`) load `[rcx + 0xA40]` (`0x3B52276`, `0x3B53190`), which holds `RBX::RbxTransport::Impl::RtcAppConnection*` (vftable `0x7193940`).
- `[RtcAppConnection + 0x068]` points to `RBX::RbxTransport::Impl::RtcIoClientConnection` (vftable `0x7193710`), which holds `QuicMultiplexedConnection` (vftable `0x7193B08`) at `+0x10E28`, `RBX::Rupp::TokenTlv` (vftable `0x71966F8`) at `+0x10F50`, `TlsSeedBlock` at `+0x11C40`, `QuicCryptoRpkClientContext` (vftable `0x71962D0`) at `+0x11C70`, `QuicClientConnection` (vftable `0x7196298`) at `+0x11C80` (also `[QuicMultiplexedConnection + 0x028]`), and `RtcIoClientPrefixProcessor` (vftable `0x7193F70`) at `+0x11C88`.
- Inside `Protocol::QuicClientConnection` (`+0x060` embedded `Detail::QuicClientConnection`, vftable `0x7196210`), `0x2216705` loads `[detail + 0x150]` (i.e. `[qconn + 0x1B0]` = `Detail::ClientConnCtx`, vftable `0x7195E90`) and `0x2216711` passes `[ctx + 0x20]` (`ngtcp2_conn`) into ngtcp2:

```asm
0x3B52276: 48 8B 89 40 0A 00 00   mov  rcx, qword ptr [rcx + 0xA40]   ; -> Impl::RtcAppConnection* (+0x068 = Impl::RtcIoClientConnection*)
0x216719C: 48 8B 8B 28 0E 01 00   mov  rcx, qword ptr [rbx + 0x10E28] ; -> Impl::QuicMultiplexedConnection*
0x218D3C6: 48 8B 49 28            mov  rcx, qword ptr [rcx + 0x28]    ; -> Protocol::QuicClientConnection* (also [io + 0x11C80])
0x218D3D0: 48 8B 41 48            mov  rax, qword ptr [rcx + 0x48]    ; -> &Detail::QuicClientConnection* ([qconn + 0x050])
0x2159B6E: 48 8D 4F 70            lea  rcx, [rdi + 0x70]              ; -> Impl::RtcIoClientConnection*
0x2159B75: E8 D6 0E 03 00         call 0x218AA50                      ; -> Copies 0xC8B seed from [io + 0x11C40] + 0x08
0x2216705: 48 8B B9 50 01 00 00   mov  rdi, qword ptr [rcx + 0x150]   ; -> Detail::ClientConnCtx* ([detail + 0x150] == [qconn + 0x1B0])
0x2216711: 48 8B 4F 20            mov  rcx, qword ptr [rdi + 0x20]    ; -> ngtcp2_conn*
```

## RBX::RbxTransport Architecture

### GameJoin & ClientConnectionConfig

When joining an RbxTransport server, `POST https://gamejoin.roblox.com/v1/join-game` returns transport fields parsed by `RBX::Network::TransportParamsParser` (`0x8270D80`). `buildRbxTransportClientConfig` (`0x3B53460`) populates a `0x280`-byte `ClientConnectionConfig` passed to `RbxTransportConnection::createAndStart` (`0x3B538E0`):

```asm
0x3B535E3: 48 8D 93 E0 01 00 00   lea  rdx, [rbx + 0x1E0]        ; -> EphemeralEarlyPubKey (Server RPK)
0x3B535EA: 48 8D 8D C8 00 00 00   lea  rcx, [rbp + 0x0C8]        ; -> QuicCryptoRpkClientContext
0x3B535F1: E8 5A E7 5F FE         call 0x2151D50                 ; -> Bind expected Server RPK
0x3B53626: 80 BB 2E 02 00 00 00   cmp  byte ptr [rbx + 0x22E], 0 ; -> Has RUPP TToken & VIPs?
0x3B5362D: 74 37                  je   0x3B53666
0x3B5362F: 48 8D B3 00 02 00 00   lea  rsi, [rbx + 0x200]        ; -> 46B: 1B type + 16B TToken + VIPs
0x3B5364C: E8 BF E4 5F FE         call 0x2151B10                 ; -> Configure RtcIoClientPrefixProcessor
```

| Offset | Size | Field | Notes |
|---|---|---|---|
| `+0x000..0x022` | `0x24` | `EdgeEndpoint` | UDMUX host (`std::string`) + `uint16_t` port (`NetStackPort` / `rbxTransportPort`) |
| `+0x070..0x092` | `0x24` | `DirectEndpoint` | Direct server host (`std::string`) + `uint16_t` port |
| `+0x108..0x137` | `0x30` | `EarlyTicket` | 48B ticket copied via 3x `movups` (`0x3B539B5`) into `vtable[19]` (`+0x98`) if `[+0x138] != 0` |
| `+0x140..0x160` | `0x20` | `SessionAuth` | Client ticket & public key data passed to `0x2151CC0` |
| `+0x1E0..0x1FF` | `0x20` | `ServerRpk` | Server TLS 1.3 Raw Public Key (`NetStackConfig.EphemeralEarlyPubKey`) |
| `+0x200..0x22D` | `0x2E` | `RuppBlock` | 46B block: 1B token type + 16B `NetStackToken` (`TToken`) + VIPs (`+0x22E` valid flag) |
| `+0x230..0x250` | `0x20` | `TlsServerName` | Optional SNI override (`GameFqdn` / `gameFqdn`) when `[+0x250] != 0` |
| `+0x278` | `0x08` | `WebTransportCfg` | Optional HTTP/3 nghttp3 config (`0x2151930`) |

### RUPP Wire Prefix & TLVs

Before UDP packets reach `ngtcp2_conn_read_pkt`, `RtcIoClientPrefixProcessor` (vftable `0x7193F70`) validates and strips the RUPP (`0x52555050`) prefix at `0x2244680`.

Entry bytes (`0x2244680`):

```
48 89 5C 24 08 48 89 74 24 10 48 89 7C 24 18 55 41 54 41 55 41 56 41 57 48 8B EC 48 83 EC 70
```

```asm
0x22446A3: 48 83 FA 04            cmp   rdx, 4                     ; -> Minimum 4B RUPP header
0x22446A7: 0F 82 55 01 00 00      jb    0x2244802
0x22446B7: 0F B7 4A 02            movzx ecx, word ptr [rdx + 2]    ; -> Big-endian uint16 prefixLen
0x22446BB: 66 C1 C1 08            rol   cx, 8                      ; -> ntohs(prefixLen)
0x22446CA: 44 0F B6 02            movzx r8d, byte ptr [rdx]        ; -> uint8 version
0x22446CE: 41 8D 40 FF            lea   eax, [r8 - 1]              ; -> version - 1
0x22446D2: A8 FC                  test  al, 0xFC                   ; -> Rejects version == 0 or > 4
0x22446D4: 75 28                  jne   0x22446FE
0x22446D6: 41 80 F8 02            cmp   r8b, 2                     ; -> Rejects RUPP v2 (only v1 & v3 pass)
```

`parseRuppFields` (`0x2291100`, jump table at `0x22913F0`) parses the TLV records after the 4-byte header (`[u8 version][u8 flags][u16_be prefixLen]`):

| TLV | Wire Size | Target Offset | Description |
|---|---|---|---|
| `0x01` | 17 (`0x11`) | `[rsi + 0x04..0x15]` | `TToken`: 1B type (`[rsi+0x04]`) + 16B `NetStackToken` (`[rsi+0x05]`, sets `[rsi+0x03] = 1`) |
| `0x02` | 6 (`0x06`) | `[rsi + 0x18..0x2B]` | Client IPv4 (af = 1, 4B IP + 2B BE port) |
| `0x03` | 18 (`0x12`) | `[rsi + 0x18..0x2B]` | Client IPv6 (af = 2, 16B IP + 2B BE port) |
| `0x04` | 6 (`0x06`) | `[rsi + 0x35..0x48]` | Edge VIP IPv4 (af = 1, 4B IP + 2B BE port) |
| `0x05` | 18 (`0x12`) | `[rsi + 0x35..0x48]` | Edge VIP IPv6 (af = 2, 16B IP + 2B BE port) |
| `0x06..0x0A` | Variable | `[rsi + 0x4A..0x88]` | Edge routing / NAT telemetry |

### TLS 1.3 RPK & PEB Capability Gate

`QuicCryptoRpkClientContext` (vftable `0x7196848`, `0x22371B0`) configures OpenSSL 3.x for RFC 7250 Raw Public Keys (`SSL_CTX_set1_client_cert_type` / `SSL_CTX_set1_server_cert_type` + `SSL_add_expected_rpk`), pinning `EphemeralEarlyPubKey` without X.509 certificates. When `FFlagDebugRbxTransportTlsUseX25519MlKem768` (`0x823A538`) is enabled, TLS 1.3 negotiates X25519MLKEM768 (`0x6F79EE0`).

`getTransportCapabilitiesMask` (`0x3B52360`) builds the 64-bit capability mask from 28 FastFlags (default `0x0220010000401001`). At `0x3B526AE`, it reads `PEB->ProcessParameters->Flags` (`gs:[0x60]`) and maps bit 28 (`0x10000000`) into Capability Bit 57 (`0x0200000000000000`):

```asm
0x3B526AE: 65 48 8B 04 25 60 00 00 00   mov    rax, qword ptr gs:[0x60]   ; -> TEB->ProcessEnvironmentBlock
0x3B526B7: 48 8B 48 20                  mov    rcx, qword ptr [rax + 0x20]; -> PEB->ProcessParameters
0x3B526BB: 8B 41 0C                     mov    eax, dword ptr [rcx + 0x0C]; -> ProcessParameters->Flags
0x3B526BE: C1 E8 1C                     shr    eax, 0x1C                  ; -> Isolate bit 28 (0x10000000)
0x3B526C1: A8 01                        test   al, 1
0x3B526C3: 74 0E                        je     0x3B526D3
0x3B526C5: 48 B8 00 00 00 00 00 00 00 02 movabs rax, 0x0200000000000000    ; -> Capability Bit 57
0x3B526CF: 48 09 07                     or     qword ptr [rdi], rax
```

### ngtcp2 AEAD Decryption, Exporters & Replicator Ingest

Short-header 1-RTT packets are decrypted in `ngtcp2_decrypt_pkt_num_and_payload` (`0x225ECF0`):

```asm
0x225ED08: 48 8B 93 20 1E 00 00   mov    rdx, qword ptr [rbx + 0x1E20] ; -> ngtcp2_conn->user_data
0x225ED31: E8 6A A8 FF FF         call   0x22595A0                     ; -> ngtcp2_pkt_remove_hp
0x225EEFD: 48 8B 83 A0 03 00 00   mov    rax, qword ptr [rbx + 0x03A0] ; -> ngtcp2_conn->pktns.crypto.rx.ckm (1-RTT)
0x225EF04: 44 0F B6 68 38         movzx  r13d, byte ptr [rax + 0x38]   ; -> ckm->flags (KEY_PHASE)
0x225F034: 48 8B 8B 30 1E 00 00   mov    rcx, qword ptr [rbx + 0x1E30] ; -> ngtcp2_conn decrypt ctx
0x225F064: E8 37 A4 FF FF         call   0x22594A0                     ; -> ngtcp2_pkt_decrypt
0x2260103: E8 88 D5 FF FF         call   0x225D690                     ; -> ngtcp2_conn_update_key
```

- **Header Protection** (`0x225ED31`): Calls `ngtcp2_pkt_remove_hp` (`0x22595A0`) using `rx.hp_ctx` (`[ngtcp2_conn + 0x3A8]`), then reconstructs the 64-bit packet number via `0x224BC90`.
- **Key Phase & AEAD** (`0x225EEFD..0x225F064`): Compares the packet `KEY_PHASE` bit against `ckm->flags` (`[rax + 0x38]`), selects `[ngtcp2_conn + 0x3A0]` (`pktns.crypto.rx.ckm`, with `tx.ckm` at `[ngtcp2_conn + 0x388]`), `[ngtcp2_conn + 0x1E00]` (`new_rx_ckm`, with `new_tx_ckm` at `+0x1DF8`), or `[ngtcp2_conn + 0x1E08]` (`old_rx_ckm`), and calls `ngtcp2_pkt_decrypt` (`0x22594A0`). Key rotation is handled by `ngtcp2_conn_update_key` (`0x225D690`).
- **RFC 5705 Exporters & PeerClock Seed** (`0x2159B60`): `OsslSession` (`[ClientConnCtx + 0xD0]`, vftable `0x7196498`) exports session keys via `SSL_export_keying_material` using labels `"EXPORTER-RBX-session-crypto-c2s"` (`0x7401C18`) and `"EXPORTER-RBX-session-crypto-s2c"` (`0x7401C38`). After handshake completion (`0x2180AE0`), `0x2159B60` -> `0x218AA50` copies the `0xC8`-byte exported seed from `[RtcIoClientConnection + 0x11C40] + 0x08` into `PeerClock` (`ClientReplicator::peerClockTick` at `0x490AC30`).
- **Replicator Receive Path** (`0x490A825`): `RbxTransportConnection` opens `"ctrl"` (`0x6374726C` at `0x21823EF`) and 14 data channels (0..13, ready mask `[+0xA30] == 0x3FFF`; Channel 1 packets starting with `0x8D` reroute to Channel 13 at `0x3B52A7B`). `NetworkClient` resolves `[nc + 0xF50]` (`ClientReplicator`) -> `[cr + 0x108]` (`ConnectionInternal`), calls `vtable[21]` (`+0xA8`, `0x3B53110`) to pop a `0x58`-byte packet descriptor, and passes it to `ClientReplicator::processPacket` (`0x490AE90`).

---

*`version-4ea8e85481e34f46`. Structure is the takeaway — addresses shift every build.*
