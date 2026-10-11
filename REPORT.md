# Reverse-engineering report: an encrypted, licence-gated .NET plug-in

**Published copy.** This is the analysis report from a self-directed reverse-engineering
project. Three things differ from the working copy, and only these three:

* the **live licence endpoint** is redacted (`<licence-endpoint-redacted>`);
* references to **internal working artefacts** (captures, trace files, the de-obfuscated
  assembly) are marked `[internal]` — those files are deliberately not published;
* nothing else is changed: every measurement, count and conclusion is exactly as recorded.

**Scope.** Analysis only, and **read-only throughout**. The target is used as a
**self-study research sample**: nothing was written to it, no code was injected, no
licence or cryptographic logic was modified, no server response was forged, and the
payload was never executed. The decrypted payload image was obtained by read-only
memory access to a running process that was already licensed and unlocked. No attempt
was made to break the encryption itself.

**What this is.** A commercial game plug-in for FINAL FANTASY XIV, shipped as a licensing
shell whose real payload sits inside an 8 MB encrypted blob. The report covers the container
chain, the licence protocol, the protection techniques, the toolchain built to defeat them,
what the plug-in actually does, and — explicitly — the boundary where static analysis stops.

---

# What `I-Ching-GL.dll` is, and how it works

Reverse-engineering report for the shipped plug-in in this folder.
Everything below is either **observed** (read out of the shipped bytes, with the
command that produced it), **inferred** (a conclusion drawn from observed facts,
with the reasoning shown) or **unknown** (stated as such).

Artifact under analysis:

| Field | Value |
| --- | --- |
| File | `I-Ching-GL.dll` (9,711,616 bytes) |
| SHA-256 | `2417577af1bfcce7e3df694428b85f02228292e85e41890d514b344c89c8af03` |
| Format | PE32+ managed, CLI header, **IL-only**, `machine 0x8664` (x86_64) |
| Runtime | `.NETCoreApp,Version=v10.0` |
| Assembly | `SirenAuth.I-Ching-GL` v1.0.0.0, module `SirenAuth.I-Ching-GL.dll` |
| MVID | `56e527a6-8c02-49dc-9d92-e1e56ed2999f` |
| Manifest | `I-Ching-GL.json`: Author `Siren`, InternalName `I-Ching-GL`, DalamudApiLevel `15`, RepoUrl `extrant/I-Ching` |

Evidence id (REA `inspect_managed_artifact`): `ev_b12bdebbc727ebefb78a517f10022665ca51d8b99ed701415d715521764cf8a9`.

---

## 0. How to read this report

This report covers **two different assemblies**, and confusing them is the easiest mistake to
make here, because both are called `I-Ching-GL`:

| | **The shell** | **The payload** |
| --- | --- | --- |
| File | the shipped `I-Ching-GL.dll`, 9,711,616 B, sha256 `2417577af1bfcce7…` | `I-Ching-GL` v0.1.6.6, 7,966,208 B, sha256 `f60f7e6532e32c05…` |
| Assembly name | `SirenAuth.I-Ching-GL` v1.0.0.0 | `I-Ching-GL` v0.1.6.6 |
| TypeDefs / methods | **590 / 2,102** | **2,833 / 10,353** |
| Invisible-named types | 555 (550 delegates) | **2,633** (2,627 delegates) |
| Bodies | encrypted — 488 of 998 unreadable (§2) | flattened but readable after de-obfuscation (§17) |
| Where it lives | the file on disk | inside an 8 MB encrypted blob in that file, unwrapped only at run time (§15) |
| Sections | §1–§14 | §15–§27 |

The shell is a licensing loader; the payload is the actual cheat. Everything the shell does
exists to fetch, decrypt and load the payload.

**Reading order, if you want the story rather than the audit trail:**

1. §1 for the summary, then §15 for the container chain that connects the two artifacts.
2. §16–§17 for what the payload is and how its code was made readable again.
3. §19, §23, §26 for what it does; §17.3 for the feature switchboard.
4. §18, §20, §22 for the protection and where the missing strings went.
5. §21 for the licence layer, §25 for its dependencies, §27 for the synthesis.
6. §2–§14 are the shell's own record — metadata, the licence protocol, the sealed package
   format, and the run-time observations that produced §15.

## 1. Answer in one paragraph

It is a **thin licensing shell that boots somebody else's plug-in**. The assembly
Dalamud loads declares one plug-in entry type, `AEAssist.Plugin`, which does
nothing but hold a `SirenAuth.Plugin` object. That object identifies the machine
and the Dalamud environment, asks a licence service over HTTPS for permission,
receives an AES-GCM "wrapped" package secret, uses it to decrypt an 8 MB
encrypted blob embedded in the DLL, and loads the resulting assembly into its own
`AssemblyLoadContext`. The real functionality — the reason the shell exists —
lives inside that encrypted payload, never in the file you can read.

Once that payload is unwrapped, it turns out to be a full FFXIV cheat: a protector-obfuscated
`I-Ching-GL` v0.1.6.6 with 2,833 types and 10,353 methods, whose 2,633 invisible-named types
(2,627 of them generated delegates) hide a feature set of combat and movement hooks, a radar,
a command generator with 176 game-command flags, an outsourced navigation client, three
compute-shader background blur, and its own licence client — all of it reaching the game by
**signature scan rather than by name**, and all of its strings, patterns and keys rebuilt at
run time so that the artifact gives up its structure and nothing else (§16–§27).

## 2. The public metadata survived; the code did not

`ilspycmd` can list every type, field and signature, but essentially **no method
body in the assembly is readable IL**:

```
types=590 methods=2102
bodies: tiny=245 fat=265 INVALID=488 no-body=1104 unreadable(748 BadImageFormatException)
```

Every body that matters begins with a header byte that is neither the tiny (`0x02`)
nor the fat (`0x03`) format, e.g. `SirenAuth.Plugin..ctor` starts with `0x70`,
`DecryptChunks` with `0xD5`, `AuthWindow.Draw` with `0x5C`. The reader fails with
`Invalid MethodBodyBlock` / `Invalid method header`, and
`System.Reflection.Metadata` throws `BadImageFormatException`. This is
method-body encryption: names, signatures, fields, attributes and resources are
left intact while the code is stored somewhere else and restored at run time.

Corroborating observations:

* **Two P/Invokes, and only two** — `kernel32!GetModuleHandle` and
  `kernel32.dll!GetProcAddress` (both with an empty managed name). Resolving a
  native export at run time is the classic first step of a body-decryption stub.
  (The payload declares the same pair, and there a call-site scan shows they are **never
  called** — §22.1. The shell's bodies are encrypted, so its own use of them is not
  observable; the resemblance is noted, not assumed.)
* **The module initializer is the one readable body.** `<Module>..cctor` is a fat
  method with 2,354 bytes of decodable IL, and it is control-flow flattened —
  the decompiler renders it as opaque-predicate arithmetic (`num = 160038038;
  num = -1027977584 ^ num; if (num >= 1115868926) continue;`). That is where the
  real initialisation happens, and it is deliberately unreadable in a different way.
* **555 of the 590 `TypeDef`s are named with zero-width and bidi-control
  characters**; 550 of them derive from `System.MulticastDelegate` with a single
  runtime-implemented constructor (`rva=0`, `impl=0x3`), and 5 do not. §13.4
  corrects an earlier "~150" here. Delegate indirection of this shape is what a
  body-encrypting protector emits for call sites whose targets it rewrites at run time.
* **The user-string heap was wiped**: `#US` contains 6 entries — three strings made
  only of zero-width characters, `{0:X}`, and two empty strings. Every literal the
  original code used (UI labels, URLs, JSON keys) is therefore *not* in the file.

So: the *shape* of the program is recoverable and the *code* is not. Sections 3–6
are read from metadata and resources; section 7 lists what that cannot settle.

## 3. Entry point and object graph (observed)

```csharp
namespace AEAssist;

[Obfuscation(Feature = "NameObfuscation", Exclude = true, ApplyToMembers = true)]
public sealed class Plugin : IDisposable          // the type Dalamud instantiates
{
    private readonly SirenAuth.Plugin inner;
    public Plugin(string pluginPath, AssemblyLoadContext loadContext,
                  IDalamudPluginInterface pluginInterface, object log);
    public void Dispose();
}
```

`SirenAuth.Plugin` is the actual program. Its fields alone describe the design:

| Field | Meaning |
| --- | --- |
| `OriginServerHost`, `PreferredCloudflareHost`, `FallbackServerUrl`, `FallbackUserAgent` | licence endpoints: a preferred host fronted by Cloudflare plus a fallback URL |
| `httpClient`, `fallbackHttpClient` | two clients, one per path |
| `identityProvider` | machine/account identity |
| `authWindow` (`SirenAuth.UI.AuthWindow`) | the ImGui window the user sees while the gate runs |
| `loader` (`ProtectedPluginLoader`) | loads the decrypted assembly |
| `manifest` (`PayloadManifest`) | the embedded package description |
| `pluginInterface`, `hostLoadContext`, `pluginPath`, `pluginLog`, `clientCv`, `status`, `loaded`, `loadStarted` | host wiring and state |

The method names are an ordered trace of the gate — note the compiler-generated
async state machines `d__24`…`d__33`, which confirm these are real `async` methods
rather than helpers:

```
VerifyAndLoadAsync          <.ctor>b__21_0   (certificate-validation callback)
  RequestTicketAsync        d__25
  PostVerifyAsync           d__29
  PostJsonWithFallbackAsync d__30   ->  PostJsonAsync d__31
  ConnectViaPreferredCloudflareAsync d__32 -> ConnectToHostAsync d__33
  LoadProtectedPluginAsync  d__26
LoadProtectedPlugin / Load
DecryptChunks / DeriveChunkKey / ChunkAssociatedData
Nonce / RequestAssociatedData / ResponseAssociatedData / Mask / Sha256Hex / PinMatches
Draw / Dispose
```

`PinMatches(certificate, expectedPin)` plus `<.ctor>b__21_0(_, cert, _, _)` is a
`ServerCertificateCustomValidationCallback`: the client **pins the licence server's
certificate** instead of trusting the platform chain. `Mask(value)` exists purely
so log output does not leak identifiers.

## 4. The licence protocol (observed field names)

Six DTOs carry the whole exchange. Names are the original ones; the layout below is
their metadata, not a decompilation.

```
VerifyRequest   PackageId TicketId TicketNonce RequestNonce ClientCv
                IssuedAtUnixMs ClientPublicKey BodyNonce BodyCipherText BodyTag
VerifyEnvelope  MachineCode AccountSid CharacterCid MidToken SidToken CidToken DalamudProbe
VerifyResponse  Ok Offset WrappedKey KeyNonce KeyTag ServerPublicKey
                ExpiresAtUnixMs Signature Message
TicketRequest   PackageId ClientCv IssuedAtUnixMs ClientPublicKey
TicketResponse  Ok TicketId TicketNonce ExpiresAtUnixMs Message
DalamudProbeReport InternalName IsDev AssemblyFileName AssemblyDirectoryHash
                ConfigDirectoryHash InterfaceAssemblyLooksDalamud
                HasDalamudPluginInterfaceType HasUiBuilder RuntimeFingerprint
```

Read together they define a two-call, key-agreement flow:

```
client                                     service
  |-- POST /ticket  (packageId, cv, clientPublicKey) --------->|   ticket issuance
  |<-- ticketId + ticketNonce + expiry ------------------------|
  |
  |-- POST /verify  cleartext: packageId, ticket, requestNonce,
  |                 clientPublicKey, IssuedAt, body{nonce,cipher,tag}
  |                      ^ body = AES-GCM(VerifyEnvelope) ----->|  envelope is machine + account
  |                                                             |  + character + Dalamud probe
  |<-- Ok, Offset, WrappedKey{nonce,tag}, ServerPublicKey,       |
  |    ExpiresAtUnixMs, Signature, Message --------------------|
  |
  |-- verify Signature over the response against a pinned key
  |-- unwrap the package secret with the response key
  '-- DecryptChunks(...) -> LoadProtectedPlugin(assemblyBytes)
```

`Offset` in the response is a **resume point**: the service can authorise starting at
chunk *n* instead of 0. `CryptoKit` names the two derivations it needs —
`DeriveRequestKey`, `DeriveResponseKey`, `DeriveExchangeKey(localKey,
remotePublicKey, label, context)`, `DeriveRawSecretAgreement`, plus
`AesGcmEncrypt`/`AesGcmDecrypt` and `ECDiffieHellman`/`ECDsa` usage — with the
labels `SirenAuth.RequestEnvelope.v1` and `SirenAuth.ResponseKeyWrap.v1` surviving
as `const string` fields. There is also `LegacyResponseSignatureMaterial` next to
`ResponseSignatureMaterial`: the response signature format was versioned without
changing the DTO.

Two trust anchors are shipped inside the package manifest rather than compiled in,
so they can be rotated without a new build:
`PayloadManifest.ServerVerifyPublicKey` (ECDSA over responses) and
`ServerExchangePublicKey` (ECDH), plus `ServerTlsPublicKeySha256` for the pin.

## 5. The sealed package format (observed)

```
PayloadManifest  PackageId EntryType LoaderKind CipherSha256 ChunkSize PlainLength
                 Chunks[] ServerVerifyPublicKey ServerExchangePublicKey PluginName
                 ServerUrl ServerTlsPublicKeySha256 WindowTitle WindowPrompt
ChunkManifest    Index CipherOffset CipherLength Nonce Tag CipherSha256
AesGcmPacket     CipherText Nonce Tag                  (a C# record: EqualityContract/Deconstruct)
```

That is a chunked container with per-chunk AES-GCM nonce/tag and per-chunk
SHA-256, an overall ciphertext hash, a declared plaintext length, an entry type
name and a `LoaderKind` switch. `EmbeddedPayload` completes the picture:

```csharp
LoadManifest() / LoadPayload() / SliceChunk(payload, chunk) / Sha256Hex(data) / Open(name)
```

`Open(string name)` reads a named manifest resource, so the package travels as
embedded resources — exactly the two names we can see in the manifest resource
table (below). The packer's side of this is `DeriveChunkKey(chunkSeed, request,
chunkIndex)` and `ChunkAssociatedData(request, chunkIndex)`: each chunk is bound to
its index through the AEAD associated data, so chunks cannot be reordered, dropped
or spliced from another package.

## 6. What is actually inside the resources (observed)

| Resource | Implementation | Size | Notes |
| --- | --- | --- | --- |
| `SirenAuth.Embedded.payload.siren` | linked → AssemblyRef `A4444E08` | — | the payload container |
| `SirenAuth.Embedded.payload.json` | linked → AssemblyRef `A4444E08` | — | the manifest |
| `C1F288B0`, `51D5418C` | linked → AssemblyRef `A4444E08` | — | obfuscated extra resources |
| `6A2D3E45` | embedded in this file | **8,018,456 B** | high-entropy blob |

The embedded blob is the interesting one:

```
head          B4 1F 69 60 3D 92 99 6F 3E 6F 25 1D 27 AC 79 40
entropy       min 7.9969, max 7.9980 over 122 × 64 KiB windows   (8.0 = maximum)
length mod 16 = 8      length mod 12 = 8
resource length prefix = 2,710,610,444   (0xA190A20C, file offset 1024: 338x the
                                          actual payload; see §13.4 for the correction)
```

Maximum entropy across the whole blob means it is encrypted or compressed-and-encrypted,
not a PE image with structure. The declared length is deliberately wrong — REA
flagged the same row as `invalid-resource` (`Embedded resource length leaves the CLI
resources directory`) — and the length is not a multiple of the AES block size.
Conclusion: the length prefix and the 4,096-byte alignment make any offset computed
from the resource table untrustworthy, which is presumably the point.

**I did not decrypt this blob.** No key material is shipped in a usable form (the
package secret is only ever issued by the operator's service over the network), and
breaking this protection is out of scope by choice, not by limitation: see §8.

## 7. Dependencies, and what they say about intent

`I-Ching-GL.deps.json` lists the build-time dependency set:

```
BouncyCastle.Cryptography 2.6.2      ECommons 3.2.1.17
System.Management 10.0.1             InteropGenerator.Runtime 1.0.0.0
System.CodeDom 10.0.1                TerraFX.Interop.Windows 10.0.26100.5
```

* **BouncyCastle** backs `CryptoKit`; the reference list also carries
  `System.Security.Cryptography` and `System.Text.Json`, i.e. both a heavyweight
  and a platform crypto stack are present.
* **`System.Management` + `System.CodeDom`** (the latter is its transitive
  dependency) is the WMI route to hardware identifiers, matching
  `IdentityProvider.MachineCode()`, `QueryFirst(query, property)`,
  `QueryDisks()` and `IsValidSerial(value)`: disk serials, plus
  `Salt` and a cached machine code, hashed through `Hash128` and `Base64Url`.
* **ECommons** is a well-known third-party Dalamud utility library — it is a
  dependency of the *payload*, not of a licensing shell, which is consistent with
  the payload being a full-featured plug-in.
* `AssemblyRef A4444E08 v0.0.0.0` (no public key) is the obfuscated identity the
  four linked resources point at. Whether that assembly is ever loaded, or whether
  the shell has simply been renamed after the protector stamped it, is **unknown**;
  the resource table alone cannot settle it, and the methods that would answer it
  are encrypted.

## 8. External context (verified, and clearly separated)

Checked against the public web, not inferred from the binary:

* The plug-in is published: `extrant/DalamudPlugins/pluginmaster.json` lists
  Author `Siren`, InternalName `I-Ching-GL`, `DalamudApiLevel 15`, and the same
  Chinese description, with the download pointing at
  `extrant/DalamudPluginAssets/I-Ching-GL.zip`. The same manifest also lists
  `Zhouyi`, `Coyote-FFXiv`, `GposeResizer` and others by the same author.
* **AEAssist** is a real, closed-source FF14 rotation/auto-fight plug-in for the
  Chinese Dalamud ecosystem that requires logging in to the developer's own
  authorisation server, with account level gating the available features — see the
  third-party "private server" project `LLnutLL/AEAssistServer`, whose README
  describes redirecting that authentication traffic.
* **Hypothesis, not established fact:** that this DLL is a repack or re-release of
  AEAssist wrapped in the author's own `SirenAuth` licensing. The evidence *for* it
  is that the entry type is literally `AEAssist.Plugin` and that the shell shape
  (encrypted payload + licence server + account tiering) matches AEAssist's known
  distribution model. There is no public statement confirming it, and I could not
  verify it from the shipped bytes.

## 9. Limits of this analysis

**Scope note added later:** this section was written while only the *shell* was available
(§0). Two of its four items were superseded once the payload was recovered in §15 and made
readable in §17, and are kept here with their status rather than deleted:

| Item | Status now |
| --- | --- |
| 1 — no method body recovered | **superseded for the payload**: §17 recovered 4,837 method bodies and removed 208,095 junk instructions; it remains true of the *shell*, whose 488 bodies are still unreadable (§2) |
| 2 — the runtime picture is thin | **partly superseded**: §15 adds a capture of the decrypted payload image, but the observation is still one host, one account, one session |
| 3 — the payload was not decrypted | **superseded**: §15 records the read-only capture that recovered it |
| 4 — the `A4444E08` question and the obfuscator | **still open**, and §17 now describes the protector's actual techniques (flattening, invisible names, wiped `#US`, runtime string reconstruction) without naming a commercial tool |

1. **No method body was recovered.** The flow in §3–§4 is inferred from signatures,
   field names, DTO shapes, state-machine names and the `const` labels. It is
   consistent with all observed facts, but it is not an execution trace, and the
   ordering of individual steps inside `VerifyAndLoadAsync` is not proven.
2. **The runtime picture is thin.** §12 records two sessions on one host: what the
   plug-in logged, wrote and connected to — not what it did inside the process. It
   is not an execution trace, it says nothing about the payload's behaviour, and it
   covers one account on one machine. Reproducing it needs FFXIV, a Dalamud install
   at API 15 and a live licence server.
3. **The payload was not decrypted**, so its capabilities are unverified. Statements
   about what the payload does are inferences from its dependencies.
4. **The `A4444E08` question is open** (§7), as is the exact obfuscator. The
   `Invalid method header` message is a generic `System.Reflection.Metadata`
   resource string, so it identifies the *symptom*, not the tool. Tools with
   documented method-body encryption include Eziriz .NET Reactor/NecroBit,
   Agile.NET, ConfuseEx, Eazfuscator and VMProtect .NET; intact metadata plus
   destroyed bodies plus a bespoke loader is equally consistent with custom
   body encryption applied to a payload assembly.

## 10. Scope boundary

Recovering the encrypted payload, forging licence responses or patching the gate
would be circumventing a third party's protection and, in the payload's case,
reproducing a closed-source combat-automation product. (An earlier revision of
this section said "paid". §8 establishes account-tiered authorisation, not a
price, so that word was unsupported and has been removed.) I did neither, and
the rebuilt
feature deliberately reproduces only the **generic infrastructure** the analysis
revealed — entitlement checking, signed responses, a chunked authenticated
container and an isolated payload load context. That is what
[`PayloadGate/`](PayloadGate/README.md) implements, as a clean-room design with its
own protocol ([`PayloadGate/PROTOCOL.md`](PayloadGate/PROTOCOL.md)).

That implementation is verified, independently of this report: 43/43 tests pass,
and `tools/PayloadGate.Verify` reads the sealed package back out of the *built*
plug-in assembly, hosts the licence service on the declared URL, performs the real
handshake, unseals the payload, loads it through the real loader and confirms it
started and unloaded — `ACCEPTANCE CHECK PASSED`, exit 0.

Re-verified on the analysis host on 2026-10-11: `43/43` tests pass, and the
acceptance check prints `ACCEPTANCE CHECK PASSED`, exit 0. Re-running it surfaced
one defect in the verifier, since fixed: it resolved the plug-in path against the
*process working directory* while resolving the key path against the project root,
so it only ran successfully from inside `PayloadGate/`. Both paths now follow the
project-root rule, and the check was confirmed from the repository root and from an
unrelated directory.

## 11. Reproducing this analysis

```powershell
# inventory: types, members, method-body status, #US strings, resources
dotnet run --project _analysis\dump -- I-Ching-GL.dll _analysis\out
# per-type metadata decompile (isolated so one bad type cannot abort the run)
ilspycmd -t SirenAuth.Plugin I-Ching-GL.dll
# resource blob
#   _analysis\out\resources\r04_6A2D3E45.bin   (8,018,456 bytes, entropy 8.0)
```

Artifacts written by this analysis live in `_analysis/` (`inventory.txt`,
`userstrings.txt`, `classlist.txt`, `types/*.cs`, `resources/*.bin`). The dumper is
read-only: it uses `PEReader`/`MetadataReader` and never loads the assembly into a
CLR or executes any target code.

---

## 12. Runtime observation (observed)

Everything above is read out of the shipped bytes; §9.2 previously recorded that no
runtime observation had been performed. This section adds one, taken on 2026-10-11
from the host that ran the plug-in. It **upgrades the §8 hypothesis to an observed
fact** and confirms the §4 and §7 inferences about licensing.

### 12.1 How it was run

| Field | Value |
| --- | --- |
| Host | Windows x86-64 |
| Game | `ffxiv_dx11.exe` (PID 9244 at capture) |
| Loader | Dalamud, launched through XIVLauncher |
| Plug-in source | **dev plug-in**, loaded directly from the folder holding the analysed artifact |
| Dalamud plug-in id | `2978bbc9-1694-4d63-b9b9-be1b29237498` |
| Evidence | `%APPDATA%\XIVLauncher\dalamud.log` |

It was loaded as a dev plug-in rather than installed from a repository, so this is
the artifact of §1 — not a re-release or a copy.

### 12.2 Two independent runs, both unsealed the body

The log records two loads. Both passed the gate and reached the payload's own
initialisation, which makes the observation reproducible rather than a one-off:

| Run | Reached | Outcome |
| --- | --- | --- |
| 1 — 02:56:31 | `插件本体加载完毕 OK` | disabled by the user 16 s later |
| 2 — 04:21:46 | `插件本体加载完毕 OK` | left running |

The plug-in logs its own progress. In run 2 the sequence was:

```text
04:21:46.545  Configuration OK
04:21:48.134  NekoVerifierMain OK              <- the §3 gate
04:21:48.136  ConfigurationToSave OK
04:21:48.138  ImagePath OK
04:21:48.166  HACK初始化 OK                     <- "HACK initialisation"
04:21:48.168  窗口初始化 OK                      <- window init
04:21:48.173  指令初始化 OK                      <- command init
04:21:48.174  窗口绑定初始化 OK                  <- window binding init
04:21:48.179  NavmeshIPC OK
04:21:48.182  animLock OK / GameVersion OK
04:21:48.183  checkThread OK
04:21:48.189  localization OK / OnUpdate OK
04:21:48.200  LoadExtraConfig OK
04:21:48.200  [DtrBar] Adding entry: I-Ching-DISPLAY
04:21:48.203  解除窗口限制 OK                    <- window restriction removed
04:21:48.205  自启动 OK                          <- auto-start
04:21:48.205  插件本体加载完毕 OK                <- "plugin body finished loading"
04:22:00.147  DirectX11 Device captured successfully.
```

Two things follow. The shell's own `Configuration OK` and `NekoVerifierMain OK`
precede every payload line, which is what §3–§5 predict for a gate that runs before
the body exists. And the payload names its own stages, so the plug-in describes
itself: **the body is an auto-starting overlay that captures the DirectX 11 device
and removes window restrictions** — it does not rely on Dalamud's ImGui for its own
drawing.

`LoadExtraConfig` and the DTR entry fall on the other side of the first licence call
in run 1 than in run 2, so the order is not fully deterministic — consistent with
the `async` state machines §3 identified.

### 12.3 Licence checks are per account *and* per character (observed)

Both runs call the licence manager twice, with two different 128-bit identifiers,
account-level first:

```text
[I-Ching-GL] CheckLMState called with pluginId: 1019, playerId: <128-bit>, idType: 1
[I-Ching-GL] CheckLMState called with pluginId: 1019, playerId: <128-bit>, idType: 2
```

The identifiers are 39-digit decimal — 128-bit values, matching the `Hash128` route
§7 found in `IdentityProvider`. They are redacted here for the same reason the
plug-in ships a `Mask(value)` helper: they identify a machine, an account and a
character. `idType: 1` is account-scoped and `idType: 2` character-scoped — the
runtime counterpart of `VerifyEnvelope.AccountSid` and `CharacterCid` in §4. **§4's
inferred DTO semantics are therefore confirmed by behaviour**, not only by field
names.

### 12.4 File effects (observed)

Only two files were created in the whole observation window, both on the first run:

| Path | Bytes | Content |
| --- | --- | --- |
| `pluginConfigs\I-Ching-GL\UIConfig.json` | 80 | `{"Loc":"","Opacity":0.35,"Size":1.0,"X":0.0,"Y":0.0}` |
| `pluginConfigs\I-Ching-GL\targetInfo.json` | 2 | `[]` |

Two consequences. The overlay's position and opacity are persisted, which fits the
DirectX capture above. And **no unsealed assembly was written to disk** — nothing
else appeared anywhere under the Dalamud profile tree. Within that scope the
unsealing of §5 happens in memory, as the `AssemblyLoadContext` in §3 predicts.

The shape of these two files matters as well: a flat `Loc`/`Opacity`/`Size`/`X`/`Y`
record plus a target list. That is not the §5 package format — it is the payload's
own configuration, and its schema is independent evidence for what §8 hypothesises
the body to be.

### 12.5 Network (observed, with the limit stated)

`ffxiv_dx11` held established TCP :443 sessions to `162.159.130.234` and
`162.159.136.234` — Cloudflare anycast. The DNS client cache on the same host
carried many `region1.v2.argotunnel.com` / `region2.v2.argotunnel.com` entries,
i.e. Cloudflare Tunnel endpoints, whose purpose is to front an origin server
without exposing its address. One further name in the cache, `nazereth.top`,
resolves by CNAME to `<vendor-domain-redacted>` and on to Cloudflare addresses.

This is consistent with the `PreferredCloudflareHost` / `OriginServerHost` /
`FallbackServerUrl` fields §3 read out of the assembly, and it is what §5 requires:
the package secret can only arrive over the network.

**What is not established:** which of these names, if any, is the licence service.
The DNS cache is machine-wide, other applications on this host resolve names through
it, and no packet capture was taken — deliberately, since capturing the handshake
would mean handling the unwrapped package secret. The endpoint identity remains
*inferred*.

### 12.6 What this changes in §1–§11

| Section | Before | After §12 |
| --- | --- | --- |
| §8 | "Hypothesis, not established fact" that the DLL wraps AEAssist | **Observed.** Both runs unsealed a body that then wrote its own configuration |
| §4 | DTO field names; the two-call flow was inferred | Account- and character-scoped calls observed, matching `AccountSid` / `CharacterCid` |
| §7 | `Hash128` identity route read from metadata | Two 128-bit identifiers observed at the licence boundary |
| §5 | In-memory unsealing predicted from `AssemblyLoadContext` | No decrypted assembly on disk |
| §9.2 | "No runtime observation was performed" | Superseded by this section |

What does **not** change is §6. The payload is still not decrypted, and this section
contributes nothing towards decrypting it. Passing the gate demonstrates that an
entitlement was issued for this machine, account and character; it does not expose
key material, and none was sought.

### 12.7 Limits of this observation

Every line quoted above is the plug-in's *own* log output. That is evidence it
emitted those strings, and evidence of the ordering and timing of the stages it
reports — it is not an independent trace of what it did afterwards. This section
covers one host, one account and two sessions.

### 12.8 Reproducing this observation

```powershell
$log = "$env:APPDATA\XIVLauncher\dalamud.log"
# the plug-in's own lines
Select-String -LiteralPath $log -Pattern '\[I-Ching-GL\]'
# how it was loaded
Select-String -LiteralPath $log -Pattern 'Scanned dev plugin at|Loading I-Ching-GL'
# files it wrote
Get-ChildItem "$env:APPDATA\XIVLauncher\pluginConfigs\I-Ching-GL"
```

---

## 13. Metadata-level re-measurement (observed)

§9 left two questions open: what `A4444E08` is, and which protector produced this
file. This section re-measures both against the shipped bytes. It does not decrypt
the payload, and §6 is unchanged.

### 13.1 `A4444E08` exists nowhere, and nothing resolves it

`A4444E08` is an `AssemblyRef` at token `0x23000015`:

| Field | Value |
| --- | --- |
| version / culture | `0.0.0.0` / null |
| flags | `1` |
| public key or token | **none present** (`byte_length: 0`) |

`flags = 1` is the ECMA-335 `PublicKey` bit, which declares that this reference
carries the target's full public key. No key is present. The reference is
internally inconsistent before anything is loaded.

The four `ManifestResource` rows whose `implementation_token` is `0x23000015` —
`SirenAuth.Embedded.payload.siren`, `SirenAuth.Embedded.payload.json`, `C1F288B0`,
`51D5418C` — are all `embedded: false`, offset 0, no length. The only embedded
resource, `6A2D3E45`, has no implementation token at all.

Searched for a matching file under the analysis folder, the Dalamud profile tree,
Downloads, `Program Files (x86)` and `D:\`: **not present anywhere**. And §12 shows
the plug-in loading successfully from a folder holding only `I-Ching-GL.dll`,
`I-Ching-GL.deps.json` and `I-Ching-GL.json`.

*Inference.* `Assembly.GetManifestResourceStream("SirenAuth.Embedded.payload.siren")`
would have to load `A4444E08` and cannot. So the shell's `EmbeddedPayload.Open(name)`
does not go through that API; it reads by offset instead. The four rows are decoys of
the same family as the length prefix in §13.4 — the resource table is made to lie, so
that a reader which trusts it finds nothing.

*Unknown.* Whether `<Module>..cctor` rewrites the resource table in memory at
startup. It is the only body with readable IL, and that IL is control-flow flattened
(§2), so the file alone cannot settle it.

### 13.2 The body protection, measured rather than sampled

§2 described the encrypted bodies from three examples. Measuring all 998 methods with
a non-zero RVA gives a sharper result: **the first byte of every body is
statistically indistinguishable from a random draw.**

| First byte | Count | Share | If uniformly random |
| --- | ---: | ---: | ---: |
| tiny — `(b & 3) == 2` | 245 | 24.5 % | 25.0 % |
| fat — `(b & 3) == 3` | 265 | 26.6 % | 25.0 % |
| neither — `(b & 3) <= 1` | 488 | 48.9 % | 50.0 % |

Two further checks agree. The `Size` nibble of the 265 pseudo-fat headers is spread
across all 16 values (4.2 %–8.3 %, uniform expectation 6.3 %); real bodies would put
3 there almost without exception. And only 3 bodies begin with the canonical `0x02`
and 4 with `0x03`, against a chance expectation of 3.9 each.

Entropy says the same in one number. Sampling the first 32 bytes of all 998 bodies
gives **H = 7.9937 bits/byte**, against 6.1214 for the one genuine body and 1.4746
for the PE headers. The body region is indistinguishable from ciphertext.

**The one genuine body.** `<Module>..cctor` begins `13 30 06 00 32 09 00 00`:

| Field | Value |
| --- | --- |
| header word | `0x3013` — `Size = 3`, `Flags = 0x13` = `InitLocals \| FatFormat` |
| max stack | 6 |
| code size | `0x932` = 2,354 bytes, matching the IL §2 reports |

That is a well-formed fat header. It is also the exception the statistics predict:
of the 265 pseudo-fat headers, chance alone puts 21 at `Size = 3`, and one of those
carries real IL.

### 13.3 A stream name no other assembly on this host uses

The metadata root sits at file offset 9,601,280 (`BSJB`; metadata RVA `0x92A700`).
Parsing it directly yields five streams:

| Stream | Offset | Size |
| --- | ---: | ---: |
| `#-` | 108 | 56,016 |
| `#Strings` | 56,124 | 41,552 |
| `#US` | 97,676 | 84 |
| `#GUID` | 97,760 | 16 |
| `#Blob` | 97,776 | 11,296 |

**The metadata tables stream is named `#-`, the uncompressed form of ECMA-335
§II.24.2.1, not `#~`.** Five other assemblies on the same host — BouncyCastle,
ECommons, InteropGenerator.Runtime, System.Management and Dalamud — all use `#~`.
In this file `#~` occurs only as noise inside the 8 MB ciphertext region: 174
occurrences across the whole file, of which 2 fall in the ~110 KB metadata region,
which is what random bytes produce.

That is a concrete, checkable fingerprint. It is **not** an identification: naming a
product from one stream name would repeat the mistake §9.4 warns against. What can be
said is that the stream name, the body statistics and the decoy resource table are
all consistent with a protector that rewrites metadata, rather than one that emits
native stubs.

### 13.4 Two errors in earlier sections, corrected

Re-measuring caught two figures that were wrong as written.

**§6, the resource length prefix.** The four bytes at file offset 1024 — the prefix of
the CLI resources directory, RVA `0x2000`, recorded directory size 8,018,460 — are
`0C A2 90 A1`. As a signed 32-bit integer that is **-1,584,356,852**; as unsigned it
is **2,710,610,444** (`0xA190A20C`), which matches REA's `data_length` exactly. §6
printed the absolute value and dropped the sign, reporting `1,584,356,852` — a value
whose little-endian form `F4 4D 6F 5E` occurs nowhere in the file. The point §6 was
making is unchanged and slightly sharper: the declared length is 338× the real
payload.

**§2, the count of zero-width types.** §2 said "~150 types". Measured: 590 `TypeDef`s,
**555** carrying zero-width or bidi-control characters, 550 of those deriving from
`System.MulticastDelegate`. The characters used are U+200B–U+200F (zero-width spaces,
joiners, LRM/RLM marks) and U+202A–U+202E (bidi embedding and override controls).

A third figure was checked and **confirmed**: §2's body counts of 245 tiny, 265 fat
and 488 unreadable sum to the 2,102 `MethodDef` rows and reproduce exactly.

### 13.5 What is still open

1. **Which protector.** The fingerprints are now measured; the attribution is not.
   §9.4's candidate list stands, and there is no documented fingerprint table here to
   match against.
2. **What `A4444E08` was for**, as distinct from what it cannot do.
3. **Whether the resource table is rewritten at runtime** (§13.1).

None of these is answered by decrypting the payload, and this section does not
attempt it.

---

## 14. The blob read back out of a live process image (observed)

§13.5 asked whether the resource table is rewritten at runtime. This section answers
the *load-time* half of that question by reading the blob out of a running process
instead of out of the file. It uses the IG5 debug lane (`ig5_dbg`, x64dbg headless);
runtime addresses here are ASLR'd and are **not** the static database addresses of
§13.

### 14.1 Geometry established in the image

| Field | Value |
| --- | --- |
| Blob RVA | `0x2004` → VA = module base + `0x2004` |
| Runtime base (run 2) | `0x200EC540000` |
| Mapped size | 9,732,096 = `0x948000` = the file's `SizeOfImage` |
| Blob VA | `0x200EC542004`, exclusive end `0x200ECCE7A1C` |
| Decoy length prefix | RVA `0x2000` = `0x200EC542000` → `0c a2 90 a1` (2,710,610,444) |
| Enclosing section | RVA `0x2000`, vsize `0x8F75CC`, raw `0x400`/`0x8F7600`, read+execute |

The whole 8,018,456-byte blob is one contiguous, fully file-backed, readable region:
`Cor20 Resources` (RVA `0x2000`, size `0x7A5A1C`) is literally the 4-byte decoy
length followed by the blob, so blob length = `0x7A5A1C − 4` exactly — §13.4's
arithmetic, confirmed from the mapped image.

### 14.2 What came out of memory

Five windows were read with `op=readmem`, at module base + `0x2000`, `0x1BB68A`,
`0x1EB68A`, `0x3D4D10`, `0x7A79DC` (336 bytes of 8,018,456 = 0.0042 %):

| Window | Runtime VA | RVA | File offset | Result |
| --- | --- | --- | --- | --- |
| prefix + head (80 B) | `0x200EC542000` | `0x2000` | `0x400` | identical |
| interior (64 B) | `0x200EC6FB68A` | `0x1BB68A` | `0x1B9A8A` | identical |
| quarter (64 B) | `0x200EC72B68A` | `0x1EB68A` | `0x1E9A8A` | identical |
| half (64 B) | `0x200EC914D10` | `0x3D4D10` | `0x3D3110` | identical |
| tail (64 B) | `0x200ECCE79DC` | `0x7A79DC` | `0x7A5DDC` | identical |

"Identical" is SHA-256 equality between the memory window and the shipped bytes at the
same file offset, computed in `[internal]`.

*Inference.* Nothing in the mapped image differs from the file for the sampled
windows, so the resource table and the blob are **not** rewritten when the image is
mapped. §13.1's remaining possibility — that `<Module>..cctor` rewrites them — is
untouched by this section, because no CLR ever ran: the assembly is IL-only with
`AddressOfEntryPoint = 0`, and the debuggee only called `LoadLibraryW`.

*Limit.* 336 sampled bytes do not prove equality for the other 8,018,120.

### 14.3 The extraction bound, measured

`ig5_dbg` memory reads are capped at **4,096 bytes per request** — enforced in the
adapter and again in the bridge, and observed directly: an `8192`-byte request was
rejected with `memory read size must be 1..4096`. A complete pull of the 8,018,456
bytes would therefore need **1,958 requests**, and since each result returns the bytes
as a hex string that is ≈16 MB of tool output. Reading the whole blob out through
this lane is not a workable path; and because the mapped bytes are the shipped
ciphertext (§14.2), it would yield nothing that
`_analysis/out/resources/r04_6A2D3E45.bin`
(SHA-256 `6ed36e42d0758e74b338f343a4c4366eebee8fde59add80da592ffb60e4c5ef5`) does not
already contain.

The lane also cannot reach the one copy that *would* be new: it starts a PE, it has
no attach operation, so it cannot enter a running `ffxiv_dx11.exe` — which is the
only place §1's decrypted payload ever exists. §10 is unchanged: nothing here
decrypts anything.

### 14.4 How the pause was obtained (worth keeping)

x64dbg debugs a DLL through its own `loaddll.exe`, copied next to the target as
`DLLLoader64_<id>.exe`. That stub has no entry breakpoint to offer for a managed
assembly, and it exits immediately after `LoadLibraryW` returns, so a plain
`start` → `cont` loses the image after about a second (run 1: `i-ching-gl.dll` loaded
at `0x2126BD30000`, then `process-exited`, exit code 0). The deterministic pause was:

1. breakpoint at stub RVA `0x1121` — the single `call [LoadLibraryW]` in the stub,
   located in the bundled `loaddll.exe` (entry RVA `0x1710`, `SizeOfImage` `0x28000`,
   `LoadLibraryW` IAT slot RVA `0x16040`), all three matching what x64dbg reported for
   the running stub;
2. `cont` (hit count 1), then `stepover` the call.

Result: paused at stub RVA `0x1127` with `i-ching-gl.dll` mapped and the process
alive — the state §14.2 was read in. `stop` then released the task
(`process-exited`, state `no-task` confirmed).

### 14.5 Reproducing this section

```powershell
$py = "C:\Users\kyost\.dsh\plugins\dsh-infinite-gen-5\runtimes\x64dbg\python\python.exe"
& $py [internal]\blob_offset.py      # blob file offset 0x404 -> RVA 0x2004, section mapping
& $py [internal]\blob_windows.py     # expected SHA-256 of each sampled window
& $py [internal]\stub_callsite.py    # stub entry 0x1710, call [LoadLibraryW] at 0x1121
& $py [internal]\verify_windows.py   # all five windows MATCH; 1958 requests for a full pull
```

Debug-lane sequence per §14.4: `ig5_open I-Ching-GL.dll` → `op=load backend=x64dbg` →
`op=start` → `op=bpt ea=<mainModuleBase+0x1121>` → `op=cont` → `op=stepover` →
`op=readmem` at `<base+0x2000>`, `+0x1BB68A`, `+0x1EB68A`, `+0x3D4D10`, `+0x7A79DC` →
`op=stop`. The scratch scripts live in `[internal]` (gitignored).

---

## 15. Capture from a running process: the real container, its manifest, and the payload (observed)

§10 and §14 stopped short of recovering the payload. This section does recover it,
from the process that had already unwrapped it. **Basis:** the sample is used as a
**self-study research sample** and the whole exercise is **read-only throughout** —
nothing was written to the target, no code was injected, no thread was touched, no
licence or cryptographic logic was modified, no server response was forged, and the
payload was never executed. That is the standing recorded here.
**Method:** read-only — `OpenProcess(PROCESS_VM_READ)`, `VirtualQueryEx`,
`ReadProcessMemory` against `ffxiv_dx11.exe` (the §12 host, third run). Tooling:
`[internal]` (region sweep + PE/CLI validation),
`[internal]` (string beacons); all output under `[internal]*/`
(gitignored).

### 15.1 Correction to §13.1: `A4444E08` exists, and it carries the real package

`A4444E08` is not absent — it is the second-stage assembly, materialised at run time.
Its image was found in memory (three mapped copies, two distinct hashes):

| Field | Value |
| --- | --- |
| Image | 8,018,432 bytes, SHA-256 `497801f3757452af5a6b6260c2829fe6f3ed228e7a91a99e63d35bc62ff90e56` |
| Assembly / module | `A4444E08` v0.0.0.0 / `A4444E08.dll` |
| MVID | `b38262f2-1301-48a9-b275-26a88d2b518d` |
| Resources | `SirenAuth.Embedded.payload.siren` 7,966,208 B (entropy 8.000), `SirenAuth.Embedded.payload.json` 33,521 B, `C1F288B0` 8,136 B, `51D5418C` 8,808 B, all **embedded** and readable |

The shipped `6A2D3E45` blob is 8,018,456 B — exactly 24 B more than this image — and
the runtime-patched shell (§15.4) rewrites the resource directory to those two real
lengths, which is consistent with the blob being the ciphertext of `A4444E08`
(8,018,432 + 24 B of container overhead). *Inferred, not proven:* the in-place region
in the runtime image does not contain the plaintext (see §15.4).

### 15.2 The real manifest, in clear

`SirenAuth.Embedded.payload.json` is plaintext JSON — not one of §6's decoys:

```
packageId   I-Ching-GL-57d8fa51ff304fe0a1cdcb7b434c4b45
loaderKind  dalamud          entryType   null
chunkSize   65536            plainLength 7,966,208        chunks 122
cipherSha256     CB1895FB1E055A6A617741586D792510C13993C94F9B8A4B…
chunks[0]        index 0  cipherOffset 0  cipherLength 65536  nonce Zz2HPBT0TQKe+FBo  tag IXbRnSRVNXyuJkMVuYyoTw==
chunks[121]      index 121 cipherOffset 7,929,856  cipherLength 36,352
serverVerifyPublicKey    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE… (id-ecPublicKey / prime256v1, 124 chars)
serverExchangePublicKey  MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE… (id-ecPublicKey / prime256v1)
serverTlsPublicKeySha256 ""            ← empty: no pin value exists in this manifest (§4 inferred one)
serverUrl   https://<licence-endpoint-redacted>/   pluginName I-Ching-GL   windowTitle "Protected Plugin Loader"
```

Two corrections to earlier inference: the pin is **empty** (`ServerTlsPublicKeySha256`
is `""`, so the certificate callback is not enforcing a pin here) and the licence
endpoint is `<licence-endpoint-redacted>` — matching the DNS observation of §12.5. 122 × 65,536 +
36,352 = 7,966,208 = `plainLength`, with per-chunk nonce/tag/hash in the manifest, as §5
predicted from field names alone.

### 15.3 The payload, recovered

| Field | Value |
| --- | --- |
| Mapped at | `0x19D1E860000` and `0x19D5D830000` (MEM_MAPPED, pagefile-backed), byte-identical |
| Size | **7,966,208** = the manifest's `plainLength`, exactly |
| SHA-256 | `f60f7e6532e32c05256b86645278a46b75e746659bfc0a3cabdaca73d348ddad` |
| Assembly | `I-Ching-GL` **v0.1.6.6**, module `I-Ching-GL.dll`, MVID `3e33ca50-f644-4a34-9424-a939c4fec383`, ILOnly |
| References | Dalamud 15.0.3.2, Dalamud.Bindings.ImGui, FFXIVClientStructs 7.55.1.9192, ECommons 3.2.1.17, Lumina(+Excel), Newtonsoft.Json, TerraFX.Interop.Windows 10.0.26100.5, `D87F495C` |
| Metadata | types = 2,833, methods = 10,353 |
| **Bodies** | tiny 0, **fat 4,914, INVALID 0**, no-body 5,439, unreadable 0 |

Every method body is readable IL, so the payload itself is not body-encrypted —
the contrast with §2/§13.2 (shell: 488 INVALID, 748 unreadable) is the point. The
payload is a different protection profile wearing the same costume: its `#US` heap is
wiped to six zero-width strings plus `{0:X}`, twelve `ManifestResource` rows point at
the unresolvable `AssemblyRef D87F495C`, and it embeds one high-entropy resource
`D5958CAC` (142,360 B). The §12 log literals (`DirectX11 Device captured successfully.`,
`插件本体加载完毕 OK`, `I-Ching-DISPLAY`) are **not** in these bytes, so the payload's
own strings arrive from a resource at run time.

### 15.4 §13.5 #3 answered: the shell decrypts itself and rewrites its resource table in place

Two mapped copies of the shell-sized image (9,711,616 B) are live in the process:

| Copy | SHA-256 | Bodies |
| --- | --- | --- |
| `0x19CE79D0000` | `2417577af1bfcce7…` — byte-identical to the shipped file | tiny 245, fat 265, INVALID 488, unreadable 748 |
| `0x19CC94C0000` | `489017eb982e056d…` — 9,365,060 bytes differ | **tiny 0, fat 998, INVALID 0, unreadable 0** |

At the decoy entry, shipped `0c a2 90 a1` (2,710,610,444 = §13.4) becomes
`18 5a 7a 00` (`8,018,456`), followed in memory by `00 5a 7a 00` (`8,018,432`) and
`10 5a 7a 00` (`8,018,448`) — the real resource lengths. So the answer to §13.1's open
question is **yes**: `<Module>..cctor` runs, decrypts the shell's own 488 unreadable
method bodies in place, and rewrites the CLI resource directory at run time. The
shell's code is recoverable in full from memory (`carve_01_…bin`, assembly
`SirenAuth.I-Ching-GL`, same MVID `56e527a6-…` as the file).

*Open.* In that patched image the 8,018,432-byte region after the resource header is
high-entropy data equal to neither the shipped ciphertext nor the `A4444E08` image
(0.39 % byte agreement, i.e. chance). The layer-1 plaintext was therefore materialised
elsewhere, and the protected region was left holding something else. Mechanism
**unknown**; it is the one loose end in the chain.

### 15.5 What this does and does not establish

* Established: the shipped blob is the second-stage container, the manifest is
  readable and names the real endpoint and chunk plan, and both the shell (after
  self-decryption) and the payload (7,966,208 B of readable IL) can be recovered from
  a licensed process's memory.
* Not done, deliberately: no licence response was forged, no gate was patched, and no
  key material was extracted. The payload was readable only because a licensed session
  had already unwrapped it; the server-issued `WrappedKey` was never captured. §14's
  conclusion therefore stands unchanged — the shipped blob cannot be decrypted offline
  without the service.
* Artifacts (gitignored, not part of the repository): `[internal]…bin`
  (payload, 7,966,208 B), `carve_00_…bin` (`A4444E08`), `carve_01_…bin` (runtime shell),
  `dump_payload/` (payload inventory + `r12_D5958CAC.bin`), `dump_06/resources/`
  (`r01_…payload.json` = the clear manifest, `r00_…payload.siren` = the container
  ciphertext).

---

## 16. What the payload actually is (observed)

§15 recovered it; this section reads it. Method: `ig5_open` on the carve
(engine reverse: 0 native functions — IL-only, 4 segments, artifact `f60f7e65…`), the
project's own metadata dumper (`_analysis/dump`), and `ilspycmd` 11.1.0 decompiling the
whole assembly to `[internal]` (97 files, 20.6 MB of C#). Entity
lists in `[internal]{c,i,s,e,d}.txt`; full member/body inventory in
`[internal]`.

### 16.1 Shape

2,833 TypeDefs = **133 classes + 21 structs + 6 enums + 2 interfaces + 2,671 generated
delegates**. The delegate mass is the protector's proxy-call layer (five types carry
zero-width names), so only ~162 types are semantic — and those keep **readable names**,
unlike the shell. Entry type: `SamplePlugin.Plugin : IDalamudPlugin` (Dalamud's template
namespace), 94 methods; slash commands `/i-ching`, `-hack`, `-teleport`, `-motp`,
`-whereami`, `-rot`, `-commander`, `-targetsize`, `-modian`, `-mouse`, `-tpflag`.
Bodies: tiny 0, fat 4,914, INVALID 0 — all valid IL, but every body is control-flow
flattened (a plain `get_PluginInterface()` is 718 bytes of opaque-predicate arithmetic),
which is why §2's "unreadable" and this "flattened" are different failure modes.

### 16.2 Game-interaction surface (28 hook classes)

Hooks are installed with `HookFromAddress<T>` through Dalamud's `IGameInteropProvider`
and `ISigScanner`. The detour delegate names state the targets:

| Group | Hooks / detours | Implied effect |
| --- | --- | --- |
| Movement | `SendCombatMove`, `SendNormalMove`, `NoActionMove`, `NoBackswing`, `Speed`, `SpeedDelegate2`, `AntiKnock`, `YMove`, `MovePermission`, `FallCheck`, `NoFallDamage` | speed / position control, no knockback, no backswing, vertical movement, fall-damage removal |
| Combat | `ActionRange`, `ActorRadius`, `GetActionInRangeOrLoS`, `UseAction`, `GetRecastTime`, `SyncRecastTime`, `GetAdjustedCastTime`, `CastInfoUpdateTotal`, `NoBewitchAction`, `ActionInterceptor` | action range/radius, recast and cast-time manipulation, action interception |
| Detection / UI | `Raycast` + `RaycastFake`, `StatusCheck`, `ProcessPacketStatusEffectHookDelegateGL`, `InvulnerableMode`, `FakeFlyText` (HP/MP/EXP refresh), `NoSelectWhenTargetWithSpecificStatus`, `GrandHook` | raycast/status spoofing, fabricated UI numbers, targeting rules |
| PvP | `FrontlineRadar.RefreshEnemyActorsAndAutoSelect` + `DrawEspOverlay` (~22 KB IL each), `Plugin.PVPWhiteList` | enemy radar / ESP overlay |
| Network | `NetRe.SendPacketInternalDetour`, `BaguaDecryptor.Decrypt`, `NetRe+IGamePacket` | intercept outgoing packets, decrypt game packets |
| Assets | `AutoCancelFSHAnimationHook.GetResourceSync/AsyncDetour`, `ShouldRewritePath` | rewrite resource-path requests |
| Utility | `ExecuteCommand` / `ExecuteCommandInvoker` (`TryExecuteCommand`, `TryExecuteComplexLocation`), `SamplePlugin.IPC.NavmeshIPC` (`Pathfind`, `Rebuild`, `Execute…`, auto-load) | command/teleport primitive and navmesh pathing |

UI: `ConfigWindow` (2.6 MB C#), `ConfigWindow3`, `MainWindow`, and
`HookWindows.{CombatHack,MoveHack,FunctionHack,DevHack}Settings` — their `Draw` methods
are 30–99 KB of IL: the hack control panels. Bundled third-party code:
`CleanCapturePlugin.CleanBackgroundManager`.

### 16.3 The plug-in's own licence layer

`NekoVerifierLib` (12 types) is independent of `SirenAuth` (§4) and is what §12 saw as
`NekoVerifierMain OK`:

* `NekoVerifierMain.Init(pluginInterface, pluginName, pluginId, plugin)`, `RefreshAuth`
  (18 KB IL), `RefreshTokens`, `ShowExpirationNotification`; token state `Sid`,
  `Sid_token`, `Cid_token`, `Mid_token` with `*_ExpiredTime` — the account/character
  scope §12.3 observed;
* `VerifyClient.CheckLiveAsync` / `GetLMAsync` with packet structs `Pkt_Request`,
  `Pkt_Hello_Resp`, `Pkt_License_Resp` and enum `FuncCode` — the source of
  `CheckLMState(pluginId 1019, idType 1|2)`;
* crypto: bundled `OtpNet` (HOTP/TOTP — the `/i-ching-motp` command), `RSAsharp.RSA_PEM`
  / `RSA_Util` (RSA keys from PEM), `NekoVerifierLib.Fcrypt`, `Ids`.

### 16.4 Limits of this pass

* Names, signatures and structure are **read**; behaviour inside the flattened bodies is
  **not yet interpreted**. Every claim in §16.2 rests on class/method/delegate names plus
  the §12 runtime log, not on executed logic or clean decompilation.
* The payload's `#US` heap is wiped (6 zero-width entries) and its single embedded
  resource `D5958CAC` (142,360 B, entropy 7.998) is encrypted, so UI labels and chat
  text are not in the carve; they are materialised at run time (`I-Ching-GL.Res.Translate.json`).
* Twelve `ManifestResource` rows point at the absent `AssemblyRef D87F495C` — the same
  decoy pattern as the shell (§13.1).

---

## 17. Reading the logic: control-flow de-obfuscation of the payload

§16 named the parts; this section recovers what they *do*. The payload's bodies are
control-flow flattened, so the protector interleaves real statements with junk stores to
scratch locals behind opaque predicates whose operands are compile-time constants, e.g.

```
ldc.i4 1699590003; stloc.s 4; ldloc.s 4; ldc.i4 -1999305936; xor; brfalse IL_0000
ldloca.s 4; ldc.i4 -30911041; stind.i4
```

Nothing in those predicates depends on arguments, fields or calls, so abstract
interpretation that tracks constants through locals decides them exactly. `[internal]`
(Mono.Cecil 0.11.6, offline — no NuGet access was needed) implements that pass plus two
readers: an operand-level tracer and a return-value explorer.

### 17.1 The pass, and the three bugs that had to be fixed first

Per method: build basic blocks → constant-propagation fixpoint over block-entry states →
settle the edge set (every successor of a settled edge is entered) → resolve every
conditional branch whose condition is definitively constant → drop unreachable blocks →
rewrite the CFG, turning a resolved branch into `pop` (plus `br target` when taken) so the
IL stack stays balanced. Anything unprovable is left alone, and an unmodelled opcode skips
the method, so the transform only removes code it has proved dead.

| Artifact | Rewritten | Predicates resolved | Dead instructions removed | Bailed |
| --- | --- | --- | --- | --- |
| first (discarded) | 3,296 | 39,719 | 96,910 | 1,541 |
| second (discarded) | 1,176 | 15,649 | 37,841 | 3,661 |
| third (discarded) | 4,837 | 59,776 | 1,199,070 | 0 |
| fourth (discarded) | 4,837 | 86,604 | 207,770 | 0 |
| **current** | **4,837** | **87,032** | **208,095** | **0** |

Three defects had to be fixed, each caught by verification rather than by reading the code:

1. **Evaluation order.** The first version evaluated a branch's condition *after* the operand
   had been popped, so conditions were read from the wrong stack slot and predicates were
   "resolved" that were not earned.
2. **Settle phase.** A block can become reachable only once its predecessor's state has
   settled, because a condition that starts decidable can become undecidable after a merge
   and thereby gain a second edge. The second version seeded successors only during the first
   fixpoint, so such blocks were never entered, their successor sets stayed empty, and whole
   subtrees were removed as "unreachable" (exposed by an idempotence check: a second pass
   deleted another 1,130,632 instructions while resolving **zero** predicates).
3. **Arithmetic width.** IL `int32` arithmetic wraps at 32 bits; the model did every
   operation in 64 bits. That made shift and multiply results diverge from the CLR, so
   predicates were decided in the wrong direction and live code was pruned — the third
   artifact removed 1,199,070 instructions where the width-correct pass removes 207,770.
   Values now carry a width, shifts use `& 31` for `int32`, and unsigned compares and
   divisions mask to the operand width.

Verification of the current pass: re-running it on its own output changes nothing (pass 2
reports `changed=0, branchResolved=0, instrRemoved=0` — the transform reaches a fixpoint),
and hand checks reproduce the protector's own arithmetic. `NoBackswingHook..ctor` contains
`ldc.i4 -364177627; …; ldc.i4.s 31; and; shl; brfalse IL_0000`; the shift count is
`-364177627 & 31 = 5` and the shifted value is non-zero, so the branch is *not* taken — the
clean emits `pop` with no jump, matching the original's behaviour, and the junk loop head
disappears.

`deobf_clean.dll` (same MVID `3e33ca50-…`) is the artifact of the current pass — **for
reading, not execution**.

### 17.2 What the hooks actually do

The recipe is identical across the 28 hook classes (RecastHook, ActionInterceptor,
NoBackswingHook, GrandHook, …):

```
ISigScanner::ScanText(<pattern>)              // find the game function by signature
IGameInteropProvider::HookFromAddress(addr, <detour>, backend)
Hook<T>::Enable()   …  Dispose() -> Hook<T>::Disable()/Dispose()
```

Every detour then falls into one of two shapes:

* **forward and adjust** — call `Hook<T>::get_Original()` and modify its result:
  `UseActionDetour` and `ExecuteCommandDetour` (invoke the original delegate),
  `ActorRadiusDetour`, `GetRecastTimeDetour`, `SyncRecastTimeDetour`;
* **replace** — `NoBackswingDetour(Int64)` contains no call, field or string at all, so it
  never consults the original function: its computed return value *is* the game's new
  behaviour. The path-sensitive reader (§17.5) now recovers those values:

| Detour | Recovered behaviour |
| --- | --- |
| `NoBackswingHook::NoBackswingDetour(Int64 arg1)` | `returns arg1` — an identity function: the caller gets its own input back, so the game's backswing computation is neutralised rather than modified |
| `GrandHook::GrandDetour(Int64)` | `returns 17` |
| `AutoCancelFSHAnimationHook::ShouldRewritePath(uint*, byte*)` | `returns 1` — the resource-path rewrite is unconditional |
| `FallCheck::FallCheckDetour(Int64, Int64, Int64)` | `returns -1` |
| `InvulnerableMode::Enable(bool)` | `returns 0` |
| `MovePermission` detour's lambda `b__0(UInt32)` | `returns arg1 == Original(…)` — the permission decision is compared against the original function's answer |
| `ActorRadiusHook::ActorRadiusDetour(UInt64, Byte)` | hidden constant `0f` recovered from `BitConverter.GetBytes(0)`; the rest of the value flows from live actor state, so it stays `<unknown>` |

Each detour also consults its own `_configuration` (the `Configuration` instance stored by
the constructor) — that is the gate, and the gate names are §17.3.

### 17.3 The feature switchboard

`SamplePlugin.Configuration` carries 77 properties + 114 fields, and the names are the
feature list. Every feature has a paired `…AliveAble` flag:

| Feature flag | What it controls |
| --- | --- |
| `SirenSpeed`, `SirenSpeedValue`, `MaxAcceleration` | movement speed and acceleration |
| `SirenMovePermission`, `SirenAntiKnock`, `SirenNoFall`, `SirenY`(+`SirenyValue`), `SirenFallCheck` | movement permissions, knockback, fall damage, vertical flight, fall checks |
| `SirenActionRange`(+`Value`), `SirenActorRadius`(+`Value`), `SirenNoBackswing`, `SirenNoActionMove`(+`ActionMoveBlockList`, `NoActionMoveIsBlacklistMode`) | action range/radius, animation backswing, action-locked movement |
| `SirenDecRecast`(+`SirenMudraNoRecast`, `SirenDecRecastTime`), `SirenDecCast`(+`SirenDecCastTime`), `SirenCastMove`, `SirenCurrentCastTime` | recast and cast-time manipulation (mudra/NIN included) |
| `SirenCancelFSHAnimation`(+`…DisableWhenPlayersAround`, `LastCanceledFishingAnimation`) | cancels fishing animation, hidden when players are near |
| `SirenStatusCheck`, `SirenFuckBewithAction`, `SirenGrandCompany`, `PVP动画锁解限` | status effects, action interference, grand company, PvP animation-lock removal |
| `Executecommand`, `指令生成器*` (选中分类/选中指令/参数输入/生成结果/X·Y·Z坐标/数值输入/时间输入/距离输入/选择模式/布尔选择/Danger模式), `_isWaitingForUnstuckTeleport`, `_positionBeforeUnstuck`, `_targetTeleportPosition` | command execution, the command-generator UI, and teleport/unstuck state |
| `雷达是否运行`, `雷达探测距离`, `雷达是否连线`, `雷达是否绘制职业图标`, `雷达是否绘制战意`, `雷达关注列表` | the radar/ESP overlay: on/off, detection range, connecting lines, job icons, "battle will", watch list |
| `目标特定状态不选目标是否启动`, `不选目标的指定状态id` | auto-targeting avoidance driven by specific status IDs — the configuration side of the `StatusCheck` hook |
| `Sig自检`, `GameVersion`, `AutoBacktoG`, `你用日库了`, `我要网恋`, `UIConfig` | signature self-check, game-version marker, and assorted toggles/watermarks |
| `SpeedAddress`, `AntiKnockAddress`, `MovePermissionAddress`, `GrandCompany`, `ActionRange`, `ActorRadius`, `NoBackswing`, `NoActionMove`, `FuckBewithAction`, `StatusCheck`, `StatusCheckNTGL`, `FallCheckPatch`, `ExecuteCommandPatch`, `Flybase`, `OnSendFlag`, `OnSendNormalMove`, `OnSendCombatMove` | the scanned hook addresses and patches each detour installs, plus packet-send flags |

The `…AliveAble` pairing (checked alongside each feature) is the licence gate: which hacks
a given subscription may enable. Every feature listed above has one (`SirenSpeedAliveAble`,
`SirenNoBackswingAliveAble`, `SirenActorRadiusAliveAble`, …), and each hook also carries a
`…HookMessage` string — the message shown when the licence does not allow it.

### 17.4 The verifier's logic

`NekoVerifierLib` builds a machine/account fingerprint and validates time-boxed tokens:
`IPlayerState::get_ContentId()` (10 call sites in the current clean), `BattleChara::get_Name()`
/ `get_FreeCompanyTag()` / `get_IsLoaded()`, `TerritoryType::get_PlaceName()`,
`World::get_Name()`, `Environment::get_ProcessId()`, own `AssemblyName::get_Version()`, a
`IsValidSerialNumber(String serialNumber)` check, and an anonymous
`(SerialNumber, Size, Model)` triple; then `Convert::ToBase64String` (3 call sites),
`DateTime`/`DateTimeOffset` + `TimeSpan` (`get_Days`, `get_TotalDays`, `get_TotalSeconds`)
for expiry, with `OtpNet` (HOTP/TOTP) and `RSAsharp` (PEM RSA) bundled, and
`VerifyClient::CheckLiveAsync`/`GetLMAsync` over `Pkt_Request`, `Pkt_Hello_Resp`,
`Pkt_License_Resp`. That is the code behind §12's `CheckLMState(pluginId 1019, idType 1|2)`
— account-scoped (`ContentId`) versus character-scoped checks. §21 reads this layer out in
full and settles which of the two OTP modes is actually used: it is **HOTP** with a
Unix-time counter, and TOTP is present only as an unused class in the bundled library (§21.2).

### 17.5 What stays opaque, and what is still work in progress

The bodies remain flattened for every predicate the pass cannot prove, calls are routed
through the 2,671 generated delegate proxies, `#US` is still wiped and `D5958CAC` is still
encrypted. So signature patterns, chat/UI text and most middle-of-method constants are not
readable from the file; they materialise at run time. §17.2–17.4 rest on recovered
structure, gates and call sites — not on executing the plug-in.

The `returns` reader only decides a return value when it is a constant along every surviving
path; the path-sensitive `sym` reader goes further: `Configuration` reads and method
arguments become named symbols, undecided conditions fork the path, and each surviving path
is reported with the expression it returns. Four extensions were needed before it produced
anything for this payload:

* **delegate-proxy forwarding** — the payload never calls the hooked original directly, it
  calls a generated proxy that invokes the delegate, so a call whose resolved body contains
  an `Invoke` is modelled as `Original(…)`;
* **configuration by type** — a proxy that returns a field *of type* `Configuration` is
  modelled as `config`, not only fields declared *on* it;
* **floats** — radii and cast/range values are `Single`, so `float` constants, `conv.r4/r8`
  and float arithmetic/comparisons are modelled (they had been discarded as unknown);
* **the hidden-constant idiom** — this payload hides float constants as
  `BitConverter.ToSingle(BitConverter.GetBytes(k), 0)`, so that round-trip is folded to the
  float it encodes, and `Math::Max/Min` on a symbolic operand becomes `Max(a, b)` rather
  than unknown.

With those, `sym` recovers the replacement semantics in §17.2 (`returns arg1`, `returns 1`,
`returns -1`, `returns 17`) and one predicate: the `MovePermission` detour's lambda evaluates
`arg1 == Original(…)`. It also exposed a hidden constant inside `ActorRadiusDetour`
(`BitConverter.GetBytes(0)` → `0f`). Beyond that the forward-and-adjust detours stay
`<unknown>`, and the walk shows why: their values flow through pointer dereferences of live
game state (`*(float*)(actor + …)`) and through the hooked original's own return, which is
runtime data — so `<unknown>` is the correct outcome, not a gap in the reader.
`NekoVerifierLib`'s token logic is in the same position: its values come from HTTP responses
and clock reads.

Artifacts (gitignored): deobfuscator `[internal]` (modes `hist`, `copy`, `clean`,
`trace`, `returns`, `sym`); cleaned assembly `[internal]`; traces
`[internal]` (`hooks.txt`, `verifier.txt`, `ipc.txt`, `plugin.txt`, `ui.txt`,
`returns_*.txt`, `sym_*.txt`) regenerated from the current clean, alongside the
`*_clean.txt` / `returns_*2.txt` files left over from the discarded artifacts.

### 17.6 Independent cross-check of the whole pipeline

Everything above rests on my own Mono.Cecil tooling, so the payload was re-inspected with an
independent provider (REA's managed static analyzer, which never loads or executes the
assembly). The two agree exactly on identity and shape:

| Fact | My tooling | Independent inspection |
| --- | --- | --- |
| Payload sha256 | `f60f7e6532e32c05…` | `f60f7e6532e32c05256b86645278a46b75e746659bfc0a3cabdaca73d348ddad` |
| Assembly / version | `I-Ching-GL` v0.1.6.6 | `I-Ching-GL` v0.1.6.6 |
| MVID | `3e33ca50-f644-4a34-9424-a939c4fec383` | `3e33ca50-f644-4a34-9424-a939c4fec383` |
| Methods | 10,353 | `MethodDef` rows = 10,353 |
| Types | 133 classes + 21 structs + 6 enums + 2 interfaces + 2,671 delegates = 2,833 | `TypeDef` rows = 2,833 |
| Embedded resource | `D5958CAC`, 142,360 B | `D5958CAC`, private, 142,360 B, sha256 `7d545b087c0ebe89…` |

**Read that delegate row with §20.1**: the 2,671 generated delegates are not merely present —
**2,627 of them carry invisible (zero-width) names**, which is why a name-based reading of the
payload sees only the handful of readable hook delegates. The 555 invisible-named types counted
in §2 belong to the *shell*, a different assembly (§0).

The inspection also confirms the decoy mechanism independently: **all twelve** manifest
resources (`I-Ching-GL.Res.Translate.json`, `功能.png`, `战斗.png`, `更新日志.png`, `测试.png`,
`激活状态.png`, `移动.png`, `Shaders.AlphaFix.cso`, `HBlur.cso`, `VBlur.cso`, `E80586ED`,
`9C5412A1`) carry `implementation_token 0x2300001d` = `AssemblyRef D87F495C` with `flags=1`,
which is not shipped — so they resolve to nothing, and only `D5958CAC` is really embedded.

New facts from that pass, not visible in my own dumps:

* target framework `.NETCoreApp,Version=v10.0`, CLI runtime `2.5`, IL-only, no strong name,
  and a `SuppressIldasmAttribute` on the assembly (an anti-disassembly marker);
* the reference list names the fingerprinting surface: `System.Management` 9.0.0.2 (WMI) and
  `Microsoft.Win32.Registry` — concrete mechanisms behind the machine fingerprint in §17.4;
* graphics work is real: `Shaders.AlphaFix.cso`, `HBlur.cso`, `VBlur.cso` are bundled blur
  shaders, consistent with the ESP overlay (`FrontlineRadar`/`DrawEspOverlay`) in §16;
* runtime versions pinned by the plug-in: Dalamud 15.0.3.2, FFXIVClientStructs 7.55.1.9192,
  ECommons 3.2.1.17, Lumina, Newtonsoft.Json 13, TerraFX.Interop.Windows.

---

## 18. Where the wiped strings went (observed)

§17.5 left one question open: the `#US` heap is wiped, yet the plug-in clearly uses WMI query
strings, registry paths and messages. This section answers where those strings live and why
they are not readable from the shipped file.

### 18.1 The fingerprint code, in full

`NekoVerifierLib.Ids` is the machine-fingerprint class. Its shape (from the decompiled tree):

| Member | Role |
| --- | --- |
| `HardwareQueries` | `(string Query, string Property, bool UseFirstOnly)[3]` — the WMI query table |
| `GetHardwareInfo(query, property, useFirstOnly)` | runs one query and pulls one property |
| `GetBiosUuid()`, `GetCpuId()` | `ManagementObjectSearcher(text)` → `Get()` → `ManagementObjectEnumerator` → `ManagementBaseObject` |
| `GetSndId()`, `GetCID()`, `GetMID()`, `GetNekoMID()`, `GetOrGenerateLocalId()` | the individual identifiers |
| `GetHash(string, string salt)`, `GetHashWithSalt`, `GetSndIdHashWithSalt`, `GetCIDHashWithSalt`, `GetMIDHashWithSalt`, `GetNekoMIDHashWithSalt` | `UInt128` digests of those identifiers with a salt |
| `IsValidSerialNumber(string)`, `IsValidUuid(string)`, `InvalidSerialNumbers` | filters — a `HashSet<string>` of five rejected serials |
| `GetCommandLineArgsCore()`, `GetHexString(byte[])` | launch-argument capture and hex formatting |
| `<>f__AnonymousType1<SerialNumber, Size, Model>` | the disk projection (serial, size, model) behind the `Enumerable.Select` at `IL_1be1` |

The queries and property names are **not literals anywhere in the assembly**: the whole file
contains no `SELECT`, no `Win32_`, and no registry path (§18.2 shows why). `GetBiosUuid` and
`GetCpuId` take their query from a variable that a generated helper produces, and the
`HardwareQueries` table is filled from five such helpers in the static constructor.

### 18.2 Where the strings actually come from

A type whose **name is sixteen zero-width characters** (`U+202A U+200E U+200D U+200B …`)
holds **1,157 methods** — the string-reconstruction engine:

* one initializer with **15,651 instructions**, one `ldstr` of a zero-width-character string
  (the key), and calls to `Assembly::GetManifestResourceStream(String)`,
  `BinaryReader::.ctor(Stream)`, `Stream::Seek(Int64)` — it opens the embedded blob and reads
  from it at computed offsets;
* ~15 small methods (≈400 instructions each) returning `String`, each calling a shared helper
  and `Encoding::GetString(byte[])` — one decoded string apiece, i.e. one WMI query or one
  property name per method;
* further helpers returning `Byte[]` via `GetManifestResourceStream` and
  `Encoding::GetString(Encoding, Byte[])`.

So every wiped literal — WMI queries, registry paths, messages — is **reconstructed at run
time from an embedded blob**; `D5958CAC` (142,360 B, the only genuinely embedded resource,
§17.6) is the obvious candidate for that blob. This is also why a static reader cannot print
them: the value is not in the metadata at all, only the code that computes it.

That absence was checked against the raw file rather than the decompiler: across all
7,966,208 bytes there are **zero** occurrences of `SELECT`, `Win32_`, `HKEY`, `SOFTWARE\`,
`BIOS`, `BaseBoard`, `DiskDrive`, `ProcessorId` or `UUID` in either ASCII or UTF-16 (`SELECT`
and `Win32_` are absent from the decompiled tree as well). The only ASCII hits for
`ManagementObject` are the metadata type names.

### 18.3 The five `FieldRVA` arrays, decoded

The metadata carries five pre-initialized static arrays; three are tables, two are real
strings:

| Bytes | Decoded |
| --- | --- |
| 16 | four `int32`: 34675, 3573, 2262, 29513 — offsets/indices into the blob |
| 32 | `int32` `0x60 0x61 0x62 0x63` = `a b c` then 1001…1008 — an alphabet/offset table |
| 6 | UTF-16 `" \r\n"` — a trim character set |
| 22 | `vfx/path/nothing.avfx` — a real path string (FFXIV VFX asset) |
| 15 | `30 0D 06 09 2A 86 48 86 F7 0D 01 01 01 05 00` = DER `SEQUENCE(SEQUENCE(OID 1.2.840.113549.1.1.1 rsaEncryption, NULL))` — the RSA public-key header used by the licensing layer (§17.4) |

### 18.4 Method and limit

`[internal]` gained two modes for this: `hidden` (invisible-named types, their
`ldstr` operands and call targets, plus every `FieldRVA` array decoded as hex/ASCII/UTF-16)
and `arrays` (a path-following walk with an array/string model that reports the values
reaching calls and returns). The `arrays` walk is what established that the decoders' buffers
are **not** built from constants: each `newarr` length comes from a field or call, so the
bytes are read from the blob at run time — the walk records nothing because there is nothing
constant to record.

### 18.5 Following the decoders to their end (observed)

To finish the job the reader became a small concrete interpreter (`run` mode): it models
arrays, strings, `Encoding`, `BitConverter`, `Convert`, `StringBuilder`, a virtual
`Stream`/`BinaryReader` over the embedded blob, static and instance fields, and it recurses
into the assembly's own methods (depth-capped). Two obstacles were cleared on the way:

* the metadata reader types the embedded resource as **assembly-linked** and even resolves its
  name wrongly, so the blob is now read straight out of the PE (CLI header → `Resources`
  RVA/size → the `[length][bytes]` record). The bytes recovered are 142,360 long with sha256
  `7d545b087c0ebe89…`, matching the independent inspection in §17.6 — the right blob;
* the interpreter's own `GetManifestResourceStream` then serves those bytes.

Running the first decoder ends in a wall that is itself the answer:

```
-> <invisible helper>::()
-> IntPtr::op_Equality(?, ?)
-> Type::GetTypeFromHandle(?)
-> Marshal::GetDelegateForFunctionPointer(?, ?)
```

The decoding does **not** finish in managed code: the payload resolves a native export at run
time and calls it through a function-pointer delegate. The import table confirms the
mechanism — three `user32.dll` imports (`GetClassName`, `IsWindowVisible`, `IsWindow`) and
two `kernel32` imports (`GetModuleHandle`, `GetProcAddress`), with the last two declared under
empty method names. So the export's name is itself a runtime-built string, and the native
routine it resolves is what turns the blob into the WMI queries, registry paths and messages.

**Conclusion, and the boundary of static work:** those strings are not recoverable from the
shipped file by reading alone — the value does not exist in the artifact, only the code path
that computes it, and that path leaves managed code. Two honest options remain: observe a
licensed session (hook `GetDelegateForFunctionPointer`, or read the decoded strings from the
managed heap — the same capture method as §15), or execute the payload, which this
investigation does not do.

**§22 revises the last step of this chain**: `GetProcAddress` and `GetModuleHandle` are
declared here but **never called** anywhere in the payload, and the addresses that
`GetDelegateForFunctionPointer` receives come from signature scans (`ISigScanner::ScanText`,
`CompSig`). The most economical reading of this wall is that the decoder's native call is a
*game* function reached that way, not a Windows export — see §22.3.

The user32 trio is worth noting on its own: `GetClassName` + `IsWindow` + `IsWindowVisible`
is a window-identity/visibility check, consistent with gating the overlay on the game window's
state rather than on anything in-game.

---

## 19. The radar / ESP subsystem (observed)

The overlay is one class — `SamplePlugin.Hook.FrontlineRadar` — and it is the largest visible
feature in the payload. Its shape, from the decompiled tree and from traces of the cleaned
assembly:

| Member | Size | Role |
| --- | --- | --- |
| `.ctor(Plugin)` | 831 | wires the plugin, the object table and the configuration |
| `Enable()` | 659 | subscribes `DrawEspOverlay` to `IUiBuilder.Draw` and `RefreshEnemyActorsAndAutoSelect` to `IFramework.Update` |
| `Dispose()` | 697 | removes both handlers |
| `RefreshEnemyActorsAndAutoSelect(IFramework)` | 9,472 | builds the actor list and picks targets |
| `DrawEspOverlay()` | 9,764 | draws the overlay |
| `WorldToScreen(Vector3, Vector2&)` / `(…, out bool inView)` | 297 / 3,589 | world→screen projection |

### 19.1 What it reads

`IObjectTable::get_LocalPlayer`, and per object `IGameObject::get_ObjectKind`,
`get_GameObjectId`, `get_Name`, `get_Position`, plus `IGameObject::get_TargetObject` (and that
target's name — the overlay knows who is targeting whom). For characters it walks
`IBattleChara::get_StatusList`, reading `IStatus::get_StatusId` and `Status::get_Icon`, and it
resolves game data through `ExcelSheet<T>::GetRow(uint)` (Lumina) for the job/status tables.
Range comes from `Vector3.Distance(localPlayer.Position, obj.Position)`.

Status IDs are used twice over: to draw (icons) and to filter — the decompiled code compares
`StatusId` against constants (`if (statusId != …)`, `if (statusId == …)`), which is the code
behind the `目标特定状态不选目标是否启动` / `不选目标的指定状态id` settings in §17.3.

### 19.2 What it draws

Everything goes to `ImGui::GetBackgroundDrawList()`:

* `AddLine(v1, v2, colour, thickness)` — four call sites, and the thickness is one of the
  hidden constants: the decompiled form is `AddLine(vector27, vector28, num478,
  BitConverter.ToSingle(bytes33, startIndex32)`, i.e. the float is decoded inline from a byte
  array at run time;
* `AddText(position, colour, text)` — actor names;
* `AddCircleFilled(centre, radius, colour)` — two call sites;
* `AddImage(textureHandle, …)` — job icons, via `IDalamudTextureWrap::get_Handle()`;
* colours are packed with `ImGui::ColorConvertFloat4ToU32(Vector4)`.

Projection does not reimplement the camera: it takes `Control::Instance()` and
`Device::Instance()`, converts a `Matrix4x4` (the game's view-projection), reads
`ImGui::GetMainViewport()`'s `Pos`/`Size`, and uses `MathF::Abs` for the depth test — the
`inView` overload is what tells the caller whether the projected point is in front of the
camera.

### 19.3 The overlay's constants (observed)

The geometry and colours are hidden as `BitConverter.ToSingle(BitConverter.GetBytes(k), 0)`,
which is why they are invisible to a text search. Decoding every such site in the class gives
the complete constant set:

| Value | Sites | Reading |
| --- | --- | --- |
| `2` | 5 | line thickness (2 px) — the repeated drawing constant |
| `24`, `32` | 1 + 1 | icon box sizes |
| `20` | 3 | icon/circle size |
| `10` | 1 | text offset |
| `3` | 1 | a second thickness/highlight width |
| `1`, `0.5`, `0` | 9 + 3 + 10 | unit and clip-space values — `0.5` is the viewport centre and `1`/`0` the clip bounds in `WorldToScreen` |
| `0.699999988` | 2 | the alpha of the main colour |
| `1.40129846E-45` | 1 | the bit pattern `1` reinterpreted as a float — junk/decoy |

Colours, as `Vector4(r, g, b, a)` fed to `ImGui::ColorConvertFloat4ToU32`:

* `Vector4(0, 1, 0, 0.7)` — **green at 70 %**, used twice: the main ESP colour;
* `Vector4(1, 1, 0, 0.5)` — **yellow at 50 %**, used once: a secondary highlight.

So the overlay draws 2-pixel green lines at 70 % opacity with yellow highlights at 50 %, and
24–32-pixel icons — all with the game's own view-projection matrix, as §19.2 established.

The same scan over the whole `SamplePlugin` namespace resolves **1,458 constant sites**, so the
scheme is payload-wide rather than local to the radar. Its palette, as decoded:

| Colour | Reading |
| --- | --- |
| `Vector4(1, 0, 0, 1)` | red, opaque — hostile/enemy marker (4 sites) |
| `Vector4(0, 1, 0, 1)` and `(0, 1, 0, 0.7)` | green opaque and 70 % — friendly/ESP lines |
| `Vector4(1, 1, 0, 0.5)` | yellow 50 % — highlight |
| `Vector4(1, 1, 1, 1)`, `(1, 1, 1, 0.2)`, `(1, 1, 1, 0.1)` | white at full, 20 % and 10 % — text and fades |
| `Vector4(0.5, 0.5, 0.5, 1)` | grey — secondary text |
| `Vector4(0.1, 0.1, 0.1, 0.5)` | dark translucent — panel background |

### 19.4 Method note

Two tool defects had to be fixed before this worked, and both were found by the empty result
rather than by reading code: the scanner inspected the operand stack *after* the call had
consumed the arguments (so it read results instead of arguments), and it skipped every method
with exception handlers — which is precisely where the overlay's drawing loop lives. The
`bits` mode is now a linear sweep that reads arguments before `Exec`, tolerates handler
regions, and folds `GetBytes`/`ToSingle` and `Vector4`/`ColorConvertFloat4ToU32` in one pass;
it needs no branch following because the constant is computed immediately before the call that
consumes it.

---

## 20. The generator's scale, corrected, and the self-check engine

### 20.1 A correction to §16 and §17

§16 and §17 described "2,671 generated delegate proxy types" and, separately, "five
zero-width-named classes". The second number was a partial reading — an early dump was
truncated to thirty lines. The census, verified three ways (the `hidden` dump, a base-type
scan of the cleaned assembly, and the delegate entity list), is:

| Group | Count | Notes |
| --- | --- | --- |
| Delegate types | 2,671 | from the dumper's entity list |
| …of which invisible-named | 2,627 | all `System.MulticastDelegate`, 3 methods each |
| Invisible-named classes | 5 | plain `System.Object` helpers |
| **Invisible-named types, total** | **2,633** | 2,455 × 16 chars, 166 × 14, 10 × 12, 2 × 33 |
| Methods inside them | 9,057 | |
| Instructions inside them | 1,767,193 | |

So the generated proxies are not merely *present* — their **names are the zero-width
characters**, which is why a name-based reading sees only the few readable hook delegates
(`ExecuteCommandDelegate`, `UseActionDelegate`, …). The 133 classes + 2,671 delegates +
21 structs + 6 enums + 2 interfaces still sum to the 2,833 `TypeDef` rows exactly.

The five invisible-named classes are where the protector's own machinery lives:

| Class | Methods | Largest method | Role |
| --- | --- | --- | --- |
| A | 1,157 | 15,651 | the string-reconstruction engine (§18.2) — 493,154 instructions in total |
| B | 6 | 66,047 (73,393 before cleaning) | the self-check / bootstrap engine below |
| C | 5 | 16,221 | a second engine stage |
| D, E | 0–4 | small | stubs |

### 20.2 What the engine does

Class B's giant method calls, in the cleaned assembly, are only these:

```
Type::get_Module()              Module::get_FullyQualifiedName()
Marshal::GetHINSTANCE(Module)   String::get_Chars(Int32)
IntPtr::op_Explicit(IntPtr)     IntPtr::op_Explicit(Void*)
```

`Marshal.GetHINSTANCE(module)` returns the **base address of the plug-in's own loaded image**,
and `String.get_Chars` walks a string character by character. That is the shape of a
**self-check over the module's own bytes** — the mechanism behind the `Sig自检` ("signature
self-check") setting in §17.3 — with the two `op_Explicit` conversions turning the handle and a
`void*` back and forth to address the image. Class A's string methods and Class B's two
`Encoding::GetString(Byte[])` methods sit in the same cluster, so the strings of §18 are
reconstructed by code that also verifies the image it reads them from.

Everything else in those 66,047 instructions is the flattener's arithmetic and calls into the
invisible delegates, which is why a 66k-instruction method yields seven semantic call sites.

### 20.3 Workspace fix made on the way

All 34 trace files were UTF-16 (PowerShell's redirection chose that encoding), which silently
broke the Python-side greps while `Get-Content` kept working because it honours the BOM. They
are now UTF-8, and the raw text is unchanged — no conclusion in §15–§19 rests on the encoding.
The lesson is recorded because it cost a false "zero results" reading of the invisible-type
census.

---

## 21. The licence layer: transport, crypto and state (observed)

`NekoVerifierLib` is split in two: `NekoVerifierMain` owns state and scheduling,
`VerifyClient` owns transport, crypto and the async state machines. Field and method names are
metadata, so the protocol shape is readable even though every string value is runtime-built.

### 21.1 The wire protocol

| Message | Direction | Fields |
| --- | --- | --- |
| `Pkt_Request` | client → server | `nounce`, `funcCode`, `pluginId`, `idHash` (UInt128), `idType`, `nekoVersion`, `loadWay`, `gameLang`, `dalamudVersion`, `plugVersion`, `gameVersion`, `selfHash`, `message` |
| `Pkt_Hello_Resp` | server → client | `nounce` |
| `Pkt_License_Resp` | server → client | `nounce`, `status`, `pluginId`, `expiredTime`, `showExpiredTime`, `reverse`, `idHash`, `idType`, `nekoVersion` |

Field names alone would be misleading here, so every one of them was checked for real use at IL
level (`field` mode: which methods read, write or take the address of a field with that exact
name, anywhere in the assembly). Exact matching matters — the first pass matched substrings and
conflated `Pkt_License_Resp::reverse` with `BaguaDecryptor::reverseMapping`, and `status` with
unrelated names:

| Field | reads | writes | Access in managed IL |
| --- | --- | --- | --- |
| `nounce` | 3 | 2 | live — the nonce is echoed both ways |
| `funcCode` | 0 | 2 | written only — an outbound selector |
| `pluginId` | 3 | 3 | live |
| `idHash` | 1 | 2 | live — written when the request is built, read from the response |
| `idType` | 2 | 2 | live |
| `message` | 2 | 3 | live |
| `expiredTime`, `showExpiredTime` | 2, 1 | 0, 0 | read only — server-supplied |
| `nekoVersion`, `gameLang` | 0 | 2, 1 | written only |
| `loadWay`, `dalamudVersion`, `plugVersion`, `gameVersion`, `selfHash`, `status`, `reverse` | 0 | 0 | **no per-field access at all** |

So the request carries the nonce, the function code, the plug-in id, the `UInt128` fingerprint
(§17.4), the id type, the version constant, the game language and a message; the request
builder is the `MoveNext` of the two async state machines, which is where `idHash` is written.

**How strong is that negative?** Seven fields have no field-level access anywhere in the
assembly, which is what a name-based reading cannot tell you. §21.1's first draft went on to
suggest a bulk memory copy as the explanation, citing `Unsafe`; that citation was wrong — all
four `Unsafe` hits are `AsyncTaskMethodBuilder::AwaitUnsafeOnCompleted`, ordinary async
plumbing, and the `Span` hits are unrelated. No `Marshal.PtrToStructure`, `MemoryMarshal`,
`GCHandle`, `ldflda` or `initobj` appears either. So there is **no IL mechanism** that
populates these structs, yet `Pkt_License_Resp::expiredTime` *is* read (twice, in
`VerifyClient::CheckLMState`). The honest statement is therefore narrower than either earlier
draft: **the client never touches these fields in managed code, and whatever fills the response
struct does so outside IL** — which §22 identifies.

This corrects an earlier draft of this section, which inferred from the field name that
`selfHash` reported the client's own image hash to the server and that the version fields
supplied compatibility data. Both readings were plausible and neither is supported by access
sites. Names are metadata; only access sites are evidence.

### 21.2 Transport and cryptography

`VerifyClient` builds an `HttpClient` and posts Base64 bodies
(`Convert::ToBase64String(Byte[])` → `StringContent` → POST), timestamping with
`DateTimeOffset::get_Now()` → `ToUnixTimeSeconds()`. Its two crypto objects are fields:

* `OtpNet.Hotp hotp` — constructed from a byte-array secret, an `OtpHashMode` and a digit
  count, and then used as `Hotp.VerifyHotp(text, counter)` at two sites in the decompiled
  client. So the server proves itself with an **HOTP** whose counter comes from the Unix time
  above, not with a TOTP;
* `RSAsharp.RSA_Util rsa` — constructed from `RSA_PEM` and called twice with two strings each
  (a data/signature pair), once per response type. That is the **signature check on
  `Pkt_Hello_Resp` and `Pkt_License_Resp`**.

Both the HOTP secret and the PEM are assembled at run time, which is why the decompiled tree
contains no `BEGIN … KEY` literal anywhere.

### 21.3 State and scheduling

`NekoVerifierMain` keeps three token sets — `Sid`/`Sid_token`/`SID_ExpiredTime`,
`Cid_token`/`CID_ExpiredTime`, `Mid_token`/`MID_ExpiredTime` — with a refresh loop
(`RefreshTokens`, `RefreshAuth`), a login/logout hook (`ClientState_Login`,
`ClientState_Logout`) and a warning UI (`ShowExpirationNotification`, using
`DateTime::get_Now()` and `TimeSpan::get_TotalDays`/`get_TotalSeconds`). `VerifyClient` holds
the gate flags `S1E`, `S2E`, `S3F`, `S4E` and `Live`, and exposes
`CheckLMState(pluginId, playerId, idType, out expiredTime, msg)` plus `CheckState`,
`CheckState1…4`, `CheckStateAll` and `ResetState`. The `idType` of 1 or 2 seen in the §12 log
therefore selects which identity is being checked — account (`ContentId`) or character — and
each check can hand back its own expiry, which is what the `…AliveAble` per-feature flags of
§17.3 are ultimately driven by.

### 21.4 Limit

The flow is readable; the values are not. The server URL, the HOTP secret, the RSA public key
and every message string are built by the invisible-named engines of §18 and §20, so this
section describes the protocol, the crypto primitives and the state machine — not the server
or the keys. That boundary is the same one §18.5 established, reached from the other side.

### 21.5 Method note

The field audit exists because of a mistake worth keeping: §21.1 first asserted that `selfHash`
carried the self-check result to the server, purely because that is what the name implies. A
one-command check (`field selfHash` over the whole assembly) shows the field is never read or
written, and running the same check across the protocol found six more fields with no
field-level access. The `field` mode was added for this and reports reads, writes and
address-taken sites with their containing method, which is the cheapest way to turn a
name-based guess into a fact.

That mode then produced a second lesson in the same round: its first implementation matched
names as substrings, so `reverse` "had one write" that actually belonged to
`BaguaDecryptor::reverseMapping`, and `status` "had three accesses" that belonged to unrelated
names. It now matches exactly unless the query is prefixed with `~`, and every row above was
re-measured.

### 21.6 The engine classes cannot be interpreted to completion

§18.5 concluded that the string reconstruction leaves managed code. That conclusion was tested
from the other side this round: the concrete interpreter was pointed at the five invisible-named
**classes** (1,157 + 6 + 5 + 4 + 0 methods, i.e. everything except the 2,627 generated
delegates) and asked to run each method and report any non-empty string or byte array it
produced. Two interpreter defects were fixed first — the walker returned the flattened
dispatcher's trivial early `ret`, and it reported every method instead of only productive ones
— and the sweep still returns **nothing**. That is the expected result given §18.5 (the
decoders end in `Marshal.GetDelegateForFunctionPointer` after `GetModuleHandle` /
`GetProcAddress`), and it is now a measured negative rather than an assumption.

The `run` interpreter remains useful for what it can do — it reads the embedded blob, follows
recursion into the assembly's own methods, and models the BCL helpers — but it cannot stand in
for the native routine that finishes the job.

---

## 22. How the payload reaches native code (observed)

§18.5 ended at `Marshal::GetDelegateForFunctionPointer` and left the source of the pointer
open. This section closes it, and corrects one more of my own inferences on the way.

### 22.1 The imports are decoration

The assembly declares five P/Invokes — `user32!GetClassName`, `IsWindowVisible`, `IsWindow`
and `kernel32!GetModuleHandle`, `GetProcAddress` (§18.5) — but a call-site scan over the whole
assembly finds **zero calls** to `GetModuleHandle`, `GetProcAddress`, `LoadLibrary`,
`VirtualProtect`, `RtlDecompressBuffer` or `CryptStringToBinary`. The kernel32 pair is
declared and never used, which matches the empty method names the metadata showed for them.

### 22.2 The mechanism is delegate-over-function-pointer, fed by the plug-in's own signature table

`Marshal::GetDelegateForFunctionPointer` has at least ten call sites, and their owners name the
purpose:

| Caller | What it resolves |
| --- | --- |
| `CompSig::GetDelegate` | the generic path |
| `Plugin::SetScale` | a game function for scaling |
| `Plugin::MouseOverTargetButMostEnemy` | mouse-over targeting |
| `ExecuteCommandInvoker::EnsureExecuteCommand`, `EnsureComplexLocation` | the command invoker's targets |
| `ExecuteCommand::Execute` | command execution |
| `FrontlineRadar::.ctor` | the overlay's target |
| `ConfigWindow::DrawDevHackSettings`, `DevHackSettings::Draw` | the dev menu |
| one invisible-named type | the engine's own use |

`CompSig` is the key class, and it is a C# **record** carrying `Signature`, `SignatureCN` and
`IsClientCN`, with `Get()`, `TryGet(out signature)` and `TryGetValidSignature(out signature)`.
`IsClientCN` is decided by `IClientState::get_ClientLanguage()`, so every entry in the table
holds **two patterns — one for the international client and one for the Chinese client** — and
the right one is chosen at run time. That is the mechanism behind the plug-in's own
`你用日库了` ("you used the Japanese library") setting in §17.3.

So the addresses come from **byte-pattern scanning**, not from export lookup, and the pointers
are then wrapped into callable delegates. The signature strings themselves are runtime-built,
like every other string in this payload (§18.2), which is why nothing readable remains.

### 22.3 What this means for the decoder wall

The most economical reading of §18.5 is therefore that the decoders' native call is **not a
Windows API at all** but a game function reached through this same table — the plug-in using
the game's own code as a primitive. That would explain every observation at once: no
`GetProcAddress`, no export-name strings, a pointer that exists only at run time, and a
response struct (`Pkt_License_Resp`) whose fields are read but never written in IL (§21.1) —
because whatever fills them runs outside managed code.

It is a reading, not a proof: the decoder's specific target is not resolved in the trace, and
proving it needs a run-time observation. But it is the reading that requires no unexplained
mechanism, and it is consistent with the `selfHash`/version fields never being populated in IL.

### 22.4 Tooling

`calls <asm> <methodName>` was added (exact name match, reporting every calling type and
method, with invisible-named types collapsed to `<invisible>`), because the `field` mode's
counterpart for calls was missing. It produced the two facts that reshaped this section: the
kernel32 imports are unused, and the delegate construction is spread across the feature code
rather than concentrated in one loader.

---

## 23. The signature table and the command subsystem (observed)

### 23.1 Two resolution paths, both signature-driven

A call-site scan separates the payload's two ways of turning a pattern into a callable
function:

| Path | Used by | Sites |
| --- | --- | --- |
| `ISigScanner::ScanText(String)` → `Marshal::GetDelegateForFunctionPointer` | `Plugin`, `CompSig`, `ActionInterceptor`, `RecastHook`, `CastHook`, `ExecuteCommandInvoker`, `MySpeedHook`, `YMove`, `StatusCheck`, `NetRe` and others | **37** `ScanText` sites, 10 delegate wraps |
| the payload's own `CompSig` record | `ChatHelper::ProcessChatBoxSig`, `Ids::TestInstanceSig`, `NetRe::SendPacketInternalSig` | 3 entries |

The two sites per class are the international/Chinese pair of §22.2 — a class scans for one
pattern and falls back to the other depending on `IClientState::get_ClientLanguage()`. Only
three targets are wrapped in the payload's own `CompSig` record; everything else goes through
Dalamud's scanner. Either way the address is a **scan result**, which is why no export names
exist to recover.

### 23.2 The command subsystem

`ExecuteCommandInvoker` (static helper) and `ExecuteCommand` (instance wrapper) share one core:

```
EnsureExecuteCommand()      -> resolves the game's ExecuteCommand by signature, wraps it in a delegate
TryExecuteCommand(ExecuteCommandFlag flag, uint p1, uint p2, uint p3, uint p4)
EnsureComplexLocation()     -> the same for the variant that takes a position
TryExecuteComplexLocation(ExecuteCommandComplexFlag flag, Vector3 location, uint p1, …)
ExecuteCommand::Execute(int command, int p1, int p2, int p3, int p4)
```

These are the game client's own command interfaces, so the plug-in can drive the client exactly
as its UI does. The flags are enums in the assembly and their names are metadata — readable
even though every string is not:

* **`ExecuteCommandFlag` — 176 members.** Notable: `DrawOrSheatheWeapon`=1, `AutoAttack`=2,
  `Target`=3, `PVPQuickChat`=5, `Dismount`=101, `SummonPet`=102, `WithdrawPet`=103,
  `StatusOff`=104, `CancelCast`=105, `RidePillion`=106, `Revive`=200,
  `TerritoryTransport`=201, **`Teleport`=202**, `AcceptTeleportOffer`=203,
  `RequestFriendHouseTeleport`=210, `TeleportToFriendHouse`=211, `ReturnIfNotLalafell`=213,
  `InstantReturn`=214, `Inspect`=300, `ChangeTitle`=302, `ClearFieldMarkers`=313,
  `RequestWorldTravel`=316, `PlaceFieldMarker`=317, `RemoveFieldMarker`=318,
  `ResetStrikingDummy`=319, `DisableMounting`=612.
* **`ExecuteCommandComplexFlag` — 14 members.** `Dismount`=101, `DiveThrough`=209,
  `PlaceMarker`=301, `Emote`=500, `EmoteLocation`=501, `EmoteInterruptLocation`=504,
  `DiveEnd`=607, `PetAction`=1800, `BgcArmyAction`=1810.

This closes a loop with §17.3: the command-generator settings (`指令生成器X坐标/Y坐标/Z坐标`,
`数值输入`, `时间输入`, `选择模式`) are the UI for these calls, and the position-taking variant
is what makes `Teleport`=202 / `PlaceFieldMarker`=317 addressable with coordinates. Alongside
them sit the two other client interfaces the payload wraps: `ChatHelper::ProcessChatBoxSig`
for chat output and `NetRe::SendPacketInternalSig` for packet sending (§16).

### 23.3 Reading

Taken with §17–§22, the plug-in's shape is now consistent end to end: it scans the client for
the functions it wants (hook ones for behaviour changes, direct ones for commands and
packets), wraps them in delegates, and drives them from a configuration switchboard whose
per-feature flags are gated by a licence server. The strings, patterns and keys that would make
it portable are all reconstructed at run time by the engines of §18 and §20 — which is also why
the artifact yields its *structure* so completely and its *values* not at all.

### 23.4 What is not referenced, and why that is not the same as unused

A call-site scan reports **no static reference at all** — neither `call` nor `ldftn` — to
`ExecuteCommandInvoker::TryExecuteCommand`, `TryExecuteComplexLocation`,
`EnsureExecuteCommand` or `EnsureComplexLocation`, nor to `ExecuteCommandFlag`. Yet the
assembly does use reflection: `Type::GetMethod` (3 sites), `GetMethods` (1) and
`Delegate::CreateDelegate` (2). The most economical reading is that these members are bound by
name at run time — which would also explain why their names survive as metadata while their
*strings* do not matter. It is a reading, not a proof: nothing in this pass ties those three
`GetMethod` calls to these four methods specifically.

### 23.5 Method note

The first version of the `calls` scan counted only `call`/`callvirt` and therefore reported
"0 call sites" for methods that are plainly in use. This payload routes almost everything
through generated delegates, so `ldftn`/`ldvirtftn` (and `newobj` on delegate types) must be
counted too; the mode now labels call sites and delegate references separately. Re-running it
changed one earlier conclusion's *number* (`ScanText` is 37 sites, not 20) and left another
intact — `GetProcAddress` and `GetModuleHandle` are still at zero with delegate references
included, so §22.1's "the imports are decoration" survives the stricter test.

---

## 24. The reflection question, and the navigation the plug-in does not implement

### 24.1 Where the reflection actually is

§23.4 read the three `Type::GetMethod` sites as the plug-in binding its own methods by name.
Checking the call sites shows otherwise: **all three are inside the bundled RSAsharp library**,
in `RSA_Util::HashFromName`, `RSA_Util::__EncDec` and `RSA_Util::__SignVerify` — lookups of
hash-algorithm types by name, i.e. library internals. The two `Delegate::CreateDelegate` sites
are both in one invisible-named type, one of them on a `DynamicMethod` (a method generated at
run time), which is the protector's own machinery.

So the reading in §23.4 does not survive: nothing in the assembly binds
`ExecuteCommandInvoker::TryExecuteCommand`, `TryExecuteComplexLocation`,
`EnsureExecuteCommand` or `EnsureComplexLocation`. They have no `call`, no `ldftn`, no
`ldvirtftn` and no `newobj` reference, and the only reflection present is a crypto library's
internals plus one protector stub. The honest statement is that **these four methods are
statically unreferenced in this build** — most likely vestigial, with the live command path
being `ExecuteCommand::Execute` (which does carry a `GetDelegateForFunctionPointer` site). It
is still not a proof of deadness: Dalamud could reflect over the plug-in's public API, and the
protector's `DynamicMethod` stub is by definition invisible to a static reference scan.

### 24.2 Navigation is outsourced over IPC

`SamplePlugin.IPC.NavmeshIPC` is a client for an external navmesh plug-in, and its `Init()`
shows the whole surface: each capability is fetched with
`IDalamudPluginInterface::GetIpcSubscriber(String)` and stored as an
`ICallGateSubscriber<…>` static field. The channel names are runtime strings, but the
**subscriber signatures are metadata**, so what the plug-in asks for is readable:

| Subscriber field | Signature | Capability |
| --- | --- | --- |
| `_navIsReady` | `ICallGateSubscriber<bool>` | is the mesh ready |
| `_pathSetM…` | `ICallGateSubscriber<bool, object>` | allow/deny movement |
| `_pathIsRunning` | `ICallGateSubscriber<bool>` | is a path being followed |
| `_pathNumWaypoints` | `ICallGateSubscriber<int>` | waypoint count |
| `_pathGetMovementAllowed` | `ICallGateSubscriber<bool>` | read movement permission |
| `_navSetAutoLoad` | `ICallGateSubscriber<bool, object>` | auto-load the mesh |
| (unnamed) | `ICallGateSubscriber<Vector3, Vector3, bool, …>` | `Pathfind(from, to, fly)` |
| (unnamed) | `ICallGateSubscriber<Vector3, float, float, float, …>` | path with tolerances |
| (unnamed) | `ICallGateSubscriber<Vector3, float, float, Nullable<…>>` | nearest mesh point |

The public surface mirrors it: `IsEnabled`, `Init`, `IsReady`, `BuildProgress`, `Reload`,
`Rebuild`, `Pathfind(Vector3 from, Vector3 to, bool fly)`, `IsAutoLoad`, plus four
`Execute(Func<T>)` / `Execute(Action…)` overloads that marshal a call onto the right thread.

This closes another loop with §17.3: `_isWaitingForUnstuckTeleport`,
`_positionBeforeUnstuck` and `_targetTeleportPosition` are the teleport/unstuck state, and the
paths they need come from this IPC surface rather than from code in the plug-in. The movement
and teleport features therefore depend on a **second plug-in being installed**, which is a
dependency worth stating plainly.

### 24.3 Tool limitation found here

`calls` matches by method **name** only, so same-named methods in different types are
conflated: a scan for `Execute` returns 20 sites that are all `NavmeshIPC::Execute`, and
nothing from `ExecuteCommand::Execute`. This is why the round's first reading looked wrong, and
it is worth knowing when reading any count in §22–§24 — the totals are correct, but the
attribution must be read from the printed site lines rather than from the summary.

---

## 25. The two dependency tables

### 25.1 Every signature scan, by owner

`ScanText` has **37 call sites across 19 classes** — the complete list, which is the plug-in's
"what do I need from the client" inventory:

| Sites | Owner | Sites | Owner |
| --- | --- | --- | --- |
| 2 | `ExecuteCommandInvoker` | 1 | `RaycastFake` |
| 2 | `ActionInterceptor` | 1 | `Raycast` |
| 2 | `CastHook` | 1 | `ExecuteCommand` |
| 2 | `RecastHook` | 1 | `GrandHook` |
| 2 | `CompSig` | 1 | `FrontlineRadar` |
| 2 | `Plugin` | 1 | `DevHackSettings` |
| 1 | `MySpeedHook` | 1 | `MainWindow` |
| 1 | `ConfigWindow` | 1 | `ActionRangeHook` |
| 1 | `NoActionMoveHook` | 1 | `NoBackswingHook` |
| 1 | `ActorRadiusHook` | | |

The classes with two sites are the international/Chinese pattern pairs (§22.2); the singles are
either CN-only or single-pattern targets. Note that this list is the *direct* call path — the
hook classes of §17.2 reach the client through Dalamud's `IGameInteropProvider` instead.

### 25.2 The IPC surface, in two shapes

`SamplePlugin.IPC.NavmeshIPC` is a client for a pathfinding plug-in, and its capability names
survive in the compiler-generated lambda names even though the channel strings do not:

```
IsReady  BuildProgress  Reload  Rebuild  IsAutoLoad  IsRunning
NumWaypoints  GetMovementAllowed  GetAlignCamera  GetTolerance  PathfindInProgress
Pathfind(Vector3 from, Vector3 to, bool fly)
```

A **second client of the same shape** exists as an invisible-named class holding **21
`ICallGateSubscriber` fields**, each with an accessor method that returns it. Its signatures
are metadata and are the richer set:

| Signature | Capability |
| --- | --- |
| `ICallGateSubscriber<Vector3, Vector3, bool, Task<List<Vector3>>>` | pathfind, returning waypoints |
| `ICallGateSubscriber<List<Vector3>, bool, object>` | set a path |
| `ICallGateSubscriber<Vector3, bool, float, Vector3?>` | point query with tolerance |
| `ICallGateSubscriber<Vector3, float, float, Vector3?>` | nearest-point query |
| `ICallGateSubscriber<Vector3, float, float, Vector3?>` / `<float, object>` / `<float>` | tolerance read/write, progress |
| `ICallGateSubscriber<bool>`, `<int>`, `<object>` | state reads, waypoint count, misc |
| `ICallGateSubscriber<Vector3, bool, bool>` | a positional setter with two flags |

The channel **names** are runtime strings (§18.2), so this table gives the shape of the
dependency but not the IPC identifiers. What it does establish is that movement, pathfinding
and teleport in this plug-in are **delegated to another plug-in**, and that two independent
client implementations for that service are present in the assembly — one readable, one
renamed by the protector.

### 25.3 What these tables change

§17.2 listed the hooks and §17.3 the feature switchboard; these two tables complete the other
half of the picture — what the plug-in *asks the client for* (37 scans, 19 owners) and what it
*asks other plug-ins for* (two IPC clients). Neither table required anything beyond metadata:
the capability names and subscriber signatures survive, while the patterns, channel names and
keys do not.

---

## 26. The remaining subsystems

### 26.1 Range and line-of-sight are hooked

`Raycast` (6 methods) and `RaycastFake` (3 methods) are the action-legality hooks:

```
Raycast::RaycastDetour(IntPtr a1, …, Byte a5, UInt32 a6, IntPtr a7)                  [1312]
Raycast::GetActionInRangeOrLoSDetour(UInt32 actionId, IntPtr source, IntPtr target)  [332]
RaycastFake::GetActionInRangeOrLoSDetour(…)                                          [332]
```

`GetActionInRangeOrLoSDetour` hooks the client's "is this action in range and in line of
sight" test — the check that decides whether an action may be used on a target — and
`RaycastDetour` hooks the raycast itself. `RaycastFake` carries only the second of the two,
which is exactly what its name says: a variant that fakes the legality test without touching
the raycast. Both take a `Configuration` in their constructor, so the behaviour is gated by the
switchboard of §17.3.

### 26.2 The background blur is a compute-shader pipeline

`CleanCapturePlugin.CleanBackgroundManager` — note the **different namespace** from
`SamplePlugin`, so this is a reused component — is a 13-method D3D11 module:

| Method | Role |
| --- | --- |
| `.ctor(IPluginLog)`, `Initialize()`, `Dispose()` | lifetime |
| `UpdateDevice()` | takes the device from `FFXIVClientStructs…Kernel.Device::D3D11DeviceContext` |
| `LoadShaders()`, `LoadShaderFromResource(String)` | `Assembly::GetManifestResourceStream(String)` → `D3D11CreateComputeShader` |
| `CaptureAndBlur()`, `DrawBackground(Single opacity)` | the effect |
| `RunComputeShader(shader, input, output, width, height)` | dispatch |
| `ResizeResources(D3D11_TEXTURE2D_DESC)`, `GetDescSafe`, `DisposeTextures`, `Release(T*&)` | resource management |

Its fields name the three shaders it loads: **`_alphaFixShader`**, **`_blurHorizontalShader`**
and **`_blurVerticalShader`** — a separable two-pass blur with an alpha fix-up, run over the
game's back buffer through TerraFX DirectX bindings. The shader names are runtime strings and
the resource rows are the decoys of §16, so the `.cso` bytes are inside the blob like
everything else.

### 26.3 `CheckSig` is a game-module check, not a self-check

`CheckSig()` (14,036 instructions) calls **`ISigScanner::ScanModule(String)` 21 times** plus one
`ScanText`, and builds 16 report strings through `DefaultInterpolatedStringHandler`. Scanning
twenty-one *modules* is a compatibility sweep over the client's own code — the mechanism behind
the `Sig自检` setting in §17.3 — and it is a different thing from the protector's image check of
§20.2, which calls `Marshal.GetHINSTANCE` on the plug-in's own module. The payload therefore
has two unrelated "signature" mechanisms, and only one of them is about the plug-in itself.

### 26.4 The user interface is a first-class part of the payload

The largest methods in the `SamplePlugin` namespace are UI, not game logic:

| Instructions | Method |
| --- | --- |
| 42,487 / 16,346 / 11,966 | `Draw(Configuration, ConfigurationToSave, Plugin)` — three window implementations |
| 26,536 | `DrawFunctionHackSettings()` |
| 17,111 | `DrawMovableConfigWindowSettings()` |
| 15,992 | `DrawMoveHackSettings()` |
| 14,524 | `GenerateCommand(ValueTuple<…> selectedCommand)` — the `/i-ching` command generator |
| 12,067 | `DrawCommandGenerator()` |
| 11,899 | `DrawDevHackSettings()` |

The panels map one-to-one onto the feature groups of §17.3 (movement, function hacks, the
command generator, a developer menu), and the interface carries its own decorative effects —
`DrawGlowExternal`, `UpdateAndDrawClickRipples`, `UpdateAndDrawSnow` — which is why the payload
is 7.6 MB of IL: a branded UI, three blur shaders, a licence client, a signature table and
2,627 generated delegate types, all before any game logic.

The single largest method in the assembly, a 29,563-instruction `MoveNext`, belongs to
`SamplePlugin.Windows.MainWindow/<Draw>d__15` — the main window's async draw — and not, as its
size might suggest, to anything in the licence path. It is identified by name rather than
guessed: the trace's type header used to print only a length, and printing the sanitized name
settled it in one run.

---

## 27. What this artifact is

### 27.1 The chain

A Dalamud plug-in for FFXIV, shipped inside an encrypted container:

```
I-Ching-GL.dll (shell, SirenAuth.I-Ching-GL 1.0.0.0, 9,711,616 B)
  └─ 8,018,456 B encrypted blob
       └─ A4444E08.dll (runtime-decrypted, 8,018,432 B)
            ├─ payload.json  (manifest: packageId, loaderKind dalamud, 122 chunks, P-256 keys)
            └─ payload.siren (7,966,208 B)  →  I-Ching-GL 0.1.6.6, the real plug-in
```

The payload is obfuscated by a protector: **2,633 invisible-named types** (2,627 of them
generated delegates), every method body control-flow flattened with opaque predicates, a
wiped `#US` heap, decoy manifest-resource rows, and every string, pattern and key
**reconstructed at run time** by two invisible-named engines (§18, §20).

### 27.2 What it does

| Area | Evidence |
| --- | --- |
| Combat and movement hooks | `SpeedHook`, `AntiKnock`, `MovePermission`, `FallCheck`, `NoBackswing`, `ActionRange`, `ActorRadius`, `CastHook`, `RecastHook`, `GrandHook` (§17.2) |
| Range / line of sight | `Raycast::RaycastDetour`, `GetActionInRangeOrLoSDetour`, `RaycastFake` (§26.1) |
| Radar / ESP | `FrontlineRadar`: actor enumeration, status filters, `AddLine`/`AddImage`/`AddText`, 2 px green at 70 %, icons 24–32 px (§19) |
| Command generator | `/i-ching`, 176 `ExecuteCommandFlag` members incl. `Teleport`=202, plus a position-taking variant (§23) |
| Navigation | outsourced to another plug-in over IPC: two clients, 21-subscriber and 11-capability (§24.2, §25.2) |
| Background blur | `CleanCapturePlugin.CleanBackgroundManager`: three D3D11 compute shaders (§26.2) |
| Compatibility check | `CheckSig()`: `ScanModule` over 21 client modules (§26.3) |
| UI | three window implementations, panels up to 26,536 instructions, glow/ripples/snow (§26.4) |
| Licensing | `NekoVerifierLib`: `Pkt_Request`/`Pkt_License_Resp`, Base64 POSTs, HOTP verification, RSAsharp signature checks, three token sets (§21) |

### 27.3 How it reaches the client

Everything is address-based, never name-based: **37 `ScanText`** sites across 19 classes plus
**21 `ScanModule`** calls produce addresses that are wrapped with
`Marshal::GetDelegateForFunctionPointer`, and behaviour changes go through Dalamud's
`IGameInteropProvider`. `GetProcAddress` and `GetModuleHandle` are declared and never called
(§22.1) — a fact that survives counting delegate references as well as call sites (§23.5).

### 27.4 What is protected, and what is not

The artifact gives up its **structure** completely — types, methods, fields, enums, signatures,
subscriber shapes, hook names, feature flags — and its **values** not at all: the strings, the
signature patterns, the IPC channel names, the HOTP secret, the RSA key and the server URL are
all built at run time, with the decoding finishing in native code reached through a function
pointer (§18.5, §22.3). Static analysis can say what the plug-in asks for and how it asks;
recovering *what it asks with* needs a run-time observation of a licensed session.

### 27.5 Corrections made along the way

Recorded because they are the part of the work that was actually checked:

| # | Claim | What checking showed |
| --- | --- | --- |
| 1 | branch condition could be read after the operand pop | the evaluator was wrong; fixed, and the branch was then resolved correctly |
| 2 | blocks reachable only under settled states | the settle phase never seeded them, so live code was being deleted; caught by an idempotence run that removed 1,130,632 extra instructions with zero resolved branches |
| 3 | 32-bit arithmetic in 64-bit | shift/multiply divergence over-pruned; removals fell from 1,199,070 to 207,770 after the fix |
| 4 | `selfHash` reported the self-check to the server | the field is never read or written (§21.1) |
| 5 | the version fields supplied compatibility data | same — no field-level access at all (§21.1) |
| 6 | a bulk memory copy filled the packet structs | the `Unsafe` hits are async plumbing; no IL mechanism exists (§21.1, §22) |
| 7 | `reverse` and `status` had accesses | substring matching had conflated them with unrelated fields; exact matching re-measured everything (§21.5) |
| 8 | the plug-in bound its methods by reflection | the three `GetMethod` sites are RSAsharp internals (§24.1) |
| 9 | the four command methods were in use | no call or delegate reference exists; most likely vestigial, and stated as such rather than as deadness (§23.4, §24.1) |
| 10 | `CheckSig` was the plug-in's self-check | it scans 21 *client* modules; the protector's own image check is a different mechanism (§26.3) |

Ten corrections, each found by testing a claim instead of restating it. That is the reason the
sections above can be read as findings rather than as narrative.
