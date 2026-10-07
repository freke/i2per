-module(i2p_crypto).

-moduledoc """
Cryptographic primitives for the I2P ECIES-X25519 and Ed25519 crypto layers.

Provides the low-level building blocks used by the identity layer, NTCP2,
the ECIES session key manager, and tunnel build-record encryption:

- Ed25519 signing (sig type 7, pure RFC 8032).
- X25519 Diffie-Hellman (crypto type 4, RFC 7748).
- Elligator2 encoding/decoding of X25519 public keys (ECIES-X25519
  specification, [`Elligator2`](https://elligator.cr.yp.to/elligator-20130828.pdf)),
  so handshake ephemeral keys are indistinguishable from uniform random bytes.
- HKDF-SHA256 (RFC 5869), the Noise-style MixHash/MixKey primitives, and the
  pure key-derivation steps of the ECIES ratchets: `dh_initialize/2` (tag-set
  initialization), the session-tag chain, the symmetric-key chain, the DH
  ratchet tag-set KDF and the New Session Reply tag-set KDF.
- ChaCha20-Poly1305 AEAD (RFC 7539 section 2.8) in both split and sealed
  (ciphertext || tag) forms, with the New Session / New Session Reply zero
  nonce and the Existing Session counter nonce.
- Noise N pattern (`Noise_N_25519_ChaChaPoly_SHA256`) for ECIES tunnel build
  request record encryption (`f:noise_n_initialize/0`,
  `f:noise_n_encrypt/5`, `f:noise_n_decrypt/6`).
- Raw ChaCha20 stream cipher (`f:chacha20_crypt/3`) for iterative tunnel
  reply record layering.

Everything here is stateless; message framing, session state and the ratchet
state machines live in the ECIES session layer (`m:i2p_ecies`).

## Usage

```erlang
%% Ed25519 keys and signatures (sig type 7)
{Pub, Seed} = i2p_crypto:ed25519_keygen(),
Sig = i2p_crypto:ed25519_sign(Data, Seed),
true = i2p_crypto:ed25519_verify(Data, Sig, Pub).

%% X25519 keys and shared secrets (crypto type 4)
{APub, APriv} = i2p_crypto:x25519_keygen(),
{BPub, BPriv} = i2p_crypto:x25519_keygen(),
Shared = i2p_crypto:x25519_dh(APriv, BPub).

%% Elligator2-encoded ephemeral keys for New Session / New Session Reply
{Pub, Priv, Repr} = i2p_crypto:x25519_keygen_elg2(),
{ok, Pub} = i2p_crypto:elligator2_decode(Repr).

%% Noise initialization for the IK handshake
{H, Ck} = i2p_crypto:noise_initialize(),
H1 = i2p_crypto:mixhash(H, Pub),
{Ck1, K} = i2p_crypto:mixkey(Ck, SharedSecret).

%% A tag set for one direction of an Existing Session
Tagset = i2p_crypto:dh_initialize(Ck1, K),
#{next_root_key := RootKey, sess_tag_ck := TagCk, symm_key_ck := KeyCk} = Tagset.

%% AEAD sealing of a payload block
CT = i2p_crypto:chacha20_poly1305_seal(K, i2p_crypto:zero_nonce(), Payload, H),
{ok, Payload} = i2p_crypto:chacha20_poly1305_open(K, i2p_crypto:zero_nonce(), CT, H).
```

## Validation

The Ed25519, X25519, HKDF and ChaCha20-Poly1305 primitives are validated
against the published RFC 8032, RFC 7748, RFC 5869 and RFC 7539 test vectors;
Elligator2 is validated against the reference `Elligator2.java` vectors. The
ratchet KDFs are deterministic and preserve the documented state structure.
""".

-export([
    ed25519_keygen/0,
    ed25519_sign/2,
    ed25519_verify/3,
    x25519_keygen/0,
    x25519_public_key/1,
    x25519_dh/2,
    x25519_keygen_elg2/0,
    elligator2_encode/1,
    elligator2_encode/2,
    elligator2_encode/3,
    elligator2_decode/1,
    hkdf_sha256/4,
    mixhash/2,
    mixkey/2,
    noise_initialize/0,
    dh_initialize/2,
    session_tag_chain_init/1,
    session_tag_chain_step/2,
    symmetric_ratchet/1,
    dh_ratchet_tagset/2,
    session_reply_tagset/1,
    noise_n_initialize/0,
    noise_n_encrypt/5,
    noise_n_decrypt/6,
    chacha20_poly1305_encrypt/4,
    chacha20_poly1305_decrypt/5,
    chacha20_poly1305_seal/4,
    chacha20_poly1305_open/4,
    zero_nonce/0,
    es_nonce/1,
    chacha20_crypt/3,
    chacha20_crypt/4,
    aes256cbc_encrypt/3,
    aes256cbc_decrypt/3
]).
-export_type([
    data/0,
    x25519_public_key/0,
    x25519_private_key/0,
    ed25519_public_key/0,
    ed25519_seed/0,
    ed25519_signature/0,
    shared_secret/0,
    representative/0,
    key/0,
    nonce/0,
    tag/0,
    ciphertext/0,
    ciphertext_with_tag/0,
    ad/0,
    hash/0,
    chaining_key/0,
    salt/0,
    hkdf_ikm/0,
    hkdf_info/0,
    session_tag/0,
    tagset/0,
    aes_block/0,
    aes_iv/0,
    iv12/0
]).

-doc "An arbitrary byte string (plaintext, input data, etc.).".
-type data() :: binary().

-doc "A 32-byte X25519 public key, little endian (I2P crypto type 4).".
-type x25519_public_key() :: <<_:256>>.

-doc "A 32-byte X25519 private key, little endian (RFC 7748).".
-type x25519_private_key() :: <<_:256>>.

-doc "A 32-byte Ed25519 public key (I2P sig type 7, RFC 8032).".
-type ed25519_public_key() :: <<_:256>>.

-doc "A 32-byte Ed25519 private key seed (RFC 8032).".
-type ed25519_seed() :: <<_:256>>.

-doc "A 64-byte Ed25519 signature (RFC 8032).".
-type ed25519_signature() :: <<_:512>>.

-doc "A 32-byte X25519 shared secret, little endian.".
-type shared_secret() :: <<_:256>>.

-doc "A 32-byte Elligator2 representative (encoded X25519 public key).".
-type representative() :: <<_:256>>.

-doc "A 32-byte symmetric cipher key.".
-type key() :: <<_:256>>.

-doc "A 12-byte ChaCha20-Poly1305 nonce.".
-type nonce() :: <<_:96>>.

-doc "A 16-byte Poly1305 message authentication code.".
-type tag() :: <<_:128>>.

-doc "ChaCha20-Poly1305 ciphertext without the authentication tag.".
-type ciphertext() :: binary().

-doc "Sealed ciphertext with the 16-byte authentication tag appended.".
-type ciphertext_with_tag() :: binary().

-doc "Associated data authenticated by the AEAD (usually the Noise hash `h`).".
-type ad() :: binary().

-doc "A 32-byte SHA-256 digest (the Noise hash `h`).".
-type hash() :: <<_:256>>.

-doc "A 32-byte ratchet chain key.".
-type chaining_key() :: <<_:256>>.

-doc "HKDF salt. Empty is treated as 32 zero bytes (RFC 5869).".
-type salt() :: binary().

-doc "HKDF input key material.".
-type hkdf_ikm() :: binary().

-doc "HKDF info (context) string.".
-type hkdf_info() :: binary().

-doc "An 8-byte Existing Session tag.".
-type session_tag() :: <<_:64>>.

-doc """
A tag set derived by `dh_initialize/2` for one direction of a session.

- `next_root_key` — root key input for a subsequent DH ratchet.
- `sess_tag_ck` — chain key for the session-tag ratchet.
- `symm_key_ck` — chain key for the symmetric-key ratchet.
""".
-type tagset() :: #{
    next_root_key := chaining_key(),
    sess_tag_ck := chaining_key(),
    symm_key_ck := chaining_key()
}.

-doc "A 16-byte AES block (cipher/plaintext block, CBC-NO-PADDING).".
-type aes_block() :: <<_:128>>.

-doc "A 16-byte AES-CBC initialization vector.".
-type aes_iv() :: <<_:128>>.

-doc "A 12-byte raw ChaCha20 initialization vector (I2P tunnel reply record format).".
-type iv12() :: <<_:96>>.

-define(PROTOCOL_NAME, <<"Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256">>).
-define(NOISE_N_PROTOCOL_NAME, <<"Noise_N_25519_ChaChaPoly_SHA256">>).

-define(P, (1 bsl 255) - 19).
-define(P_PLUS_3_DIV_8, (((1 bsl 255) - 19) + 3) div 8).
-define(P_MINUS_1_DIV_2, (((1 bsl 255) - 19) - 1) div 2).
-define(P_MINUS_1_DIV_4, ((((1 bsl 255) - 19) - 1) div 2) div 2).
-define(SQRT_NEG_1_EXP, (((1 bsl 255) - 19) - 1) div 4).
-define(A, 486662).
-define(NEG_A, ((1 bsl 255) - 486681)).
-define(U, 2).
-define(INV_U, ((1 bsl 254) - 9)).

-doc """
Generate a fresh Ed25519 key pair.

Input: none.
Output: `{PublicKey, Seed}` — the 32-byte public key and 32-byte private key
seed (I2P sig type 7, pure RFC 8032 Ed25519).
""".
-spec ed25519_keygen() -> {ed25519_public_key(), ed25519_seed()}.
ed25519_keygen() ->
    {Pub, Seed} = crypto:generate_key(eddsa, ed25519, undefined),
    {Pub, Seed}.

-doc """
Sign `Data` with the Ed25519 private key `Seed`.

Input: `Data` — the bytes to sign (for I2P, usually a hash of the signed
object); `Seed` — a 32-byte Ed25519 private key seed.
Output: a 64-byte Ed25519 signature.
""".
-spec ed25519_sign(data(), ed25519_seed()) -> ed25519_signature().
ed25519_sign(Data, Seed) ->
    crypto:sign(eddsa, none, Data, [Seed, ed25519]).

-doc """
Verify the Ed25519 `Signature` over `Data` with `Pub`.

Input: `Data` — the signed bytes; `Signature` — a 64-byte signature;
`Pub` — a 32-byte public key.
Output: `true` if the signature verifies, `false` otherwise.
""".
-spec ed25519_verify(data(), ed25519_signature(), ed25519_public_key()) -> boolean().
ed25519_verify(Data, Signature, Pub) ->
    crypto:verify(eddsa, none, Data, Signature, [Pub, ed25519]).

-doc """
Generate a fresh X25519 key pair.

Input: none.
Output: `{PublicKey, PrivateKey}` — 32-byte little-endian keys
(I2P crypto type 4, RFC 7748).
""".
-spec x25519_keygen() -> {x25519_public_key(), x25519_private_key()}.
x25519_keygen() ->
    {Pub, Priv} = crypto:generate_key(ecdh, x25519, undefined),
    {Pub, Priv}.

-doc """
Derive the X25519 public key from the private key.

Input: `Priv` — a 32-byte X25519 private key.
Output: the corresponding 32-byte public key (scalar multiplication by the
RFC 7748 base point `u = 9`).
""".
-spec x25519_public_key(x25519_private_key()) -> x25519_public_key().
x25519_public_key(Priv) ->
    crypto:compute_key(ecdh, <<9, 0:248>>, Priv, x25519).

-doc """
Compute the X25519 shared secret.

Input: `Priv` — our 32-byte private key; `Pub` — the peer's 32-byte public key.
Output: the 32-byte shared secret. Callers MUST reject an all-zero result (an
all-zero output indicates a small-order public key; RFC 7748 contributory
behavior).
""".
-spec x25519_dh(x25519_private_key(), x25519_public_key()) -> shared_secret().
x25519_dh(Priv, Pub) ->
    crypto:compute_key(ecdh, Pub, Priv, x25519).

-doc """
Generate an X25519 key pair suitable for Elligator2 encoding.

Roughly half of all X25519 public keys cannot be Elligator2-encoded; this
function retries until a suitable key pair is found, so its runtime is
geometric. The returned representative uses a random `alternative` bit and
random high bits, ready for the wire.

Input: none.
Output: `{PublicKey, PrivateKey, Representative}`.
""".
-spec x25519_keygen_elg2() -> {x25519_public_key(), x25519_private_key(), representative()}.
x25519_keygen_elg2() ->
    {Pub, Priv} = x25519_keygen(),
    case elligator2_encode(Pub) of
        {ok, Repr} -> {Pub, Priv, Repr};
        error -> x25519_keygen_elg2()
    end.

-doc """
Elligator2-encode an X25519 public key (wire form).

The `alternative` bit and the two high bits of byte 31 are chosen at random,
so the output looks like 256 uniform random bits. Two out of eight possible
encodings of the same key require the `alternative` bit to match on decode;
because the bit is recoverable from the representative, round-tripping is
unambiguous.

Input: `Pub` — a 32-byte X25519 public key.
Output: `{ok, Representative}` or `error` if the key cannot be encoded.
""".
-spec elligator2_encode(x25519_public_key()) -> {ok, representative()} | error.
elligator2_encode(Pub) ->
    <<Rand>> = crypto:strong_rand_bytes(1),
    Alternative = (Rand band 1) =:= 0,
    elligator2_encode(Pub, Alternative, Rand).

-doc """
Elligator2-encode an X25519 public key with an explicit `alternative` bit.

The two high bits of byte 31 are set to zero. Intended for testing and for
callers that need to reproduce a specific encoding.

Input: `Pub` — a 32-byte X25519 public key; `Alternative` — the parity bit
that selects between the two encodings of the key.
Output: `{ok, Representative}` or `error` if the key cannot be encoded.
""".
-spec elligator2_encode(x25519_public_key(), boolean()) -> {ok, representative()} | error.
elligator2_encode(Pub, Alternative) ->
    elligator2_encode(Pub, Alternative, 0).

-doc """
Elligator2-encode an X25519 public key with full control over the high bits.

Input: `Pub` — a 32-byte X25519 public key; `Alternative` — the parity bit;
`HighBits` — a byte whose two most significant bits are ORed into byte 31 of
the representative.
Output: `{ok, Representative}` or `error` if the key cannot be encoded.
""".
-spec elligator2_encode(x25519_public_key(), boolean(), byte()) ->
    {ok, representative()} | error.
elligator2_encode(Pub, Alternative0, HighBits) ->
    X = little_int(Pub),
    Alternative =
        case X of
            0 -> false;
            _ -> Alternative0
        end,
    % v = -u*x*(x + A) (mod p), used for the Legendre test
    V = mod(-?U * X * (X + ?A), ?P),
    case legendre(V) of
        -1 ->
            error;
        _ ->
            case encode_r0(X, Alternative) of
                error ->
                    error;
                R0 ->
                    % r = sqrt(r/u) (mod p), least-representative root
                    R = square_root(mod(R0 * ?INV_U, ?P)),
                    Repr0 = little_bin32(R),
                    <<Rest:31/binary, Last>> = Repr0,
                    {ok, <<Rest/binary, (Last bor (HighBits band 16#c0))>>}
            end
    end.

%% r = -(x + A)/x (alternative) or -x/(x + A); error if the denominator is 0.
encode_r0(X, true) ->
    mod(mod(-(X + ?A), ?P) * mod_inv(X, ?P), ?P);
encode_r0(X, false) ->
    case mod(X + ?A, ?P) of
        0 -> error;
        XA -> mod(X * mod_inv(mod(-XA, ?P), ?P), ?P)
    end.

-doc """
Elligator2-decode a representative back into an X25519 public key.

The two high bits of byte 31 are masked out before decoding (the ENCODE
inverse).

Input: `Repr` — a 32-byte representative.
Output: `{ok, PublicKey}` or `error` if the representative is invalid
(about 10 of the 2^254 possible representatives fail).
""".
-spec elligator2_decode(representative()) -> {ok, x25519_public_key()} | error.
elligator2_decode(Repr) ->
    <<Rest:31/binary, Last>> = Repr,
    R = little_int(<<Rest/binary, (Last band 16#3f)>>),
    case R >= ?P_MINUS_1_DIV_2 of
        true ->
            error;
        false ->
            Denom = mod(1 + ?U * mod(R * R, ?P), ?P),
            case Denom of
                0 ->
                    error;
                _ ->
                    % v = -A / (1 + u*r^2) (mod p)
                    V = mod(?NEG_A * mod_inv(Denom, ?P), ?P),
                    % t = v^3 + A*v^2 + v = v^2*(v + A) + v (mod p)
                    T = mod(mod(V * V, ?P) * mod(V + ?A, ?P) + V, ?P),
                    E = legendre(T),
                    X =
                        case E of
                            1 -> V;
                            _ -> mod(?P - V - ?A, ?P)
                        end,
                    {ok, little_bin32(X)}
            end
    end.

-doc """
HKDF-SHA256 as specified in RFC 5869.

Input: `Salt` — HKDF salt (an empty salt is treated as 32 zero bytes, per
RFC 5869 section 2.2); `IKM` — input key material; `Info` — context string;
`Len` — output length in bytes.
Output: `Len` bytes of derived key material.
""".
-spec hkdf_sha256(salt(), hkdf_ikm(), hkdf_info(), pos_integer()) -> binary().
hkdf_sha256(Salt, IKM, Info, Len) ->
    Prk = hmac_sha256(Salt, IKM),
    expand(Prk, Info, Len, 1, <<>>, <<>>).

-doc """
Noise MixHash: `h = SHA256(h || data)`.

Input: `H` — the current chaining hash `h`; `Data` — the bytes to mix in.
Output: the updated 32-byte hash.
""".
-spec mixhash(hash(), data()) -> hash().
mixhash(H, Data) ->
    crypto:hash(sha256, <<H/binary, Data/binary>>).

-doc """
Noise MixKey: derive a fresh cipher key from the chaining key and a shared
secret.

`keydata = HKDF(Ck, DH, "", 64)`; the first 32 bytes become the new chaining
key and the last 32 bytes the cipher key `k` (the ECIES "es"/"ss" sections).

Input: `Ck` — the current chaining key; `DH` — an X25519 shared secret.
Output: `{Ck', K}` — the new chaining key and the 32-byte cipher key.
""".
-spec mixkey(chaining_key(), shared_secret()) -> {chaining_key(), key()}.
mixkey(Ck, DH) ->
    <<Ck2:32/binary, K:32/binary>> = hkdf_sha256(Ck, DH, <<>>, 64),
    {Ck2, K}.

-doc """
Noise initialization for the ECIES IK pattern, including the null prologue.

`h = SHA256(protocol_name)`, `ck = h`, then `h = SHA256(h)` (MixHash of the
empty prologue). `protocol_name` is the 40-byte
`"Noise_IKelg2+hs2_25519_ChaChaPoly_SHA256"`. Identical for both bound (IK)
and unbound (N) sessions, and precomputable by both peers for all
connections.

Input: none.
Output: `{H, Ck}` — the chaining hash and chaining key after the null
prologue.
""".
-spec noise_initialize() -> {hash(), chaining_key()}.
noise_initialize() ->
    H0 = crypto:hash(sha256, ?PROTOCOL_NAME),
    {crypto:hash(sha256, H0), H0}.

-doc """
DH ratchet / tag-set initialization (`DH_INITIALIZE(rootKey, k)`).

Creates a tag set for a single direction and the next root key for a
subsequent DH ratchet. Used to generate the New Session Reply tag set, the
two initial Existing Session tag sets, and each post-ratchet tag set.

`keydata = HKDF(RootKey, K, "KDFDHRatchetStep", 64)` then
`keydata = HKDF(ck, ZEROLEN, "TagAndKeyGenKeys", 64)`.

Input: `RootKey` — the root key (for the first tag sets, the New Session
payload chaining key); `K` — the tag-set seed (for the first tag sets, the
`k` from the handshake or Noise `split()`).
Output: a `t:tagset/0` map.
""".
-spec dh_initialize(chaining_key(), key()) -> tagset().
dh_initialize(RootKey, K) ->
    <<NextRootKey:32/binary, Ck:32/binary>> = hkdf_sha256(RootKey, K, <<"KDFDHRatchetStep">>, 64),
    <<SessTagCk:32/binary, SymmKeyCk:32/binary>> =
        hkdf_sha256(Ck, <<>>, <<"TagAndKeyGenKeys">>, 64),
    #{next_root_key => NextRootKey, sess_tag_ck => SessTagCk, symm_key_ck => SymmKeyCk}.

-doc """
Initialize a session-tag ratchet chain.

`keydata = HKDF(SessTagCk, ZEROLEN, "STInitialization", 64)`; the first 32
bytes become the chain key and the last 32 bytes the per-tag-set constant.

Input: `SessTagCk` — the `sess_tag_ck` from a `t:tagset/0`.
Output: `{ChainKey, Constant}` — the chain key and the `SESSTAG_CONSTANT`.
""".
-spec session_tag_chain_init(chaining_key()) -> {chaining_key(), key()}.
session_tag_chain_init(SessTagCk) ->
    <<ChainKey:32/binary, Constant:32/binary>> =
        hkdf_sha256(SessTagCk, <<>>, <<"STInitialization">>, 64),
    {ChainKey, Constant}.

-doc """
Advance a session-tag ratchet chain one step.

`keydata = HKDF(ChainKey, Constant, "SessionTagKeyGen", 64)`; the first 32
bytes become the next chain key and the first 8 bytes of the last 32 the
session tag.

Input: `ChainKey` — the current chain key; `Constant` — the tag-set constant
from `session_tag_chain_init/1`.
Output: `{ChainKey', Tag}` — the next chain key and the 8-byte session tag.
""".
-spec session_tag_chain_step(chaining_key(), key()) -> {chaining_key(), session_tag()}.
session_tag_chain_step(ChainKey, Constant) ->
    <<Next:32/binary, TagData:32/binary>> =
        hkdf_sha256(ChainKey, Constant, <<"SessionTagKeyGen">>, 64),
    <<Tag:8/binary, _/binary>> = TagData,
    {Next, Tag}.

-doc """
Advance the symmetric-key ratchet chain one step.

`keydata = HKDF(SymmKeyCk, ZEROLEN, "SymmetricRatchet", 64)`; the first 32
bytes become the next chain key and the last 32 bytes the symmetric key.

Input: `SymmKeyCk` — the current `symm_key_ck` chain key.
Output: `{ChainKey', K}` — the next chain key and the 32-byte session key.
""".
-spec symmetric_ratchet(chaining_key()) -> {chaining_key(), key()}.
symmetric_ratchet(SymmKeyCk) ->
    <<Next:32/binary, K:32/binary>> = hkdf_sha256(SymmKeyCk, <<>>, <<"SymmetricRatchet">>, 64),
    {Next, K}.

-doc """
DH ratchet tag-set KDF (`XDHRatchetTagSet`).

Derives a new single-direction tag set after new DH keys are exchanged in
Next Key blocks.

`tagsetKey = HKDF(SharedSecret, ZEROLEN, "XDHRatchetTagSet", 32)` then
`DH_INITIALIZE(RootKey, tagsetKey)`.

Input: `SharedSecret` — the DH result of the new ratchet keys; `RootKey` —
the `next_root_key` from the previous tag set in this direction.
Output: a `t:tagset/0` map for the new tag set.
""".
-spec dh_ratchet_tagset(shared_secret(), chaining_key()) -> tagset().
dh_ratchet_tagset(SharedSecret, RootKey) ->
    TagsetKey = hkdf_sha256(SharedSecret, <<>>, <<"XDHRatchetTagSet">>, 32),
    dh_initialize(RootKey, TagsetKey).

-doc """
New Session Reply tag-set KDF (`SessionReplyTags`).

`tagsetKey = HKDF(ChainKey, ZEROLEN, "SessionReplyTags", 32)` then
`DH_INITIALIZE(ChainKey, tagsetKey)`.

Input: `ChainKey` — the chaining key from the New Session message.
Output: a `t:tagset/0` map whose tags correlate the reply to the session.
""".
-spec session_reply_tagset(chaining_key()) -> tagset().
session_reply_tagset(ChainKey) ->
    TagsetKey = hkdf_sha256(ChainKey, <<>>, <<"SessionReplyTags">>, 32),
    dh_initialize(ChainKey, TagsetKey).

-doc """
Initialize the Noise N pattern (`Noise_N_25519_ChaChaPoly_SHA256`).

The protocol name is 31 bytes, so it is padded to 32 bytes (NOT hashed) per
the ECIES tunnel creation spec, then `ck = h`, then `h = SHA256(h)` for the
null prologue. Each build request record starts from this same state — there
is no cross-record chaining.

Input: none.
Output: `{H, Ck}` — the initial chaining hash and chaining key for one
build request record.
""".
-spec noise_n_initialize() -> {hash(), chaining_key()}.
noise_n_initialize() ->
    H0 = <<?NOISE_N_PROTOCOL_NAME/binary, 0>>,
    Ck = H0,
    {crypto:hash(sha256, H0), Ck}.

-doc """
Encrypt one ECIES tunnel build request record using the Noise N pattern.

Per the tunnel creation spec:
1. `h = SHA256(h || hepk)` — MixHash with receiver's full static X25519
   public key from its RouterIdentity.
2. `h = SHA256(h || sepk)` — MixHash with sender's ephemeral public key.
3. `sharedSecret = DH(sesk, hepk)`
4. `keydata = HKDF(ck, sharedSecret, "", 64)` → `ck' = keydata[0:31]`,
   `k = keydata[32:63]`
5. `ciphertext = ENCRYPT(k, 0, plaintext, h')` — ChaCha20-Poly1305 AEAD,
   nonce 0.
6. `h' = SHA256(h' || ciphertext || tag)` — MixHash with ciphertext + tag.

Each build request record is an independent Noise N session: callers start
from a fresh `noise_n_initialize/0` state per record.

Input: `EphPriv` — 32-byte ephemeral X25519 private key; `StaticPub` —
receiver's 32-byte static X25519 public key; `H` — the initial chaining hash;
`Ck` — the initial chaining key; `Plaintext` — the 154-byte short build
request record.
Output: `{Ciphertext, Tag, H', Ck'}` where Ciphertext matches the plaintext
size, Tag is 16 bytes, `H'` is the reply record's AEAD associated data and
`Ck'` feeds the reply/layer KDFs.
""".
-spec noise_n_encrypt(
    x25519_private_key(),
    x25519_public_key(),
    hash(),
    chaining_key(),
    data()
) -> {ciphertext(), tag(), hash(), chaining_key()}.
noise_n_encrypt(EphPriv, StaticPub, H, Ck, Plaintext) ->
    EphPub = x25519_public_key(EphPriv),
    H1 = mixhash(H, EphPub),
    SharedSecret = x25519_dh(EphPriv, StaticPub),
    {Ck1, K} = mixkey(Ck, SharedSecret),
    {CT, Tag} = chacha20_poly1305_encrypt(K, zero_nonce(), Plaintext, H1),
    H2 = mixhash(H1, <<CT/binary, Tag/binary>>),
    {CT, Tag, H2, Ck1}.

-doc """
Decrypt one ECIES tunnel build request record using the Noise N pattern.

Inverse of `f:noise_n_encrypt/5`. The receiver (the tunnel hop) uses its
static private key to DH with the sender's ephemeral public key, then
AEAD-decrypts and verifies.

Input: `StaticPriv` — receiver's 32-byte static X25519 private key;
`EphPub` — sender's 32-byte ephemeral X25519 public key; `H` — the initial
chaining hash (after MixHash of the receiver's full static public key);
`Ck` — the initial chaining key; `Ciphertext` — the encrypted record;
`Tag` — the 16-byte Poly1305 authentication tag.
Output: `{ok, Plaintext, H', Ck'}` on success, or the atom `error` if
authentication fails.
""".
-spec noise_n_decrypt(
    x25519_private_key(),
    x25519_public_key(),
    hash(),
    chaining_key(),
    ciphertext(),
    tag()
) -> {ok, data(), hash(), chaining_key()} | error.
noise_n_decrypt(StaticPriv, EphPub, H, Ck, Ciphertext, Tag) ->
    H1 = mixhash(H, EphPub),
    SharedSecret = x25519_dh(StaticPriv, EphPub),
    {Ck1, K} = mixkey(Ck, SharedSecret),
    Sealed = <<Ciphertext/binary, Tag/binary>>,
    case chacha20_poly1305_decrypt(K, zero_nonce(), Ciphertext, Tag, H1) of
        error ->
            error;
        Plaintext ->
            H2 = mixhash(H1, Sealed),
            {ok, Plaintext, H2, Ck1}
    end.

-doc """
Raw ChaCha20 stream cipher encryption/decryption (no authentication).

Used for the iterative reply record encryption in ECIES tunnel build replies:
the OBEP encrypts each reply record with ChaCha20 (stream cipher, not AEAD),
using the reply key and a 12-byte IV where `IV[4] = record_position`. The
counter portion of the OTP 16-byte IV is zeroed.

This is an XOR stream cipher, so decryption is the same operation.

Input: `Key` — a 32-byte ChaCha20 key; `IV12` — a 12-byte initialization
vector; `Data` — plaintext or ciphertext.
Output: the encrypted/decrypted data (same length as `Data`).
""".
-spec chacha20_crypt(key(), iv12(), data()) -> data().
chacha20_crypt(Key, IV12, Data) ->
    chacha20_crypt(Key, IV12, 0, Data).

-doc """
Raw ChaCha20 stream cipher with an explicit initial block counter.

The RFC 7539 state layout is `IV16 = counter32(little endian) || Nonce12`.
SSU2's header and ephemeral-key obfuscation runs the stream with a zero
nonce and the counter starting at one (`f:chacha20_crypt/3` fixes the
counter at zero for the ECIES reply-record layering).

This is an XOR stream cipher, so decryption is the same operation.

Input: `Key` — a 32-byte ChaCha20 key; `IV12` — a 12-byte nonce;
`Counter` — the initial 32-bit block counter; `Data` — plaintext or
ciphertext.
Output: the encrypted/decrypted data (same length as `Data`).
""".
-spec chacha20_crypt(key(), iv12(), non_neg_integer(), data()) -> data().
chacha20_crypt(Key, <<IV12:12/binary>>, Counter, Data) ->
    IV = <<Counter:32/little, IV12/binary>>,
    crypto:crypto_one_time(chacha20, Key, IV, Data, true).

-doc """
ChaCha20-Poly1305 AEAD encryption (RFC 7539 section 2.8).

Input: `Key` — a 32-byte key; `Nonce` — a 12-byte nonce; `Data` — plaintext;
`AD` — associated data (for NS/NSR messages the Noise hash `h`, for ES
messages the session tag).
Output: `{Ciphertext, Tag}` — ciphertext (same length as the plaintext) and
the 16-byte authentication tag.
""".
-spec chacha20_poly1305_encrypt(key(), nonce(), data(), ad()) ->
    {ciphertext(), tag()}.
chacha20_poly1305_encrypt(Key, Nonce, Data, AD) ->
    {Cipher, Tag} = crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, Data, AD, true),
    {Cipher, Tag}.

-doc """
ChaCha20-Poly1305 AEAD decryption.

Input: `Key` — a 32-byte key; `Nonce` — a 12-byte nonce; `Ciphertext` — the
ciphertext (without tag); `Tag` — the 16-byte authentication tag; `AD` — the
associated data.
Output: the plaintext, or the atom `error` if authentication fails.
""".
-spec chacha20_poly1305_decrypt(key(), nonce(), ciphertext(), tag(), ad()) ->
    data() | error.
chacha20_poly1305_decrypt(Key, Nonce, Ciphertext, Tag, AD) ->
    crypto:crypto_one_time_aead(chacha20_poly1305, Key, Nonce, Ciphertext, AD, Tag, false).

-doc """
Seal a payload: encrypt and append the authentication tag.

Input: `Key` — a 32-byte key; `Nonce` — a 12-byte nonce; `Data` — plaintext;
`AD` — associated data.
Output: `Ciphertext || Tag`, the wire format used by the ECIES message
sections.
""".
-spec chacha20_poly1305_seal(key(), nonce(), data(), ad()) -> ciphertext_with_tag().
chacha20_poly1305_seal(Key, Nonce, Data, AD) ->
    {Cipher, Tag} = chacha20_poly1305_encrypt(Key, Nonce, Data, AD),
    <<Cipher/binary, Tag/binary>>.

-doc """
Open a sealed payload: verify and decrypt `Ciphertext || Tag`.

Input: `Key` — a 32-byte key; `Nonce` — a 12-byte nonce; `Data` — the sealed
ciphertext with tag; `AD` — associated data.
Output: `{ok, Plaintext}` or the atom `error` if authentication fails.
""".
-spec chacha20_poly1305_open(key(), nonce(), ciphertext_with_tag(), ad()) ->
    {ok, data()} | error.
chacha20_poly1305_open(Key, Nonce, Data, AD) when byte_size(Data) >= 16 ->
    Sz = byte_size(Data) - 16,
    <<Cipher:Sz/binary, Tag:16/binary>> = Data,
    case chacha20_poly1305_decrypt(Key, Nonce, Cipher, Tag, AD) of
        error -> error;
        Plain -> {ok, Plain}
    end;
chacha20_poly1305_open(_Key, _Nonce, _Data, _AD) ->
    error.

-doc """
The zero nonce used for New Session and New Session Reply AEAD sections.

Input: none.
Output: 12 zero bytes.
""".
-spec zero_nonce() -> nonce().
zero_nonce() ->
    <<0:96>>.

-doc """
The Existing Session counter nonce for message number `N`.

The first 4 bytes are zero and the last 8 bytes are the message number in
little-endian order, so **the counter is 64 bits wide** and `N` runs
`0..2^64 - 2`.

That width is the specification's, not a choice this tree made. NTCP2 states
*"Last eight bytes are the counter, little-endian encoded. Maximum value is
2**64 - 2. Connection must be dropped and restarted after it reaches that
value. The value 2**64 - 1 must never be sent"*
([NTCP2](https://i2p.net/en/docs/specs/ntcp2/), "Authenticated Encryption"), and
the data phase *"n starts at 0 and increments for each frame in that
direction"* under one direction key for the life of the connection. There is no
rekey in NTCP2 and none is needed: a nonce under a fixed key is unique for as
long as the counter does not repeat, and an 8-byte little-endian field repeats
only after 2^64 increments.

The bound is enforced here rather than left to the caller, because the value the
spec says must never be sent is the one value this function exists to keep away
from the wire. Raising on it is the whole response: a counter that reached 2^64 -
1 is a defect in whatever increments it, not a condition to accommodate.

Input: `N` — the message number in the current chain, `0..2^64 - 2`.
Output: a 12-byte nonce.
""".
-spec es_nonce(0..16#FFFFFFFFFFFFFFFE) -> nonce().
es_nonce(N) when N >= 0, N =< 16#FFFFFFFFFFFFFFFE ->
    <<0:32, N:64/little-unsigned>>.

-doc """
AES-256-CBC encryption with no padding (CBC-NO-PADDING).

Used by the NTCP2 handshake to obfuscate the ephemeral keys in messages 1 and
2 (the Noise `aesobfse` modifier), so that they are indistinguishable from
random bytes to a passive observer.

Input: `Key` — a 32-byte AES-256 key; `IV` — a 16-byte initialization vector;
`Data` — plaintext whose length is a nonzero multiple of 16 bytes.
Output: the ciphertext (same length as `Data`).

No padding is applied: `Data` must already be block-aligned. IV chaining (the
last ciphertext block becoming the next message's IV) is the caller's
responsibility, as the NTCP2 spec chains the ephemerals as a single plaintext
stream.
""".
-spec aes256cbc_encrypt(key(), aes_iv(), binary()) -> binary().
aes256cbc_encrypt(Key, IV, Data) when
    byte_size(Key) =:= 32, byte_size(IV) =:= 16, byte_size(Data) rem 16 =:= 0
->
    crypto:crypto_one_time(aes_256_cbc, Key, IV, Data, true).

-doc """
AES-256-CBC decryption with no padding (CBC-NO-PADDING).

Inverse of `aes256cbc_encrypt/3`. Input: `Key` — a 32-byte AES-256 key; `IV` —
a 16-byte initialization vector; `Data` — ciphertext whose length is a nonzero
multiple of 16 bytes. Output: the plaintext (same length as `Data`).
""".
-spec aes256cbc_decrypt(key(), aes_iv(), binary()) -> binary().
aes256cbc_decrypt(Key, IV, Data) when
    byte_size(Key) =:= 32, byte_size(IV) =:= 16, byte_size(Data) rem 16 =:= 0
->
    crypto:crypto_one_time(aes_256_cbc, Key, IV, Data, false).

%%%%%%%
%%% Internal
%%%%%%%

expand(_Prk, _Info, Len, _N, _Prev, Acc) when byte_size(Acc) >= Len ->
    binary:part(Acc, 0, Len);
expand(Prk, Info, Len, N, Prev, Acc) ->
    T = hmac_sha256(Prk, <<Prev/binary, Info/binary, N>>),
    expand(Prk, Info, Len, N + 1, T, <<Acc/binary, T/binary>>).

hmac_sha256(Key, Data) ->
    crypto:mac(hmac, sha256, Key, Data).

%% x^((p+3)/8) (mod p), the square root that is in the lower half of the
%% field; if the input is not a square this returns a garbage root, so the
%% caller must have verified the Legendre symbol first.
square_root(X) ->
    T = mod_pow(X, ?P_MINUS_1_DIV_4, ?P),
    Result0 = mod_pow(X, ?P_PLUS_3_DIV_8, ?P),
    Result1 =
        case T + 1 =:= ?P of
            true -> mod(Result0 * sqrt_neg_1(), ?P);
            false -> Result0
        end,
    case Result1 > ?P_MINUS_1_DIV_2 of
        true -> mod(?P - Result1, ?P);
        false -> Result1
    end.

%% Legendre symbol of a (mod p), assuming 0 =< a < p: 1 if a is a nonzero
%% square, 0 if a = 0, -1 otherwise.
legendre(0) ->
    0;
legendre(A) ->
    case mod_pow(A, ?P_MINUS_1_DIV_2, ?P) of
        1 -> 1;
        _ -> -1
    end.

%% sqrt(-1) = 2^((p-1)/4) (mod p); cached after first computation.
sqrt_neg_1() ->
    case persistent_term:get({?MODULE, sqrt_neg_1}, undefined) of
        undefined ->
            V = mod_pow(2, ?SQRT_NEG_1_EXP, ?P),
            persistent_term:put({?MODULE, sqrt_neg_1}, V),
            V;
        V ->
            V
    end.

mod_pow(Base, Exp, Mod) ->
    binary:decode_unsigned(crypto:mod_pow(Base, Exp, Mod)).

%% Multiplicative inverse modulo the prime, by Fermat's little theorem.
%% Callers must not pass 0.
mod_inv(A, P) when A =/= 0 ->
    mod_pow(A, P - 2, P).

mod(X, P) ->
    (X rem P + P) rem P.

little_int(<<I:256/little-unsigned>>) ->
    I.

little_bin32(I) ->
    <<I:256/little-unsigned>>.
