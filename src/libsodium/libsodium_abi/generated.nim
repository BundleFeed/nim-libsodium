# Generated @ 2023-04-28T09:25:33+02:00
import std/os
const sodiumPath = currentSourcePath().parentDir() / "libsodium-stable"

# const 'SODIUM_EXPORT' has unsupported value '__attribute__ ((visibility ("default")))'
# const 'SODIUM_EXPORT_WEAK' has unsupported value 'SODIUM_EXPORT'
# const 'SODIUM_SIZE_MAX' has unsupported value 'SODIUM_MIN(UINT64_MAX, SIZE_MAX)'
# const 'crypto_aead_aes256gcm_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_aes256gcm_ABYTES, (16ULL * ((1ULL << 32) - 2ULL)))'
# const 'crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ietf_ABYTES, (64ULL * ((1ULL << 32) - 1ULL)))'
# const 'crypto_aead_chacha20poly1305_MESSAGEBYTES_MAX' has unsupported value '(SODIUM_SIZE_MAX - crypto_aead_chacha20poly1305_ABYTES)'
# const 'crypto_aead_chacha20poly1305_IETF_KEYBYTES' has unsupported value 'crypto_aead_chacha20poly1305_ietf_KEYBYTES'
# const 'crypto_aead_chacha20poly1305_IETF_NSECBYTES' has unsupported value 'crypto_aead_chacha20poly1305_ietf_NSECBYTES'
# const 'crypto_aead_chacha20poly1305_IETF_NPUBBYTES' has unsupported value 'crypto_aead_chacha20poly1305_ietf_NPUBBYTES'
# const 'crypto_aead_chacha20poly1305_IETF_ABYTES' has unsupported value 'crypto_aead_chacha20poly1305_ietf_ABYTES'
# const 'crypto_aead_chacha20poly1305_IETF_MESSAGEBYTES_MAX' has unsupported value 'crypto_aead_chacha20poly1305_ietf_MESSAGEBYTES_MAX'
# const 'crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX' has unsupported value '(SODIUM_SIZE_MAX - crypto_aead_xchacha20poly1305_ietf_ABYTES)'
# const 'crypto_aead_xchacha20poly1305_IETF_KEYBYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES'
# const 'crypto_aead_xchacha20poly1305_IETF_NSECBYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_NSECBYTES'
# const 'crypto_aead_xchacha20poly1305_IETF_NPUBBYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES'
# const 'crypto_aead_xchacha20poly1305_IETF_ABYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_ABYTES'
# const 'crypto_aead_xchacha20poly1305_IETF_MESSAGEBYTES_MAX' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_MESSAGEBYTES_MAX'
# const 'crypto_auth_BYTES' has unsupported value 'crypto_auth_hmacsha512256_BYTES'
# const 'crypto_auth_KEYBYTES' has unsupported value 'crypto_auth_hmacsha512256_KEYBYTES'
# const 'crypto_stream_xsalsa20_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX' has unsupported value '(crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_box_curve25519xsalsa20poly1305_MACBYTES)'
# const 'crypto_box_SEEDBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_SEEDBYTES'
# const 'crypto_box_PUBLICKEYBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES'
# const 'crypto_box_SECRETKEYBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES'
# const 'crypto_box_NONCEBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_NONCEBYTES'
# const 'crypto_box_MACBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_MACBYTES'
# const 'crypto_box_MESSAGEBYTES_MAX' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_MESSAGEBYTES_MAX'
# const 'crypto_box_BEFORENMBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES'
# const 'crypto_box_SEALBYTES' has unsupported value '(crypto_box_PUBLICKEYBYTES + crypto_box_MACBYTES)'
# const 'crypto_box_ZEROBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_ZEROBYTES'
# const 'crypto_box_BOXZEROBYTES' has unsupported value 'crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES'
# const 'crypto_generichash_BYTES_MIN' has unsupported value 'crypto_generichash_blake2b_BYTES_MIN'
# const 'crypto_generichash_BYTES_MAX' has unsupported value 'crypto_generichash_blake2b_BYTES_MAX'
# const 'crypto_generichash_BYTES' has unsupported value 'crypto_generichash_blake2b_BYTES'
# const 'crypto_generichash_KEYBYTES_MIN' has unsupported value 'crypto_generichash_blake2b_KEYBYTES_MIN'
# const 'crypto_generichash_KEYBYTES_MAX' has unsupported value 'crypto_generichash_blake2b_KEYBYTES_MAX'
# const 'crypto_generichash_KEYBYTES' has unsupported value 'crypto_generichash_blake2b_KEYBYTES'
# const 'crypto_hash_BYTES' has unsupported value 'crypto_hash_sha512_BYTES'
# const 'crypto_kdf_BYTES_MIN' has unsupported value 'crypto_kdf_blake2b_BYTES_MIN'
# const 'crypto_kdf_BYTES_MAX' has unsupported value 'crypto_kdf_blake2b_BYTES_MAX'
# const 'crypto_kdf_CONTEXTBYTES' has unsupported value 'crypto_kdf_blake2b_CONTEXTBYTES'
# const 'crypto_kdf_KEYBYTES' has unsupported value 'crypto_kdf_blake2b_KEYBYTES'
# const 'crypto_onetimeauth_BYTES' has unsupported value 'crypto_onetimeauth_poly1305_BYTES'
# const 'crypto_onetimeauth_KEYBYTES' has unsupported value 'crypto_onetimeauth_poly1305_KEYBYTES'
# const 'crypto_pwhash_argon2i_BYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX, 4294967295U)'
# const 'crypto_pwhash_argon2i_MEMLIMIT_MAX' has unsupported value '((SIZE_MAX >= 4398046510080U) ? 4398046510080U : (SIZE_MAX >= 2147483648U) ? 2147483648U : 32768U)'
# const 'crypto_pwhash_argon2id_BYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX, 4294967295U)'
# const 'crypto_pwhash_argon2id_MEMLIMIT_MAX' has unsupported value '((SIZE_MAX >= 4398046510080U) ? 4398046510080U : (SIZE_MAX >= 2147483648U) ? 2147483648U : 32768U)'
# const 'crypto_pwhash_ALG_ARGON2I13' has unsupported value 'crypto_pwhash_argon2i_ALG_ARGON2I13'
# const 'crypto_pwhash_ALG_ARGON2ID13' has unsupported value 'crypto_pwhash_argon2id_ALG_ARGON2ID13'
# const 'crypto_pwhash_ALG_DEFAULT' has unsupported value 'crypto_pwhash_ALG_ARGON2ID13'
# const 'crypto_pwhash_BYTES_MIN' has unsupported value 'crypto_pwhash_argon2id_BYTES_MIN'
# const 'crypto_pwhash_BYTES_MAX' has unsupported value 'crypto_pwhash_argon2id_BYTES_MAX'
# const 'crypto_pwhash_PASSWD_MIN' has unsupported value 'crypto_pwhash_argon2id_PASSWD_MIN'
# const 'crypto_pwhash_PASSWD_MAX' has unsupported value 'crypto_pwhash_argon2id_PASSWD_MAX'
# const 'crypto_pwhash_SALTBYTES' has unsupported value 'crypto_pwhash_argon2id_SALTBYTES'
# const 'crypto_pwhash_STRBYTES' has unsupported value 'crypto_pwhash_argon2id_STRBYTES'
# const 'crypto_pwhash_STRPREFIX' has unsupported value 'crypto_pwhash_argon2id_STRPREFIX'
# const 'crypto_pwhash_OPSLIMIT_MIN' has unsupported value 'crypto_pwhash_argon2id_OPSLIMIT_MIN'
# const 'crypto_pwhash_OPSLIMIT_MAX' has unsupported value 'crypto_pwhash_argon2id_OPSLIMIT_MAX'
# const 'crypto_pwhash_MEMLIMIT_MIN' has unsupported value 'crypto_pwhash_argon2id_MEMLIMIT_MIN'
# const 'crypto_pwhash_MEMLIMIT_MAX' has unsupported value 'crypto_pwhash_argon2id_MEMLIMIT_MAX'
# const 'crypto_pwhash_OPSLIMIT_INTERACTIVE' has unsupported value 'crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE'
# const 'crypto_pwhash_MEMLIMIT_INTERACTIVE' has unsupported value 'crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE'
# const 'crypto_pwhash_OPSLIMIT_MODERATE' has unsupported value 'crypto_pwhash_argon2id_OPSLIMIT_MODERATE'
# const 'crypto_pwhash_MEMLIMIT_MODERATE' has unsupported value 'crypto_pwhash_argon2id_MEMLIMIT_MODERATE'
# const 'crypto_pwhash_OPSLIMIT_SENSITIVE' has unsupported value 'crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE'
# const 'crypto_pwhash_MEMLIMIT_SENSITIVE' has unsupported value 'crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE'
# const 'crypto_scalarmult_BYTES' has unsupported value 'crypto_scalarmult_curve25519_BYTES'
# const 'crypto_scalarmult_SCALARBYTES' has unsupported value 'crypto_scalarmult_curve25519_SCALARBYTES'
# const 'crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX' has unsupported value '(crypto_stream_xsalsa20_MESSAGEBYTES_MAX - crypto_secretbox_xsalsa20poly1305_MACBYTES)'
# const 'crypto_secretbox_KEYBYTES' has unsupported value 'crypto_secretbox_xsalsa20poly1305_KEYBYTES'
# const 'crypto_secretbox_NONCEBYTES' has unsupported value 'crypto_secretbox_xsalsa20poly1305_NONCEBYTES'
# const 'crypto_secretbox_MACBYTES' has unsupported value 'crypto_secretbox_xsalsa20poly1305_MACBYTES'
# const 'crypto_secretbox_MESSAGEBYTES_MAX' has unsupported value 'crypto_secretbox_xsalsa20poly1305_MESSAGEBYTES_MAX'
# const 'crypto_secretbox_ZEROBYTES' has unsupported value 'crypto_secretbox_xsalsa20poly1305_ZEROBYTES'
# const 'crypto_secretbox_BOXZEROBYTES' has unsupported value 'crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES'
# const 'crypto_stream_chacha20_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX, 64ULL * (1ULL << 32))'
# const 'crypto_stream_chacha20_IETF_KEYBYTES' has unsupported value 'crypto_stream_chacha20_ietf_KEYBYTES'
# const 'crypto_stream_chacha20_IETF_NONCEBYTES' has unsupported value 'crypto_stream_chacha20_ietf_NONCEBYTES'
# const 'crypto_stream_chacha20_IETF_MESSAGEBYTES_MAX' has unsupported value 'crypto_stream_chacha20_ietf_MESSAGEBYTES_MAX'
# const 'crypto_secretstream_xchacha20poly1305_HEADERBYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_NPUBBYTES'
# const 'crypto_secretstream_xchacha20poly1305_KEYBYTES' has unsupported value 'crypto_aead_xchacha20poly1305_ietf_KEYBYTES'
# const 'crypto_secretstream_xchacha20poly1305_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX - crypto_secretstream_xchacha20poly1305_ABYTES, (64ULL * ((1ULL << 32) - 2ULL)))'
# const 'crypto_shorthash_BYTES' has unsupported value 'crypto_shorthash_siphash24_BYTES'
# const 'crypto_shorthash_KEYBYTES' has unsupported value 'crypto_shorthash_siphash24_KEYBYTES'
# const 'crypto_sign_ed25519_MESSAGEBYTES_MAX' has unsupported value '(SODIUM_SIZE_MAX - crypto_sign_ed25519_BYTES)'
# const 'crypto_sign_BYTES' has unsupported value 'crypto_sign_ed25519_BYTES'
# const 'crypto_sign_SEEDBYTES' has unsupported value 'crypto_sign_ed25519_SEEDBYTES'
# const 'crypto_sign_PUBLICKEYBYTES' has unsupported value 'crypto_sign_ed25519_PUBLICKEYBYTES'
# const 'crypto_sign_SECRETKEYBYTES' has unsupported value 'crypto_sign_ed25519_SECRETKEYBYTES'
# const 'crypto_sign_MESSAGEBYTES_MAX' has unsupported value 'crypto_sign_ed25519_MESSAGEBYTES_MAX'
# const 'crypto_stream_KEYBYTES' has unsupported value 'crypto_stream_xsalsa20_KEYBYTES'
# const 'crypto_stream_NONCEBYTES' has unsupported value 'crypto_stream_xsalsa20_NONCEBYTES'
# const 'crypto_stream_MESSAGEBYTES_MAX' has unsupported value 'crypto_stream_xsalsa20_MESSAGEBYTES_MAX'
# const 'crypto_stream_salsa20_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'randombytes_BYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX, 0xffffffffUL)'
# const 'randombytes_salsa20_implementation' has unsupported value 'randombytes_internal_implementation'
# const 'crypto_stream_xchacha20_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'crypto_box_curve25519xchacha20poly1305_MESSAGEBYTES_MAX' has unsupported value '(crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_box_curve25519xchacha20poly1305_MACBYTES)'
# const 'crypto_secretbox_xchacha20poly1305_MESSAGEBYTES_MAX' has unsupported value '(crypto_stream_xchacha20_MESSAGEBYTES_MAX - crypto_secretbox_xchacha20poly1305_MACBYTES)'
# const 'crypto_pwhash_scryptsalsa208sha256_BYTES_MAX' has unsupported value 'SODIUM_MIN(SODIUM_SIZE_MAX, 0x1fffffffe0ULL)'
# const 'crypto_pwhash_scryptsalsa208sha256_PASSWD_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MAX' has unsupported value 'SODIUM_MIN(SIZE_MAX, 68719476736ULL)'
# const 'crypto_stream_salsa2012_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
# const 'crypto_stream_salsa208_MESSAGEBYTES_MAX' has unsupported value 'SODIUM_SIZE_MAX'
{.push hint[ConvFromXtoItselfNotNeeded]: off.}


{.experimental: "codeReordering".}
{.passC: "-I" & sodiumPath & "/src/libsodium/include".}
{.passC: "-I" & sodiumPath & "/src/libsodium/include/sodium".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/ed25519/core_ed25519.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/ed25519/core_ristretto255.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/ed25519/ref10/ed25519_ref10.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/hsalsa20/core_hsalsa20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/hsalsa20/ref2/core_hsalsa20_ref2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/hchacha20/core_hchacha20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_core/salsa/ref/core_salsa_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_secretstream/xchacha20poly1305/secretstream_xchacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_aead/chacha20poly1305/sodium/aead_chacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_aead/aes256gcm/aesni/aead_aes256gcm_aesni.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_aead/xchacha20poly1305/sodium/aead_xchacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_hash/crypto_hash.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_hash/sha256/hash_sha256.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_hash/sha256/cp/hash_sha256_cp.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_hash/sha512/hash_sha512.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_hash/sha512/cp/hash_sha512_cp.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/crypto_stream.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/xsalsa20/stream_xsalsa20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa208/stream_salsa208.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa208/ref/stream_salsa208_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa2012/stream_salsa2012.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa2012/ref/stream_salsa2012_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa20/stream_salsa20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa20/xmm6/salsa20_xmm6.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-avx2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa20/xmm6int/salsa20_xmm6int-sse2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/salsa20/ref/salsa20_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/chacha20/stream_chacha20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-avx2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/chacha20/dolbeau/chacha20_dolbeau-ssse3.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/chacha20/ref/chacha20_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_stream/xchacha20/stream_xchacha20.c".}
{.compile: "" & sodiumPath & "/src/libsodium/sodium/codecs.c".}
{.compile: "" & sodiumPath & "/src/libsodium/sodium/runtime.c".}
{.compile: "" & sodiumPath & "/src/libsodium/sodium/core.c".}
{.compile: "" & sodiumPath & "/src/libsodium/sodium/utils.c".}
{.compile: "" & sodiumPath & "/src/libsodium/sodium/version.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/crypto_box_easy.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/crypto_box_seal.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/crypto_box.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_curve25519xchacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/curve25519xchacha20poly1305/box_seal_curve25519xchacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_box/curve25519xsalsa20poly1305/box_curve25519xsalsa20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/randombytes/randombytes.c".}
{.compile: "" & sodiumPath & "/src/libsodium/randombytes/internal/randombytes_internal_random.c".}
{.compile: "" & sodiumPath & "/src/libsodium/randombytes/sysrandom/randombytes_sysrandom.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_onetimeauth/crypto_onetimeauth.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_onetimeauth/poly1305/onetimeauth_poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_onetimeauth/poly1305/sse2/poly1305_sse2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_onetimeauth/poly1305/donna/poly1305_donna.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/crypto_scalarmult.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/curve25519/scalarmult_curve25519.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/curve25519/ref10/x25519_ref10.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/curve25519/sandy2x/curve25519_sandy2x.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe_frombytes_sandy2x.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/curve25519/sandy2x/fe51_invert.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/ed25519/ref10/scalarmult_ed25519_ref10.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_scalarmult/ristretto255/ref10/scalarmult_ristretto255_ref10.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_shorthash/crypto_shorthash.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_shorthash/siphash24/shorthash_siphash24.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_shorthash/siphash24/shorthash_siphashx24.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphashx24_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_shorthash/siphash24/ref/shorthash_siphash24_ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_kdf/crypto_kdf.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_kdf/blake2b/kdf_blake2b.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_auth/crypto_auth.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_auth/hmacsha256/auth_hmacsha256.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_auth/hmacsha512256/auth_hmacsha512256.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_auth/hmacsha512/auth_hmacsha512.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_verify/sodium/verify.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/crypto_pwhash.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/scrypt_platform.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/crypto_scrypt-common.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pwhash_scryptsalsa208sha256.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/pbkdf2-sha256.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/sse/pwhash_scryptsalsa208sha256_sse.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/scryptsalsa208sha256/nosse/pwhash_scryptsalsa208sha256_nosse.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/blake2b-long.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-core.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx512f.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-ssse3.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/pwhash_argon2i.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/pwhash_argon2id.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-fill-block-avx2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_pwhash/argon2/argon2-encoding.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_secretbox/crypto_secretbox.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_secretbox/crypto_secretbox_easy.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_secretbox/xchacha20poly1305/secretbox_xchacha20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_secretbox/xsalsa20poly1305/secretbox_xsalsa20poly1305.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/crypto_sign.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/ed25519/sign_ed25519.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/ed25519/ref10/obsolete.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/ed25519/ref10/sign.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/ed25519/ref10/keypair.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_sign/ed25519/ref10/open.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_kx/crypto_kx.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/crypto_generichash.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/generichash_blake2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ref.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-ssse3.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-avx2.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/blake2b-compress-sse41.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/generichash_blake2b.c".}
{.compile: "" & sodiumPath & "/src/libsodium/crypto_generichash/blake2b/ref/blake2b-ref.c".}
const
  SODIUM_VERSION_STRING* = "1.0.18"
  SODIUM_LIBRARY_VERSION_MAJOR* = 10
  SODIUM_LIBRARY_VERSION_MINOR* = 3
  crypto_aead_aes256gcm_KEYBYTES* = 32'u
  crypto_aead_aes256gcm_NSECBYTES* = 0'u
  crypto_aead_aes256gcm_NPUBBYTES* = 12'u
  crypto_aead_aes256gcm_ABYTES* = 16'u
  crypto_aead_chacha20poly1305_ietf_KEYBYTES* = 32'u
  crypto_aead_chacha20poly1305_ietf_NSECBYTES* = 0'u
  crypto_aead_chacha20poly1305_ietf_NPUBBYTES* = 12'u
  crypto_aead_chacha20poly1305_ietf_ABYTES* = 16'u
  crypto_aead_chacha20poly1305_KEYBYTES* = 32'u
  crypto_aead_chacha20poly1305_NSECBYTES* = 0'u
  crypto_aead_chacha20poly1305_NPUBBYTES* = 8'u
  crypto_aead_chacha20poly1305_ABYTES* = 16'u
  crypto_aead_xchacha20poly1305_ietf_KEYBYTES* = 32'u
  crypto_aead_xchacha20poly1305_ietf_NSECBYTES* = 0'u
  crypto_aead_xchacha20poly1305_ietf_NPUBBYTES* = 24'u
  crypto_aead_xchacha20poly1305_ietf_ABYTES* = 16'u
  crypto_hash_sha512_BYTES* = 64'u
  crypto_auth_hmacsha512_BYTES* = 64'u
  crypto_auth_hmacsha512_KEYBYTES* = 32'u
  crypto_auth_hmacsha512256_BYTES* = 32'u
  crypto_auth_hmacsha512256_KEYBYTES* = 32'u
  crypto_auth_PRIMITIVE* = "hmacsha512256"
  crypto_hash_sha256_BYTES* = 32'u
  crypto_auth_hmacsha256_BYTES* = 32'u
  crypto_auth_hmacsha256_KEYBYTES* = 32'u
  crypto_stream_xsalsa20_KEYBYTES* = 32'u
  crypto_stream_xsalsa20_NONCEBYTES* = 24'u
  crypto_box_curve25519xsalsa20poly1305_SEEDBYTES* = 32'u
  crypto_box_curve25519xsalsa20poly1305_PUBLICKEYBYTES* = 32'u
  crypto_box_curve25519xsalsa20poly1305_SECRETKEYBYTES* = 32'u
  crypto_box_curve25519xsalsa20poly1305_BEFORENMBYTES* = 32'u
  crypto_box_curve25519xsalsa20poly1305_NONCEBYTES* = 24'u
  crypto_box_curve25519xsalsa20poly1305_MACBYTES* = 16'u
  crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES* = 16'u
  crypto_box_curve25519xsalsa20poly1305_ZEROBYTES* = (crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES +
      typeof(crypto_box_curve25519xsalsa20poly1305_BOXZEROBYTES)(
      crypto_box_curve25519xsalsa20poly1305_MACBYTES))
  crypto_box_PRIMITIVE* = "curve25519xsalsa20poly1305"
  crypto_core_hsalsa20_OUTPUTBYTES* = 32'u
  crypto_core_hsalsa20_INPUTBYTES* = 16'u
  crypto_core_hsalsa20_KEYBYTES* = 32'u
  crypto_core_hsalsa20_CONSTBYTES* = 16'u
  crypto_core_hchacha20_OUTPUTBYTES* = 32'u
  crypto_core_hchacha20_INPUTBYTES* = 16'u
  crypto_core_hchacha20_KEYBYTES* = 32'u
  crypto_core_hchacha20_CONSTBYTES* = 16'u
  crypto_core_salsa20_OUTPUTBYTES* = 64'u
  crypto_core_salsa20_INPUTBYTES* = 16'u
  crypto_core_salsa20_KEYBYTES* = 32'u
  crypto_core_salsa20_CONSTBYTES* = 16'u
  crypto_core_salsa2012_OUTPUTBYTES* = 64'u
  crypto_core_salsa2012_INPUTBYTES* = 16'u
  crypto_core_salsa2012_KEYBYTES* = 32'u
  crypto_core_salsa2012_CONSTBYTES* = 16'u
  crypto_core_salsa208_OUTPUTBYTES* = 64'u
  crypto_core_salsa208_INPUTBYTES* = 16'u
  crypto_core_salsa208_KEYBYTES* = 32'u
  crypto_core_salsa208_CONSTBYTES* = 16'u
  crypto_generichash_blake2b_BYTES_MIN* = 16'u
  crypto_generichash_blake2b_BYTES_MAX* = 64'u
  crypto_generichash_blake2b_BYTES* = 32'u
  crypto_generichash_blake2b_KEYBYTES_MIN* = 16'u
  crypto_generichash_blake2b_KEYBYTES_MAX* = 64'u
  crypto_generichash_blake2b_KEYBYTES* = 32'u
  crypto_generichash_blake2b_SALTBYTES* = 16'u
  crypto_generichash_blake2b_PERSONALBYTES* = 16'u
  crypto_generichash_PRIMITIVE* = "blake2b"
  crypto_hash_PRIMITIVE* = "sha512"
  crypto_kdf_blake2b_BYTES_MIN* = 16
  crypto_kdf_blake2b_BYTES_MAX* = 64
  crypto_kdf_blake2b_CONTEXTBYTES* = 8
  crypto_kdf_blake2b_KEYBYTES* = 32
  crypto_kdf_PRIMITIVE* = "blake2b"
  crypto_kx_PUBLICKEYBYTES* = 32
  crypto_kx_SECRETKEYBYTES* = 32
  crypto_kx_SEEDBYTES* = 32
  crypto_kx_SESSIONKEYBYTES* = 32
  crypto_kx_PRIMITIVE* = "x25519blake2b"
  crypto_onetimeauth_poly1305_BYTES* = 16'u
  crypto_onetimeauth_poly1305_KEYBYTES* = 32'u
  crypto_onetimeauth_PRIMITIVE* = "poly1305"
  crypto_pwhash_argon2i_ALG_ARGON2I13* = 1
  crypto_pwhash_argon2i_BYTES_MIN* = 16'u
  crypto_pwhash_argon2i_PASSWD_MIN* = 0'u
  crypto_pwhash_argon2i_PASSWD_MAX* = 4294967295'u
  crypto_pwhash_argon2i_SALTBYTES* = 16'u
  crypto_pwhash_argon2i_STRBYTES* = 128'u
  crypto_pwhash_argon2i_STRPREFIX* = "$argon2i$"
  crypto_pwhash_argon2i_OPSLIMIT_MIN* = 3'u
  crypto_pwhash_argon2i_OPSLIMIT_MAX* = 4294967295'u
  crypto_pwhash_argon2i_MEMLIMIT_MIN* = 8192'u
  crypto_pwhash_argon2i_OPSLIMIT_INTERACTIVE* = 4'u
  crypto_pwhash_argon2i_MEMLIMIT_INTERACTIVE* = 33554432'u
  crypto_pwhash_argon2i_OPSLIMIT_MODERATE* = 6'u
  crypto_pwhash_argon2i_MEMLIMIT_MODERATE* = 134217728'u
  crypto_pwhash_argon2i_OPSLIMIT_SENSITIVE* = 8'u
  crypto_pwhash_argon2i_MEMLIMIT_SENSITIVE* = 536870912'u
  crypto_pwhash_argon2id_ALG_ARGON2ID13* = 2
  crypto_pwhash_argon2id_BYTES_MIN* = 16'u
  crypto_pwhash_argon2id_PASSWD_MIN* = 0'u
  crypto_pwhash_argon2id_PASSWD_MAX* = 4294967295'u
  crypto_pwhash_argon2id_SALTBYTES* = 16'u
  crypto_pwhash_argon2id_STRBYTES* = 128'u
  crypto_pwhash_argon2id_STRPREFIX* = "$argon2id$"
  crypto_pwhash_argon2id_OPSLIMIT_MIN* = 1'u
  crypto_pwhash_argon2id_OPSLIMIT_MAX* = 4294967295'u
  crypto_pwhash_argon2id_MEMLIMIT_MIN* = 8192'u
  crypto_pwhash_argon2id_OPSLIMIT_INTERACTIVE* = 2'u
  crypto_pwhash_argon2id_MEMLIMIT_INTERACTIVE* = 67108864'u
  crypto_pwhash_argon2id_OPSLIMIT_MODERATE* = 3'u
  crypto_pwhash_argon2id_MEMLIMIT_MODERATE* = 268435456'u
  crypto_pwhash_argon2id_OPSLIMIT_SENSITIVE* = 4'u
  crypto_pwhash_argon2id_MEMLIMIT_SENSITIVE* = 1073741824'u
  crypto_pwhash_PRIMITIVE* = "argon2i"
  crypto_scalarmult_curve25519_BYTES* = 32'u
  crypto_scalarmult_curve25519_SCALARBYTES* = 32'u
  crypto_scalarmult_PRIMITIVE* = "curve25519"
  crypto_secretbox_xsalsa20poly1305_KEYBYTES* = 32'u
  crypto_secretbox_xsalsa20poly1305_NONCEBYTES* = 24'u
  crypto_secretbox_xsalsa20poly1305_MACBYTES* = 16'u
  crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES* = 16'u
  crypto_secretbox_xsalsa20poly1305_ZEROBYTES* = (crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES +
      typeof(crypto_secretbox_xsalsa20poly1305_BOXZEROBYTES)(
      crypto_secretbox_xsalsa20poly1305_MACBYTES))
  crypto_secretbox_PRIMITIVE* = "xsalsa20poly1305"
  crypto_stream_chacha20_KEYBYTES* = 32'u
  crypto_stream_chacha20_NONCEBYTES* = 8'u
  crypto_stream_chacha20_ietf_KEYBYTES* = 32'u
  crypto_stream_chacha20_ietf_NONCEBYTES* = 12'u
  crypto_secretstream_xchacha20poly1305_ABYTES* = (
    1'u + typeof(1'u)(crypto_aead_xchacha20poly1305_ietf_ABYTES))
  crypto_secretstream_xchacha20poly1305_TAG_MESSAGE* = 0x00000000
  crypto_secretstream_xchacha20poly1305_TAG_PUSH* = 0x00000001
  crypto_secretstream_xchacha20poly1305_TAG_REKEY* = 0x00000002
  crypto_secretstream_xchacha20poly1305_TAG_FINAL* = (crypto_secretstream_xchacha20poly1305_TAG_PUSH or
      typeof(crypto_secretstream_xchacha20poly1305_TAG_PUSH)(
      crypto_secretstream_xchacha20poly1305_TAG_REKEY))
  crypto_shorthash_siphash24_BYTES* = 8'u
  crypto_shorthash_siphash24_KEYBYTES* = 16'u
  crypto_shorthash_siphashx24_BYTES* = 16'u
  crypto_shorthash_siphashx24_KEYBYTES* = 16'u
  crypto_shorthash_PRIMITIVE* = "siphash24"
  crypto_sign_ed25519_BYTES* = 64'u
  crypto_sign_ed25519_SEEDBYTES* = 32'u
  crypto_sign_ed25519_PUBLICKEYBYTES* = 32'u
  crypto_sign_ed25519_SECRETKEYBYTES* = (32'u + typeof(32'u)(32'u))
  crypto_sign_PRIMITIVE* = "ed25519"
  crypto_stream_PRIMITIVE* = "xsalsa20"
  crypto_stream_salsa20_KEYBYTES* = 32'u
  crypto_stream_salsa20_NONCEBYTES* = 8'u
  crypto_verify_16_BYTES* = 16'u
  crypto_verify_32_BYTES* = 32'u
  crypto_verify_64_BYTES* = 64'u
  randombytes_SEEDBYTES* = 32'u
  sodium_base64_VARIANT_ORIGINAL* = 1
  sodium_base64_VARIANT_ORIGINAL_NO_PADDING* = 3
  sodium_base64_VARIANT_URLSAFE* = 5
  sodium_base64_VARIANT_URLSAFE_NO_PADDING* = 7
  crypto_stream_xchacha20_KEYBYTES* = 32'u
  crypto_stream_xchacha20_NONCEBYTES* = 24'u
  crypto_box_curve25519xchacha20poly1305_SEEDBYTES* = 32'u
  crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES* = 32'u
  crypto_box_curve25519xchacha20poly1305_SECRETKEYBYTES* = 32'u
  crypto_box_curve25519xchacha20poly1305_BEFORENMBYTES* = 32'u
  crypto_box_curve25519xchacha20poly1305_NONCEBYTES* = 24'u
  crypto_box_curve25519xchacha20poly1305_MACBYTES* = 16'u
  crypto_box_curve25519xchacha20poly1305_SEALBYTES* = (crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES +
      typeof(crypto_box_curve25519xchacha20poly1305_PUBLICKEYBYTES)(
      crypto_box_curve25519xchacha20poly1305_MACBYTES))
  crypto_core_ed25519_BYTES* = 32
  crypto_core_ed25519_UNIFORMBYTES* = 32
  crypto_core_ed25519_HASHBYTES* = 64
  crypto_core_ed25519_SCALARBYTES* = 32
  crypto_core_ed25519_NONREDUCEDSCALARBYTES* = 64
  crypto_core_ristretto255_BYTES* = 32
  crypto_core_ristretto255_HASHBYTES* = 64
  crypto_core_ristretto255_SCALARBYTES* = 32
  crypto_core_ristretto255_NONREDUCEDSCALARBYTES* = 64
  crypto_scalarmult_ed25519_BYTES* = 32'u
  crypto_scalarmult_ed25519_SCALARBYTES* = 32'u
  crypto_scalarmult_ristretto255_BYTES* = 32'u
  crypto_scalarmult_ristretto255_SCALARBYTES* = 32'u
  crypto_secretbox_xchacha20poly1305_KEYBYTES* = 32'u
  crypto_secretbox_xchacha20poly1305_NONCEBYTES* = 24'u
  crypto_secretbox_xchacha20poly1305_MACBYTES* = 16'u
  crypto_pwhash_scryptsalsa208sha256_BYTES_MIN* = 16'u
  crypto_pwhash_scryptsalsa208sha256_PASSWD_MIN* = 0'u
  crypto_pwhash_scryptsalsa208sha256_SALTBYTES* = 32'u
  crypto_pwhash_scryptsalsa208sha256_STRBYTES* = 102'u
  crypto_pwhash_scryptsalsa208sha256_STRPREFIX* = "$7$"
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MIN* = 32768'u
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_MAX* = 4294967295'u
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_MIN* = 16777216'u
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_INTERACTIVE* = 524288'u
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_INTERACTIVE* = 16777216'u
  crypto_pwhash_scryptsalsa208sha256_OPSLIMIT_SENSITIVE* = 33554432'u
  crypto_pwhash_scryptsalsa208sha256_MEMLIMIT_SENSITIVE* = 1073741824'u
  crypto_stream_salsa2012_KEYBYTES* = 32'u
  crypto_stream_salsa2012_NONCEBYTES* = 8'u
  crypto_stream_salsa208_KEYBYTES* = 32'u
  crypto_stream_salsa208_NONCEBYTES* = 8'u
type
  crypto_aead_aes256gcm_state_def* {.bycopy.} = object
    opaque*: array[512, cuchar]

  crypto_aead_aes256gcm_state* = crypto_aead_aes256gcm_state_def
  crypto_hash_sha512_state* {.bycopy.} = object
    state*: array[8, uint64]
    count*: array[2, uint64]
    buf*: array[128, uint8]

  crypto_auth_hmacsha512_state* {.bycopy.} = object
    ictx*: crypto_hash_sha512_state
    octx*: crypto_hash_sha512_state

  crypto_auth_hmacsha512256_state* = crypto_auth_hmacsha512_state
  crypto_hash_sha256_state* {.bycopy.} = object
    state*: array[8, uint32]
    count*: uint64
    buf*: array[64, uint8]

  crypto_auth_hmacsha256_state* {.bycopy.} = object
    ictx*: crypto_hash_sha256_state
    octx*: crypto_hash_sha256_state

  crypto_generichash_blake2b_state* {.bycopy.} = object
    opaque*: array[384, cuchar]

  crypto_generichash_state* = crypto_generichash_blake2b_state ## ```
                                                               ##   Important when writing bindings for other programming languages:
                                                               ##    the state address should be 64-bytes aligned.
                                                               ## ```
  crypto_onetimeauth_poly1305_state* {.bycopy.} = object
    opaque*: array[256, cuchar]

  crypto_onetimeauth_state* = crypto_onetimeauth_poly1305_state
  crypto_secretstream_xchacha20poly1305_state* {.bycopy.} = object
    k*: array[32'u, cuchar]
    nonce*: array[12'u, cuchar]
    INTERNAL_pad*: array[8, cuchar]

  crypto_sign_ed25519ph_state* {.bycopy.} = object
    hs*: crypto_hash_sha512_state

  crypto_sign_state* = crypto_sign_ed25519ph_state
  randombytes_implementation* {.bycopy.} = object
    implementation_name*: proc (): cstring {.cdecl.} ## ```
                                                     ##   required
                                                     ## ```
    random*: proc (): uint32 {.cdecl.} ## ```
                                       ##   required
                                       ## ```
    stir*: proc () {.cdecl.} ## ```
                             ##   optional
                             ## ```
    uniform*: proc (upper_bound: uint32): uint32 {.cdecl.} ## ```
                                                           ##   optional, a default implementation will be used if NULL
                                                           ## ```
    buf*: proc (buf: pointer; size: uint) {.cdecl.} ## ```
                                                    ##   required
                                                    ## ```
    close*: proc (): cint {.cdecl.} ## ```
                                    ##   optional
                                    ## ```
  
var
  randombytes_internal_implementation* {.importc.}: randombytes_implementation
  randombytes_sysrandom_implementation* {.importc.}: randombytes_implementation
proc sodium_version_string*(): cstring {.importc, cdecl.}
proc sodium_library_version_major*(): cint {.importc, cdecl.}
proc sodium_library_version_minor*(): cint {.importc, cdecl.}
proc sodium_library_minimal*(): cint {.importc, cdecl.}
proc sodium_init*(): cint {.importc, cdecl.}
proc sodium_set_misuse_handler*(handler: proc () {.cdecl.}): cint {.importc,
    cdecl.}
proc sodium_misuse*() {.importc, cdecl.}
proc crypto_aead_aes256gcm_is_available*(): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_aead_aes256gcm_keybytes", cdecl.}
proc crypto_aead_aes256gcm_CONSTANT_NSECBYTES*(): uint {.
    importc: "crypto_aead_aes256gcm_nsecbytes", cdecl.}
proc crypto_aead_aes256gcm_CONSTANT_NPUBBYTES*(): uint {.
    importc: "crypto_aead_aes256gcm_npubbytes", cdecl.}
proc crypto_aead_aes256gcm_CONSTANT_ABYTES*(): uint {.
    importc: "crypto_aead_aes256gcm_abytes", cdecl.}
proc crypto_aead_aes256gcm_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_aead_aes256gcm_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_aead_aes256gcm_statebytes", cdecl.}
proc crypto_aead_aes256gcm_encrypt*(c: ptr cuchar; clen_p: ptr culonglong;
                                    m: ptr cuchar; mlen: culonglong;
                                    ad: ptr cuchar; adlen: culonglong;
                                    nsec: ptr cuchar; npub: ptr cuchar;
                                    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_decrypt*(m: ptr cuchar; mlen_p: ptr culonglong;
                                    nsec: ptr cuchar; c: ptr cuchar;
                                    clen: culonglong; ad: ptr cuchar;
                                    adlen: culonglong; npub: ptr cuchar;
                                    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_encrypt_detached*(c: ptr cuchar; mac: ptr cuchar;
    maclen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_aes256gcm_decrypt_detached*(m: ptr cuchar; nsec: ptr cuchar;
    c: ptr cuchar; clen: culonglong; mac: ptr cuchar; ad: ptr cuchar;
    adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_beforenm*(ctx: ptr crypto_aead_aes256gcm_state;
                                     k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_encrypt_afternm*(c: ptr cuchar;
    clen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar;
    ctx: ptr crypto_aead_aes256gcm_state): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_decrypt_afternm*(m: ptr cuchar;
    mlen_p: ptr culonglong; nsec: ptr cuchar; c: ptr cuchar; clen: culonglong;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar;
    ctx: ptr crypto_aead_aes256gcm_state): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_encrypt_detached_afternm*(c: ptr cuchar;
    mac: ptr cuchar; maclen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong;
    ad: ptr cuchar; adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar;
    ctx: ptr crypto_aead_aes256gcm_state): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_decrypt_detached_afternm*(m: ptr cuchar;
    nsec: ptr cuchar; c: ptr cuchar; clen: culonglong; mac: ptr cuchar;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar;
    ctx: ptr crypto_aead_aes256gcm_state): cint {.importc, cdecl.}
proc crypto_aead_aes256gcm_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_aead_chacha20poly1305_ietf_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_ietf_keybytes", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_CONSTANT_NSECBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_ietf_nsecbytes", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_CONSTANT_NPUBBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_ietf_npubbytes", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_CONSTANT_ABYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_ietf_abytes", cdecl.}
proc crypto_aead_chacha20poly1305_ietf_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_aead_chacha20poly1305_ietf_encrypt*(c: ptr cuchar;
    clen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_ietf_decrypt*(m: ptr cuchar;
    mlen_p: ptr culonglong; nsec: ptr cuchar; c: ptr cuchar; clen: culonglong;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_ietf_encrypt_detached*(c: ptr cuchar;
    mac: ptr cuchar; maclen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong;
    ad: ptr cuchar; adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_chacha20poly1305_ietf_decrypt_detached*(m: ptr cuchar;
    nsec: ptr cuchar; c: ptr cuchar; clen: culonglong; mac: ptr cuchar;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_ietf_keygen*(k: array[32'u, cuchar]) {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_keybytes", cdecl.}
proc crypto_aead_chacha20poly1305_CONSTANT_NSECBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_nsecbytes", cdecl.}
proc crypto_aead_chacha20poly1305_CONSTANT_NPUBBYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_npubbytes", cdecl.}
proc crypto_aead_chacha20poly1305_CONSTANT_ABYTES*(): uint {.
    importc: "crypto_aead_chacha20poly1305_abytes", cdecl.}
proc crypto_aead_chacha20poly1305_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_aead_chacha20poly1305_encrypt*(c: ptr cuchar;
    clen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_decrypt*(m: ptr cuchar;
    mlen_p: ptr culonglong; nsec: ptr cuchar; c: ptr cuchar; clen: culonglong;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_encrypt_detached*(c: ptr cuchar;
    mac: ptr cuchar; maclen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong;
    ad: ptr cuchar; adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_chacha20poly1305_decrypt_detached*(m: ptr cuchar;
    nsec: ptr cuchar; c: ptr cuchar; clen: culonglong; mac: ptr cuchar;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_chacha20poly1305_keygen*(k: array[32'u, cuchar]) {.importc,
    cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_aead_xchacha20poly1305_ietf_keybytes", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_CONSTANT_NSECBYTES*(): uint {.
    importc: "crypto_aead_xchacha20poly1305_ietf_nsecbytes", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_CONSTANT_NPUBBYTES*(): uint {.
    importc: "crypto_aead_xchacha20poly1305_ietf_npubbytes", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_CONSTANT_ABYTES*(): uint {.
    importc: "crypto_aead_xchacha20poly1305_ietf_abytes", cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_encrypt*(c: ptr cuchar;
    clen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_decrypt*(m: ptr cuchar;
    mlen_p: ptr culonglong; nsec: ptr cuchar; c: ptr cuchar; clen: culonglong;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_encrypt_detached*(c: ptr cuchar;
    mac: ptr cuchar; maclen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong;
    ad: ptr cuchar; adlen: culonglong; nsec: ptr cuchar; npub: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_decrypt_detached*(m: ptr cuchar;
    nsec: ptr cuchar; c: ptr cuchar; clen: culonglong; mac: ptr cuchar;
    ad: ptr cuchar; adlen: culonglong; npub: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_aead_xchacha20poly1305_ietf_keygen*(k: array[32'u, cuchar]) {.
    importc, cdecl.}
proc crypto_hash_sha512_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_hash_sha512_statebytes", cdecl.}
proc crypto_hash_sha512_CONSTANT_BYTES*(): uint {.
    importc: "crypto_hash_sha512_bytes", cdecl.}
proc crypto_hash_sha512*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_hash_sha512_init*(state: ptr crypto_hash_sha512_state): cint {.
    importc, cdecl.}
proc crypto_hash_sha512_update*(state: ptr crypto_hash_sha512_state;
                                `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_hash_sha512_final*(state: ptr crypto_hash_sha512_state;
                               `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_hmacsha512_CONSTANT_BYTES*(): uint {.
    importc: "crypto_auth_hmacsha512_bytes", cdecl.}
proc crypto_auth_hmacsha512_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_auth_hmacsha512_keybytes", cdecl.}
proc crypto_auth_hmacsha512*(`out`: ptr cuchar; `in`: ptr cuchar;
                             inlen: culonglong; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_auth_hmacsha512_verify*(h: ptr cuchar; `in`: ptr cuchar;
                                    inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_auth_hmacsha512_statebytes", cdecl.}
proc crypto_auth_hmacsha512_init*(state: ptr crypto_auth_hmacsha512_state;
                                  key: ptr cuchar; keylen: uint): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512_update*(state: ptr crypto_auth_hmacsha512_state;
                                    `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512_final*(state: ptr crypto_auth_hmacsha512_state;
                                   `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_hmacsha512_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_auth_hmacsha512256_CONSTANT_BYTES*(): uint {.
    importc: "crypto_auth_hmacsha512256_bytes", cdecl.}
proc crypto_auth_hmacsha512256_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_auth_hmacsha512256_keybytes", cdecl.}
proc crypto_auth_hmacsha512256*(`out`: ptr cuchar; `in`: ptr cuchar;
                                inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512256_verify*(h: ptr cuchar; `in`: ptr cuchar;
                                       inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512256_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_auth_hmacsha512256_statebytes", cdecl.}
proc crypto_auth_hmacsha512256_init*(state: ptr crypto_auth_hmacsha512256_state;
                                     key: ptr cuchar; keylen: uint): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512256_update*(state: ptr crypto_auth_hmacsha512256_state;
                                       `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha512256_final*(state: ptr crypto_auth_hmacsha512256_state;
                                      `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_hmacsha512256_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_auth_CONSTANT_BYTES*(): uint {.importc: "crypto_auth_bytes", cdecl.}
proc crypto_auth_CONSTANT_KEYBYTES*(): uint {.importc: "crypto_auth_keybytes",
    cdecl.}
proc crypto_auth_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_auth_primitive", cdecl.}
proc crypto_auth*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong;
                  k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_verify*(h: ptr cuchar; `in`: ptr cuchar; inlen: culonglong;
                         k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_hash_sha256_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_hash_sha256_statebytes", cdecl.}
proc crypto_hash_sha256_CONSTANT_BYTES*(): uint {.
    importc: "crypto_hash_sha256_bytes", cdecl.}
proc crypto_hash_sha256*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_hash_sha256_init*(state: ptr crypto_hash_sha256_state): cint {.
    importc, cdecl.}
proc crypto_hash_sha256_update*(state: ptr crypto_hash_sha256_state;
                                `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_hash_sha256_final*(state: ptr crypto_hash_sha256_state;
                               `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_hmacsha256_CONSTANT_BYTES*(): uint {.
    importc: "crypto_auth_hmacsha256_bytes", cdecl.}
proc crypto_auth_hmacsha256_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_auth_hmacsha256_keybytes", cdecl.}
proc crypto_auth_hmacsha256*(`out`: ptr cuchar; `in`: ptr cuchar;
                             inlen: culonglong; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_auth_hmacsha256_verify*(h: ptr cuchar; `in`: ptr cuchar;
                                    inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha256_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_auth_hmacsha256_statebytes", cdecl.}
proc crypto_auth_hmacsha256_init*(state: ptr crypto_auth_hmacsha256_state;
                                  key: ptr cuchar; keylen: uint): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha256_update*(state: ptr crypto_auth_hmacsha256_state;
                                    `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_auth_hmacsha256_final*(state: ptr crypto_auth_hmacsha256_state;
                                   `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_auth_hmacsha256_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_stream_xsalsa20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_xsalsa20_keybytes", cdecl.}
proc crypto_stream_xsalsa20_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_xsalsa20_noncebytes", cdecl.}
proc crypto_stream_xsalsa20_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_xsalsa20*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                             k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_xsalsa20_xor*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                                 n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_xsalsa20_xor_ic*(c: ptr cuchar; m: ptr cuchar;
                                    mlen: culonglong; n: ptr cuchar; ic: uint64;
                                    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_xsalsa20_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_SEEDBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_seedbytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_publickeybytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_secretkeybytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_BEFORENMBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_beforenmbytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_noncebytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_MACBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_macbytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_seed_keypair*(pk: ptr cuchar;
    sk: ptr cuchar; seed: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_keypair*(pk: ptr cuchar;
    sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_beforenm*(k: ptr cuchar;
    pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_BOXZEROBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_boxzerobytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_CONSTANT_ZEROBYTES*(): uint {.
    importc: "crypto_box_curve25519xsalsa20poly1305_zerobytes", cdecl.}
proc crypto_box_curve25519xsalsa20poly1305*(c: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_open*(m: ptr cuchar; c: ptr cuchar;
    clen: culonglong; n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_afternm*(c: ptr cuchar;
    m: ptr cuchar; mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xsalsa20poly1305_open_afternm*(m: ptr cuchar;
    c: ptr cuchar; clen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_CONSTANT_SEEDBYTES*(): uint {.importc: "crypto_box_seedbytes",
    cdecl.}
proc crypto_box_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_box_publickeybytes", cdecl.}
proc crypto_box_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_box_secretkeybytes", cdecl.}
proc crypto_box_CONSTANT_NONCEBYTES*(): uint {.importc: "crypto_box_noncebytes",
    cdecl.}
proc crypto_box_CONSTANT_MACBYTES*(): uint {.importc: "crypto_box_macbytes",
    cdecl.}
proc crypto_box_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_box_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_box_primitive", cdecl.}
proc crypto_box_seed_keypair*(pk: ptr cuchar; sk: ptr cuchar; seed: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_keypair*(pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_easy*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                      n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_open_easy*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                           n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_detached*(c: ptr cuchar; mac: ptr cuchar; m: ptr cuchar;
                          mlen: culonglong; n: ptr cuchar; pk: ptr cuchar;
                          sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_open_detached*(m: ptr cuchar; c: ptr cuchar; mac: ptr cuchar;
                               clen: culonglong; n: ptr cuchar; pk: ptr cuchar;
                               sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_CONSTANT_BEFORENMBYTES*(): uint {.
    importc: "crypto_box_beforenmbytes", cdecl.}
proc crypto_box_beforenm*(k: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_easy_afternm*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                              n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_box_open_easy_afternm*(m: ptr cuchar; c: ptr cuchar;
                                   clen: culonglong; n: ptr cuchar;
                                   k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_detached_afternm*(c: ptr cuchar; mac: ptr cuchar; m: ptr cuchar;
                                  mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_open_detached_afternm*(m: ptr cuchar; c: ptr cuchar;
                                       mac: ptr cuchar; clen: culonglong;
                                       n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_CONSTANT_SEALBYTES*(): uint {.importc: "crypto_box_sealbytes",
    cdecl.}
proc crypto_box_seal*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                      pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_seal_open*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                           pk: ptr cuchar; sk: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_box_CONSTANT_ZEROBYTES*(): uint {.importc: "crypto_box_zerobytes",
    cdecl.}
proc crypto_box_CONSTANT_BOXZEROBYTES*(): uint {.
    importc: "crypto_box_boxzerobytes", cdecl.}
proc crypto_box*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong; n: ptr cuchar;
                 pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_open*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                      n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_afternm*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                         n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_open_afternm*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                              n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_core_hsalsa20_CONSTANT_OUTPUTBYTES*(): uint {.
    importc: "crypto_core_hsalsa20_outputbytes", cdecl.}
proc crypto_core_hsalsa20_CONSTANT_INPUTBYTES*(): uint {.
    importc: "crypto_core_hsalsa20_inputbytes", cdecl.}
proc crypto_core_hsalsa20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_core_hsalsa20_keybytes", cdecl.}
proc crypto_core_hsalsa20_CONSTANT_CONSTBYTES*(): uint {.
    importc: "crypto_core_hsalsa20_constbytes", cdecl.}
proc crypto_core_hsalsa20*(`out`: ptr cuchar; `in`: ptr cuchar; k: ptr cuchar;
                           c: ptr cuchar): cint {.importc, cdecl.}
proc crypto_core_hchacha20_CONSTANT_OUTPUTBYTES*(): uint {.
    importc: "crypto_core_hchacha20_outputbytes", cdecl.}
proc crypto_core_hchacha20_CONSTANT_INPUTBYTES*(): uint {.
    importc: "crypto_core_hchacha20_inputbytes", cdecl.}
proc crypto_core_hchacha20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_core_hchacha20_keybytes", cdecl.}
proc crypto_core_hchacha20_CONSTANT_CONSTBYTES*(): uint {.
    importc: "crypto_core_hchacha20_constbytes", cdecl.}
proc crypto_core_hchacha20*(`out`: ptr cuchar; `in`: ptr cuchar; k: ptr cuchar;
                            c: ptr cuchar): cint {.importc, cdecl.}
proc crypto_core_salsa20_CONSTANT_OUTPUTBYTES*(): uint {.
    importc: "crypto_core_salsa20_outputbytes", cdecl.}
proc crypto_core_salsa20_CONSTANT_INPUTBYTES*(): uint {.
    importc: "crypto_core_salsa20_inputbytes", cdecl.}
proc crypto_core_salsa20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_core_salsa20_keybytes", cdecl.}
proc crypto_core_salsa20_CONSTANT_CONSTBYTES*(): uint {.
    importc: "crypto_core_salsa20_constbytes", cdecl.}
proc crypto_core_salsa20*(`out`: ptr cuchar; `in`: ptr cuchar; k: ptr cuchar;
                          c: ptr cuchar): cint {.importc, cdecl.}
proc crypto_core_salsa2012_CONSTANT_OUTPUTBYTES*(): uint {.
    importc: "crypto_core_salsa2012_outputbytes", cdecl.}
proc crypto_core_salsa2012_CONSTANT_INPUTBYTES*(): uint {.
    importc: "crypto_core_salsa2012_inputbytes", cdecl.}
proc crypto_core_salsa2012_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_core_salsa2012_keybytes", cdecl.}
proc crypto_core_salsa2012_CONSTANT_CONSTBYTES*(): uint {.
    importc: "crypto_core_salsa2012_constbytes", cdecl.}
proc crypto_core_salsa2012*(`out`: ptr cuchar; `in`: ptr cuchar; k: ptr cuchar;
                            c: ptr cuchar): cint {.importc, cdecl.}
proc crypto_core_salsa208_CONSTANT_OUTPUTBYTES*(): uint {.
    importc: "crypto_core_salsa208_outputbytes", cdecl.}
proc crypto_core_salsa208_CONSTANT_INPUTBYTES*(): uint {.
    importc: "crypto_core_salsa208_inputbytes", cdecl.}
proc crypto_core_salsa208_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_core_salsa208_keybytes", cdecl.}
proc crypto_core_salsa208_CONSTANT_CONSTBYTES*(): uint {.
    importc: "crypto_core_salsa208_constbytes", cdecl.}
proc crypto_core_salsa208*(`out`: ptr cuchar; `in`: ptr cuchar; k: ptr cuchar;
                           c: ptr cuchar): cint {.importc, cdecl.}
proc crypto_generichash_blake2b_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_generichash_blake2b_bytes_min", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_generichash_blake2b_bytes_max", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_BYTES*(): uint {.
    importc: "crypto_generichash_blake2b_bytes", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_KEYBYTES_MIN*(): uint {.
    importc: "crypto_generichash_blake2b_keybytes_min", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_KEYBYTES_MAX*(): uint {.
    importc: "crypto_generichash_blake2b_keybytes_max", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_generichash_blake2b_keybytes", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_SALTBYTES*(): uint {.
    importc: "crypto_generichash_blake2b_saltbytes", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_PERSONALBYTES*(): uint {.
    importc: "crypto_generichash_blake2b_personalbytes", cdecl.}
proc crypto_generichash_blake2b_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_generichash_blake2b_statebytes", cdecl.}
proc crypto_generichash_blake2b*(`out`: ptr cuchar; outlen: uint;
                                 `in`: ptr cuchar; inlen: culonglong;
                                 key: ptr cuchar; keylen: uint): cint {.importc,
    cdecl.}
proc crypto_generichash_blake2b_salt_personal*(`out`: ptr cuchar; outlen: uint;
    `in`: ptr cuchar; inlen: culonglong; key: ptr cuchar; keylen: uint;
    salt: ptr cuchar; personal: ptr cuchar): cint {.importc, cdecl.}
proc crypto_generichash_blake2b_init*(state: ptr crypto_generichash_blake2b_state;
                                      key: ptr cuchar; keylen: uint;
                                      outlen: uint): cint {.importc, cdecl.}
proc crypto_generichash_blake2b_init_salt_personal*(
    state: ptr crypto_generichash_blake2b_state; key: ptr cuchar; keylen: uint;
    outlen: uint; salt: ptr cuchar; personal: ptr cuchar): cint {.importc, cdecl.}
proc crypto_generichash_blake2b_update*(state: ptr crypto_generichash_blake2b_state;
                                        `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_generichash_blake2b_final*(state: ptr crypto_generichash_blake2b_state;
                                       `out`: ptr cuchar; outlen: uint): cint {.
    importc, cdecl.}
proc crypto_generichash_blake2b_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_generichash_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_generichash_bytes_min", cdecl.}
proc crypto_generichash_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_generichash_bytes_max", cdecl.}
proc crypto_generichash_CONSTANT_BYTES*(): uint {.
    importc: "crypto_generichash_bytes", cdecl.}
proc crypto_generichash_CONSTANT_KEYBYTES_MIN*(): uint {.
    importc: "crypto_generichash_keybytes_min", cdecl.}
proc crypto_generichash_CONSTANT_KEYBYTES_MAX*(): uint {.
    importc: "crypto_generichash_keybytes_max", cdecl.}
proc crypto_generichash_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_generichash_keybytes", cdecl.}
proc crypto_generichash_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_generichash_primitive", cdecl.}
proc crypto_generichash_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_generichash_statebytes", cdecl.}
proc crypto_generichash*(`out`: ptr cuchar; outlen: uint; `in`: ptr cuchar;
                         inlen: culonglong; key: ptr cuchar; keylen: uint): cint {.
    importc, cdecl.}
proc crypto_generichash_init*(state: ptr crypto_generichash_state;
                              key: ptr cuchar; keylen: uint; outlen: uint): cint {.
    importc, cdecl.}
proc crypto_generichash_update*(state: ptr crypto_generichash_state;
                                `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_generichash_final*(state: ptr crypto_generichash_state;
                               `out`: ptr cuchar; outlen: uint): cint {.importc,
    cdecl.}
proc crypto_generichash_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_hash_CONSTANT_BYTES*(): uint {.importc: "crypto_hash_bytes", cdecl.}
proc crypto_hash*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_hash_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_hash_primitive", cdecl.}
proc crypto_kdf_blake2b_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_kdf_blake2b_bytes_min", cdecl.}
proc crypto_kdf_blake2b_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_kdf_blake2b_bytes_max", cdecl.}
proc crypto_kdf_blake2b_CONSTANT_CONTEXTBYTES*(): uint {.
    importc: "crypto_kdf_blake2b_contextbytes", cdecl.}
proc crypto_kdf_blake2b_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_kdf_blake2b_keybytes", cdecl.}
proc crypto_kdf_blake2b_derive_from_key*(subkey: ptr cuchar; subkey_len: uint;
    subkey_id: uint64; ctx: array[8, cchar]; key: array[32, cuchar]): cint {.
    importc, cdecl.}
proc crypto_kdf_CONSTANT_BYTES_MIN*(): uint {.importc: "crypto_kdf_bytes_min",
    cdecl.}
proc crypto_kdf_CONSTANT_BYTES_MAX*(): uint {.importc: "crypto_kdf_bytes_max",
    cdecl.}
proc crypto_kdf_CONSTANT_CONTEXTBYTES*(): uint {.
    importc: "crypto_kdf_contextbytes", cdecl.}
proc crypto_kdf_CONSTANT_KEYBYTES*(): uint {.importc: "crypto_kdf_keybytes",
    cdecl.}
proc crypto_kdf_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_kdf_primitive", cdecl.}
proc crypto_kdf_derive_from_key*(subkey: ptr cuchar; subkey_len: uint;
                                 subkey_id: uint64; ctx: array[8, cchar];
                                 key: array[32, cuchar]): cint {.importc, cdecl.}
proc crypto_kdf_keygen*(k: array[32, cuchar]) {.importc, cdecl.}
proc crypto_kx_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_kx_publickeybytes", cdecl.}
proc crypto_kx_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_kx_secretkeybytes", cdecl.}
proc crypto_kx_CONSTANT_SEEDBYTES*(): uint {.importc: "crypto_kx_seedbytes",
    cdecl.}
proc crypto_kx_CONSTANT_SESSIONKEYBYTES*(): uint {.
    importc: "crypto_kx_sessionkeybytes", cdecl.}
proc crypto_kx_CONSTANT_PRIMITIVE*(): cstring {.importc: "crypto_kx_primitive",
    cdecl.}
proc crypto_kx_seed_keypair*(pk: array[32, cuchar]; sk: array[32, cuchar];
                             seed: array[32, cuchar]): cint {.importc, cdecl.}
proc crypto_kx_keypair*(pk: array[32, cuchar]; sk: array[32, cuchar]): cint {.
    importc, cdecl.}
proc crypto_kx_client_session_keys*(rx: array[32, cuchar];
                                    tx: array[32, cuchar];
                                    client_pk: array[32, cuchar];
                                    client_sk: array[32, cuchar];
                                    server_pk: array[32, cuchar]): cint {.
    importc, cdecl.}
proc crypto_kx_server_session_keys*(rx: array[32, cuchar];
                                    tx: array[32, cuchar];
                                    server_pk: array[32, cuchar];
                                    server_sk: array[32, cuchar];
                                    client_pk: array[32, cuchar]): cint {.
    importc, cdecl.}
proc crypto_onetimeauth_poly1305_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_onetimeauth_poly1305_statebytes", cdecl.}
proc crypto_onetimeauth_poly1305_CONSTANT_BYTES*(): uint {.
    importc: "crypto_onetimeauth_poly1305_bytes", cdecl.}
proc crypto_onetimeauth_poly1305_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_onetimeauth_poly1305_keybytes", cdecl.}
proc crypto_onetimeauth_poly1305*(`out`: ptr cuchar; `in`: ptr cuchar;
                                  inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_onetimeauth_poly1305_verify*(h: ptr cuchar; `in`: ptr cuchar;
    inlen: culonglong; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_onetimeauth_poly1305_init*(state: ptr crypto_onetimeauth_poly1305_state;
                                       key: ptr cuchar): cint {.importc, cdecl.}
proc crypto_onetimeauth_poly1305_update*(
    state: ptr crypto_onetimeauth_poly1305_state; `in`: ptr cuchar;
    inlen: culonglong): cint {.importc, cdecl.}
proc crypto_onetimeauth_poly1305_final*(state: ptr crypto_onetimeauth_poly1305_state;
                                        `out`: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_onetimeauth_poly1305_keygen*(k: array[32'u, cuchar]) {.importc,
    cdecl.}
proc crypto_onetimeauth_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_onetimeauth_statebytes", cdecl.}
proc crypto_onetimeauth_CONSTANT_BYTES*(): uint {.
    importc: "crypto_onetimeauth_bytes", cdecl.}
proc crypto_onetimeauth_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_onetimeauth_keybytes", cdecl.}
proc crypto_onetimeauth_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_onetimeauth_primitive", cdecl.}
proc crypto_onetimeauth*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong;
                         k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_onetimeauth_verify*(h: ptr cuchar; `in`: ptr cuchar;
                                inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_onetimeauth_init*(state: ptr crypto_onetimeauth_state;
                              key: ptr cuchar): cint {.importc, cdecl.}
proc crypto_onetimeauth_update*(state: ptr crypto_onetimeauth_state;
                                `in`: ptr cuchar; inlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_onetimeauth_final*(state: ptr crypto_onetimeauth_state;
                               `out`: ptr cuchar): cint {.importc, cdecl.}
proc crypto_onetimeauth_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_ALG_ARGON2I13*(): cint {.
    importc: "crypto_pwhash_argon2i_alg_argon2i13", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_pwhash_argon2i_bytes_min", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_pwhash_argon2i_bytes_max", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_PASSWD_MIN*(): uint {.
    importc: "crypto_pwhash_argon2i_passwd_min", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_PASSWD_MAX*(): uint {.
    importc: "crypto_pwhash_argon2i_passwd_max", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_SALTBYTES*(): uint {.
    importc: "crypto_pwhash_argon2i_saltbytes", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_STRBYTES*(): uint {.
    importc: "crypto_pwhash_argon2i_strbytes", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_STRPREFIX*(): cstring {.
    importc: "crypto_pwhash_argon2i_strprefix", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_OPSLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_argon2i_opslimit_min", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_OPSLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_argon2i_opslimit_max", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_MEMLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_argon2i_memlimit_min", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_MEMLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_argon2i_memlimit_max", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_OPSLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_argon2i_opslimit_interactive", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_MEMLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_argon2i_memlimit_interactive", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_OPSLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_argon2i_opslimit_moderate", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_MEMLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_argon2i_memlimit_moderate", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_OPSLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_argon2i_opslimit_sensitive", cdecl.}
proc crypto_pwhash_argon2i_CONSTANT_MEMLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_argon2i_memlimit_sensitive", cdecl.}
proc crypto_pwhash_argon2i*(`out`: ptr cuchar; outlen: culonglong;
                            passwd: cstring; passwdlen: culonglong;
                            salt: ptr cuchar; opslimit: culonglong;
                            memlimit: uint; alg: cint): cint {.importc, cdecl.}
proc crypto_pwhash_argon2i_str*(`out`: array[128'u, cchar]; passwd: cstring;
                                passwdlen: culonglong; opslimit: culonglong;
                                memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_argon2i_str_verify*(str: array[128'u, cchar];
                                       passwd: cstring; passwdlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_pwhash_argon2i_str_needs_rehash*(str: array[128'u, cchar];
    opslimit: culonglong; memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_ALG_ARGON2ID13*(): cint {.
    importc: "crypto_pwhash_argon2id_alg_argon2id13", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_pwhash_argon2id_bytes_min", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_pwhash_argon2id_bytes_max", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_PASSWD_MIN*(): uint {.
    importc: "crypto_pwhash_argon2id_passwd_min", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_PASSWD_MAX*(): uint {.
    importc: "crypto_pwhash_argon2id_passwd_max", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_SALTBYTES*(): uint {.
    importc: "crypto_pwhash_argon2id_saltbytes", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_STRBYTES*(): uint {.
    importc: "crypto_pwhash_argon2id_strbytes", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_STRPREFIX*(): cstring {.
    importc: "crypto_pwhash_argon2id_strprefix", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_OPSLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_argon2id_opslimit_min", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_OPSLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_argon2id_opslimit_max", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_MEMLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_argon2id_memlimit_min", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_MEMLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_argon2id_memlimit_max", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_OPSLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_argon2id_opslimit_interactive", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_MEMLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_argon2id_memlimit_interactive", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_OPSLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_argon2id_opslimit_moderate", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_MEMLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_argon2id_memlimit_moderate", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_OPSLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_argon2id_opslimit_sensitive", cdecl.}
proc crypto_pwhash_argon2id_CONSTANT_MEMLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_argon2id_memlimit_sensitive", cdecl.}
proc crypto_pwhash_argon2id*(`out`: ptr cuchar; outlen: culonglong;
                             passwd: cstring; passwdlen: culonglong;
                             salt: ptr cuchar; opslimit: culonglong;
                             memlimit: uint; alg: cint): cint {.importc, cdecl.}
proc crypto_pwhash_argon2id_str*(`out`: array[128'u, cchar]; passwd: cstring;
                                 passwdlen: culonglong; opslimit: culonglong;
                                 memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_argon2id_str_verify*(str: array[128'u, cchar];
                                        passwd: cstring; passwdlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_pwhash_argon2id_str_needs_rehash*(str: array[128'u, cchar];
    opslimit: culonglong; memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_CONSTANT_ALG_ARGON2I13*(): cint {.
    importc: "crypto_pwhash_alg_argon2i13", cdecl.}
proc crypto_pwhash_CONSTANT_ALG_ARGON2ID13*(): cint {.
    importc: "crypto_pwhash_alg_argon2id13", cdecl.}
proc crypto_pwhash_alg_default*(): cint {.importc, cdecl.}
proc crypto_pwhash_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_pwhash_bytes_min", cdecl.}
proc crypto_pwhash_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_pwhash_bytes_max", cdecl.}
proc crypto_pwhash_CONSTANT_PASSWD_MIN*(): uint {.
    importc: "crypto_pwhash_passwd_min", cdecl.}
proc crypto_pwhash_CONSTANT_PASSWD_MAX*(): uint {.
    importc: "crypto_pwhash_passwd_max", cdecl.}
proc crypto_pwhash_CONSTANT_SALTBYTES*(): uint {.
    importc: "crypto_pwhash_saltbytes", cdecl.}
proc crypto_pwhash_CONSTANT_STRBYTES*(): uint {.
    importc: "crypto_pwhash_strbytes", cdecl.}
proc crypto_pwhash_CONSTANT_STRPREFIX*(): cstring {.
    importc: "crypto_pwhash_strprefix", cdecl.}
proc crypto_pwhash_CONSTANT_OPSLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_opslimit_min", cdecl.}
proc crypto_pwhash_CONSTANT_OPSLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_opslimit_max", cdecl.}
proc crypto_pwhash_CONSTANT_MEMLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_memlimit_min", cdecl.}
proc crypto_pwhash_CONSTANT_MEMLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_memlimit_max", cdecl.}
proc crypto_pwhash_CONSTANT_OPSLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_opslimit_interactive", cdecl.}
proc crypto_pwhash_CONSTANT_MEMLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_memlimit_interactive", cdecl.}
proc crypto_pwhash_CONSTANT_OPSLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_opslimit_moderate", cdecl.}
proc crypto_pwhash_CONSTANT_MEMLIMIT_MODERATE*(): uint {.
    importc: "crypto_pwhash_memlimit_moderate", cdecl.}
proc crypto_pwhash_CONSTANT_OPSLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_opslimit_sensitive", cdecl.}
proc crypto_pwhash_CONSTANT_MEMLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_memlimit_sensitive", cdecl.}
proc crypto_pwhash*(`out`: ptr cuchar; outlen: culonglong; passwd: cstring;
                    passwdlen: culonglong; salt: ptr cuchar;
                    opslimit: culonglong; memlimit: uint; alg: cint): cint {.
    importc, cdecl.}
proc crypto_pwhash_str*(`out`: array[128'u, cchar]; passwd: cstring;
                        passwdlen: culonglong; opslimit: culonglong;
                        memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_str_alg*(`out`: array[128'u, cchar]; passwd: cstring;
                            passwdlen: culonglong; opslimit: culonglong;
                            memlimit: uint; alg: cint): cint {.importc, cdecl.}
proc crypto_pwhash_str_verify*(str: array[128'u, cchar]; passwd: cstring;
                               passwdlen: culonglong): cint {.importc, cdecl.}
proc crypto_pwhash_str_needs_rehash*(str: array[128'u, cchar];
                                     opslimit: culonglong; memlimit: uint): cint {.
    importc, cdecl.}
proc crypto_pwhash_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_pwhash_primitive", cdecl.}
proc crypto_scalarmult_curve25519_CONSTANT_BYTES*(): uint {.
    importc: "crypto_scalarmult_curve25519_bytes", cdecl.}
proc crypto_scalarmult_curve25519_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_scalarmult_curve25519_scalarbytes", cdecl.}
proc crypto_scalarmult_curve25519*(q: ptr cuchar; n: ptr cuchar; p: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_curve25519_base*(q: ptr cuchar; n: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_CONSTANT_BYTES*(): uint {.
    importc: "crypto_scalarmult_bytes", cdecl.}
proc crypto_scalarmult_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_scalarmult_scalarbytes", cdecl.}
proc crypto_scalarmult_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_scalarmult_primitive", cdecl.}
proc crypto_scalarmult_base*(q: ptr cuchar; n: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_scalarmult*(q: ptr cuchar; n: ptr cuchar; p: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_secretbox_xsalsa20poly1305_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_secretbox_xsalsa20poly1305_keybytes", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_secretbox_xsalsa20poly1305_noncebytes", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_CONSTANT_MACBYTES*(): uint {.
    importc: "crypto_secretbox_xsalsa20poly1305_macbytes", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_secretbox_xsalsa20poly1305*(c: ptr cuchar; m: ptr cuchar;
                                        mlen: culonglong; n: ptr cuchar;
                                        k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_xsalsa20poly1305_open*(m: ptr cuchar; c: ptr cuchar;
    clen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_xsalsa20poly1305_keygen*(k: array[32'u, cuchar]) {.
    importc, cdecl.}
proc crypto_secretbox_xsalsa20poly1305_CONSTANT_BOXZEROBYTES*(): uint {.
    importc: "crypto_secretbox_xsalsa20poly1305_boxzerobytes", cdecl.}
proc crypto_secretbox_xsalsa20poly1305_CONSTANT_ZEROBYTES*(): uint {.
    importc: "crypto_secretbox_xsalsa20poly1305_zerobytes", cdecl.}
proc crypto_secretbox_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_secretbox_keybytes", cdecl.}
proc crypto_secretbox_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_secretbox_noncebytes", cdecl.}
proc crypto_secretbox_CONSTANT_MACBYTES*(): uint {.
    importc: "crypto_secretbox_macbytes", cdecl.}
proc crypto_secretbox_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_secretbox_primitive", cdecl.}
proc crypto_secretbox_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_secretbox_easy*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                            n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_open_easy*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                                 n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_secretbox_detached*(c: ptr cuchar; mac: ptr cuchar; m: ptr cuchar;
                                mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_secretbox_open_detached*(m: ptr cuchar; c: ptr cuchar;
                                     mac: ptr cuchar; clen: culonglong;
                                     n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_secretbox_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_secretbox_CONSTANT_ZEROBYTES*(): uint {.
    importc: "crypto_secretbox_zerobytes", cdecl.}
proc crypto_secretbox_CONSTANT_BOXZEROBYTES*(): uint {.
    importc: "crypto_secretbox_boxzerobytes", cdecl.}
proc crypto_secretbox*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                       n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_open*(m: ptr cuchar; c: ptr cuchar; clen: culonglong;
                            n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_chacha20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_chacha20_keybytes", cdecl.}
proc crypto_stream_chacha20_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_chacha20_noncebytes", cdecl.}
proc crypto_stream_chacha20_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_chacha20*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                             k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_chacha20_xor*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                                 n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_chacha20_xor_ic*(c: ptr cuchar; m: ptr cuchar;
                                    mlen: culonglong; n: ptr cuchar; ic: uint64;
                                    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_chacha20_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_stream_chacha20_ietf_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_chacha20_ietf_keybytes", cdecl.}
proc crypto_stream_chacha20_ietf_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_chacha20_ietf_noncebytes", cdecl.}
proc crypto_stream_chacha20_ietf_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_chacha20_ietf*(c: ptr cuchar; clen: culonglong;
                                  n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_chacha20_ietf_xor*(c: ptr cuchar; m: ptr cuchar;
                                      mlen: culonglong; n: ptr cuchar;
                                      k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_chacha20_ietf_xor_ic*(c: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; n: ptr cuchar; ic: uint32; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_chacha20_ietf_keygen*(k: array[32'u, cuchar]) {.importc,
    cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_ABYTES*(): uint {.
    importc: "crypto_secretstream_xchacha20poly1305_abytes", cdecl.}
proc crypto_secretstream_xchacha20poly1305_headerbytes*(): uint {.importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_secretstream_xchacha20poly1305_keybytes", cdecl.}
proc crypto_secretstream_xchacha20poly1305_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_TAG_MESSAGE*(): cuchar {.
    importc: "crypto_secretstream_xchacha20poly1305_tag_message", cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_TAG_PUSH*(): cuchar {.
    importc: "crypto_secretstream_xchacha20poly1305_tag_push", cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_TAG_REKEY*(): cuchar {.
    importc: "crypto_secretstream_xchacha20poly1305_tag_rekey", cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_TAG_FINAL*(): cuchar {.
    importc: "crypto_secretstream_xchacha20poly1305_tag_final", cdecl.}
proc crypto_secretstream_xchacha20poly1305_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_secretstream_xchacha20poly1305_statebytes", cdecl.}
proc crypto_secretstream_xchacha20poly1305_keygen*(k: array[32'u, cuchar]) {.
    importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_push*(
    state: ptr crypto_secretstream_xchacha20poly1305_state;
    header: array[24'u, cuchar]; k: array[32'u, cuchar]): cint {.importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_push*(
    state: ptr crypto_secretstream_xchacha20poly1305_state; c: ptr cuchar;
    clen_p: ptr culonglong; m: ptr cuchar; mlen: culonglong; ad: ptr cuchar;
    adlen: culonglong; tag: cuchar): cint {.importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_init_pull*(
    state: ptr crypto_secretstream_xchacha20poly1305_state;
    header: array[24'u, cuchar]; k: array[32'u, cuchar]): cint {.importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_pull*(
    state: ptr crypto_secretstream_xchacha20poly1305_state; m: ptr cuchar;
    mlen_p: ptr culonglong; tag_p: ptr cuchar; c: ptr cuchar; clen: culonglong;
    ad: ptr cuchar; adlen: culonglong): cint {.importc, cdecl.}
proc crypto_secretstream_xchacha20poly1305_rekey*(
    state: ptr crypto_secretstream_xchacha20poly1305_state) {.importc, cdecl.}
proc crypto_shorthash_siphash24_CONSTANT_BYTES*(): uint {.
    importc: "crypto_shorthash_siphash24_bytes", cdecl.}
proc crypto_shorthash_siphash24_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_shorthash_siphash24_keybytes", cdecl.}
proc crypto_shorthash_siphash24*(`out`: ptr cuchar; `in`: ptr cuchar;
                                 inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_shorthash_siphashx24_CONSTANT_BYTES*(): uint {.
    importc: "crypto_shorthash_siphashx24_bytes", cdecl.}
proc crypto_shorthash_siphashx24_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_shorthash_siphashx24_keybytes", cdecl.}
proc crypto_shorthash_siphashx24*(`out`: ptr cuchar; `in`: ptr cuchar;
                                  inlen: culonglong; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_shorthash_CONSTANT_BYTES*(): uint {.
    importc: "crypto_shorthash_bytes", cdecl.}
proc crypto_shorthash_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_shorthash_keybytes", cdecl.}
proc crypto_shorthash_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_shorthash_primitive", cdecl.}
proc crypto_shorthash*(`out`: ptr cuchar; `in`: ptr cuchar; inlen: culonglong;
                       k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_shorthash_keygen*(k: array[16'u, cuchar]) {.importc, cdecl.}
proc crypto_sign_ed25519ph_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_sign_ed25519ph_statebytes", cdecl.}
proc crypto_sign_ed25519_CONSTANT_BYTES*(): uint {.
    importc: "crypto_sign_ed25519_bytes", cdecl.}
proc crypto_sign_ed25519_CONSTANT_SEEDBYTES*(): uint {.
    importc: "crypto_sign_ed25519_seedbytes", cdecl.}
proc crypto_sign_ed25519_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_sign_ed25519_publickeybytes", cdecl.}
proc crypto_sign_ed25519_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_sign_ed25519_secretkeybytes", cdecl.}
proc crypto_sign_ed25519_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_sign_ed25519*(sm: ptr cuchar; smlen_p: ptr culonglong;
                          m: ptr cuchar; mlen: culonglong; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519_open*(m: ptr cuchar; mlen_p: ptr culonglong;
                               sm: ptr cuchar; smlen: culonglong; pk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519_detached*(sig: ptr cuchar; siglen_p: ptr culonglong;
                                   m: ptr cuchar; mlen: culonglong;
                                   sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_ed25519_verify_detached*(sig: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_ed25519_keypair*(pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519_seed_keypair*(pk: ptr cuchar; sk: ptr cuchar;
                                       seed: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_ed25519_pk_to_curve25519*(curve25519_pk: ptr cuchar;
    ed25519_pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_ed25519_sk_to_curve25519*(curve25519_sk: ptr cuchar;
    ed25519_sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_ed25519_sk_to_seed*(seed: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519_sk_to_pk*(pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519ph_init*(state: ptr crypto_sign_ed25519ph_state): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519ph_update*(state: ptr crypto_sign_ed25519ph_state;
                                   m: ptr cuchar; mlen: culonglong): cint {.
    importc, cdecl.}
proc crypto_sign_ed25519ph_final_create*(state: ptr crypto_sign_ed25519ph_state;
    sig: ptr cuchar; siglen_p: ptr culonglong; sk: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_sign_ed25519ph_final_verify*(state: ptr crypto_sign_ed25519ph_state;
    sig: ptr cuchar; pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_CONSTANT_STATEBYTES*(): uint {.
    importc: "crypto_sign_statebytes", cdecl.}
proc crypto_sign_CONSTANT_BYTES*(): uint {.importc: "crypto_sign_bytes", cdecl.}
proc crypto_sign_CONSTANT_SEEDBYTES*(): uint {.importc: "crypto_sign_seedbytes",
    cdecl.}
proc crypto_sign_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_sign_publickeybytes", cdecl.}
proc crypto_sign_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_sign_secretkeybytes", cdecl.}
proc crypto_sign_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_sign_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_sign_primitive", cdecl.}
proc crypto_sign_seed_keypair*(pk: ptr cuchar; sk: ptr cuchar; seed: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_keypair*(pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign*(sm: ptr cuchar; smlen_p: ptr culonglong; m: ptr cuchar;
                  mlen: culonglong; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_open*(m: ptr cuchar; mlen_p: ptr culonglong; sm: ptr cuchar;
                       smlen: culonglong; pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_sign_detached*(sig: ptr cuchar; siglen_p: ptr culonglong;
                           m: ptr cuchar; mlen: culonglong; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_verify_detached*(sig: ptr cuchar; m: ptr cuchar;
                                  mlen: culonglong; pk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_init*(state: ptr crypto_sign_state): cint {.importc, cdecl.}
proc crypto_sign_update*(state: ptr crypto_sign_state; m: ptr cuchar;
                         mlen: culonglong): cint {.importc, cdecl.}
proc crypto_sign_final_create*(state: ptr crypto_sign_state; sig: ptr cuchar;
                               siglen_p: ptr culonglong; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_sign_final_verify*(state: ptr crypto_sign_state; sig: ptr cuchar;
                               pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_keybytes", cdecl.}
proc crypto_stream_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_noncebytes", cdecl.}
proc crypto_stream_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_CONSTANT_PRIMITIVE*(): cstring {.
    importc: "crypto_stream_primitive", cdecl.}
proc crypto_stream*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_xor*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                        n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_stream_salsa20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_salsa20_keybytes", cdecl.}
proc crypto_stream_salsa20_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_salsa20_noncebytes", cdecl.}
proc crypto_stream_salsa20_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_salsa20*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                            k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_salsa20_xor*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                                n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_salsa20_xor_ic*(c: ptr cuchar; m: ptr cuchar;
                                   mlen: culonglong; n: ptr cuchar; ic: uint64;
                                   k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_salsa20_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_verify_16_CONSTANT_BYTES*(): uint {.
    importc: "crypto_verify_16_bytes", cdecl.}
proc crypto_verify_16*(x: ptr cuchar; y: ptr cuchar): cint {.importc, cdecl.}
proc crypto_verify_32_CONSTANT_BYTES*(): uint {.
    importc: "crypto_verify_32_bytes", cdecl.}
proc crypto_verify_32*(x: ptr cuchar; y: ptr cuchar): cint {.importc, cdecl.}
proc crypto_verify_64_CONSTANT_BYTES*(): uint {.
    importc: "crypto_verify_64_bytes", cdecl.}
proc crypto_verify_64*(x: ptr cuchar; y: ptr cuchar): cint {.importc, cdecl.}
proc randombytes_CONSTANT_SEEDBYTES*(): uint {.importc: "randombytes_seedbytes",
    cdecl.}
proc randombytes_buf*(buf: pointer; size: uint) {.importc, cdecl.}
proc randombytes_buf_deterministic*(buf: pointer; size: uint;
                                    seed: array[32'u, cuchar]) {.importc, cdecl.}
proc randombytes_random*(): uint32 {.importc, cdecl.}
proc randombytes_uniform*(upper_bound: uint32): uint32 {.importc, cdecl.}
proc randombytes_stir*() {.importc, cdecl.}
proc randombytes_close*(): cint {.importc, cdecl.}
proc randombytes_set_implementation*(impl: ptr randombytes_implementation): cint {.
    importc, cdecl.}
proc randombytes_implementation_name*(): cstring {.importc, cdecl.}
proc randombytes*(buf: ptr cuchar; buf_len: culonglong) {.importc, cdecl.}
proc sodium_runtime_has_neon*(): cint {.importc, cdecl.}
proc sodium_runtime_has_sse2*(): cint {.importc, cdecl.}
proc sodium_runtime_has_sse3*(): cint {.importc, cdecl.}
proc sodium_runtime_has_ssse3*(): cint {.importc, cdecl.}
proc sodium_runtime_has_sse41*(): cint {.importc, cdecl.}
proc sodium_runtime_has_avx*(): cint {.importc, cdecl.}
proc sodium_runtime_has_avx2*(): cint {.importc, cdecl.}
proc sodium_runtime_has_avx512f*(): cint {.importc, cdecl.}
proc sodium_runtime_has_pclmul*(): cint {.importc, cdecl.}
proc sodium_runtime_has_aesni*(): cint {.importc, cdecl.}
proc sodium_runtime_has_rdrand*(): cint {.importc, cdecl.}
proc INTERNAL_sodium_runtime_get_cpu_features*(): cint {.
    importc: "_sodium_runtime_get_cpu_features", cdecl.}
proc sodium_memzero*(pnt: pointer; len: uint) {.importc, cdecl.}
proc sodium_stackzero*(len: uint) {.importc, cdecl.}
proc sodium_memcmp*(b1: pointer; b2: pointer; len: uint): cint {.importc, cdecl.}
proc sodium_compare*(b1: ptr cuchar; b2: ptr cuchar; len: uint): cint {.importc,
    cdecl.}
proc sodium_is_zero*(n: ptr cuchar; nlen: uint): cint {.importc, cdecl.}
proc sodium_increment*(n: ptr cuchar; nlen: uint) {.importc, cdecl.}
proc sodium_add*(a: ptr cuchar; b: ptr cuchar; len: uint) {.importc, cdecl.}
proc sodium_sub*(a: ptr cuchar; b: ptr cuchar; len: uint) {.importc, cdecl.}
proc sodium_bin2hex*(hex: cstring; hex_maxlen: uint; bin: ptr cuchar;
                     bin_len: uint): cstring {.importc, cdecl.}
proc sodium_hex2bin*(bin: ptr cuchar; bin_maxlen: uint; hex: cstring;
                     hex_len: uint; ignore: cstring; bin_len: ptr uint;
                     hex_end: ptr cstring): cint {.importc, cdecl.}
proc sodium_base64_encoded_len*(bin_len: uint; variant: cint): uint {.importc,
    cdecl.}
proc sodium_bin2base64*(b64: cstring; b64_maxlen: uint; bin: ptr cuchar;
                        bin_len: uint; variant: cint): cstring {.importc, cdecl.}
proc sodium_base642bin*(bin: ptr cuchar; bin_maxlen: uint; b64: cstring;
                        b64_len: uint; ignore: cstring; bin_len: ptr uint;
                        b64_end: ptr cstring; variant: cint): cint {.importc,
    cdecl.}
proc sodium_mlock*(`addr`: pointer; len: uint): cint {.importc, cdecl.}
proc sodium_munlock*(`addr`: pointer; len: uint): cint {.importc, cdecl.}
proc sodium_malloc*(size: uint): pointer {.importc, cdecl.}
proc sodium_allocarray*(count: uint; size: uint): pointer {.importc, cdecl.}
proc sodium_free*(`ptr`: pointer) {.importc, cdecl.}
proc sodium_mprotect_noaccess*(`ptr`: pointer): cint {.importc, cdecl.}
proc sodium_mprotect_readonly*(`ptr`: pointer): cint {.importc, cdecl.}
proc sodium_mprotect_readwrite*(`ptr`: pointer): cint {.importc, cdecl.}
proc sodium_pad*(padded_buflen_p: ptr uint; buf: ptr cuchar;
                 unpadded_buflen: uint; blocksize: uint; max_buflen: uint): cint {.
    importc, cdecl.}
proc sodium_unpad*(unpadded_buflen_p: ptr uint; buf: ptr cuchar;
                   padded_buflen: uint; blocksize: uint): cint {.importc, cdecl.}
proc INTERNAL_sodium_alloc_init*(): cint {.importc: "_sodium_alloc_init", cdecl.}
proc crypto_stream_xchacha20_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_xchacha20_keybytes", cdecl.}
proc crypto_stream_xchacha20_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_xchacha20_noncebytes", cdecl.}
proc crypto_stream_xchacha20_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_xchacha20*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                              k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_xchacha20_xor*(c: ptr cuchar; m: ptr cuchar;
                                  mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_stream_xchacha20_xor_ic*(c: ptr cuchar; m: ptr cuchar;
                                     mlen: culonglong; n: ptr cuchar;
                                     ic: uint64; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_xchacha20_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_SEEDBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_seedbytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_PUBLICKEYBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_publickeybytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_SECRETKEYBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_secretkeybytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_BEFORENMBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_beforenmbytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_noncebytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_MACBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_macbytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_box_curve25519xchacha20poly1305_seed_keypair*(pk: ptr cuchar;
    sk: ptr cuchar; seed: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_keypair*(pk: ptr cuchar;
    sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_easy*(c: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; n: ptr cuchar; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_easy*(m: ptr cuchar;
    c: ptr cuchar; clen: culonglong; n: ptr cuchar; pk: ptr cuchar;
    sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_detached*(c: ptr cuchar;
    mac: ptr cuchar; m: ptr cuchar; mlen: culonglong; n: ptr cuchar;
    pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_detached*(m: ptr cuchar;
    c: ptr cuchar; mac: ptr cuchar; clen: culonglong; n: ptr cuchar;
    pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_beforenm*(k: ptr cuchar;
    pk: ptr cuchar; sk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_easy_afternm*(c: ptr cuchar;
    m: ptr cuchar; mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_easy_afternm*(m: ptr cuchar;
    c: ptr cuchar; clen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_detached_afternm*(c: ptr cuchar;
    mac: ptr cuchar; m: ptr cuchar; mlen: culonglong; n: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_open_detached_afternm*(
    m: ptr cuchar; c: ptr cuchar; mac: ptr cuchar; clen: culonglong;
    n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_CONSTANT_SEALBYTES*(): uint {.
    importc: "crypto_box_curve25519xchacha20poly1305_sealbytes", cdecl.}
proc crypto_box_curve25519xchacha20poly1305_seal*(c: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; pk: ptr cuchar): cint {.importc, cdecl.}
proc crypto_box_curve25519xchacha20poly1305_seal_open*(m: ptr cuchar;
    c: ptr cuchar; clen: culonglong; pk: ptr cuchar; sk: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_CONSTANT_BYTES*(): uint {.
    importc: "crypto_core_ed25519_bytes", cdecl.}
proc crypto_core_ed25519_CONSTANT_UNIFORMBYTES*(): uint {.
    importc: "crypto_core_ed25519_uniformbytes", cdecl.}
proc crypto_core_ed25519_CONSTANT_HASHBYTES*(): uint {.
    importc: "crypto_core_ed25519_hashbytes", cdecl.}
proc crypto_core_ed25519_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_core_ed25519_scalarbytes", cdecl.}
proc crypto_core_ed25519_CONSTANT_NONREDUCEDSCALARBYTES*(): uint {.
    importc: "crypto_core_ed25519_nonreducedscalarbytes", cdecl.}
proc crypto_core_ed25519_is_valid_point*(p: ptr cuchar): cint {.importc, cdecl.}
proc crypto_core_ed25519_add*(r: ptr cuchar; p: ptr cuchar; q: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_sub*(r: ptr cuchar; p: ptr cuchar; q: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_from_uniform*(p: ptr cuchar; r: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_from_hash*(p: ptr cuchar; h: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_random*(p: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ed25519_scalar_random*(r: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ed25519_scalar_invert*(recip: ptr cuchar; s: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_negate*(neg: ptr cuchar; s: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_complement*(comp: ptr cuchar; s: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_add*(z: ptr cuchar; x: ptr cuchar; y: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_sub*(z: ptr cuchar; x: ptr cuchar; y: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_mul*(z: ptr cuchar; x: ptr cuchar; y: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ed25519_scalar_reduce*(r: ptr cuchar; s: ptr cuchar) {.importc,
    cdecl.}
proc crypto_core_ristretto255_CONSTANT_BYTES*(): uint {.
    importc: "crypto_core_ristretto255_bytes", cdecl.}
proc crypto_core_ristretto255_CONSTANT_HASHBYTES*(): uint {.
    importc: "crypto_core_ristretto255_hashbytes", cdecl.}
proc crypto_core_ristretto255_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_core_ristretto255_scalarbytes", cdecl.}
proc crypto_core_ristretto255_CONSTANT_NONREDUCEDSCALARBYTES*(): uint {.
    importc: "crypto_core_ristretto255_nonreducedscalarbytes", cdecl.}
proc crypto_core_ristretto255_is_valid_point*(p: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_core_ristretto255_add*(r: ptr cuchar; p: ptr cuchar; q: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ristretto255_sub*(r: ptr cuchar; p: ptr cuchar; q: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ristretto255_from_hash*(p: ptr cuchar; r: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ristretto255_random*(p: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ristretto255_scalar_random*(r: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ristretto255_scalar_invert*(recip: ptr cuchar; s: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_core_ristretto255_scalar_negate*(neg: ptr cuchar; s: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ristretto255_scalar_complement*(comp: ptr cuchar; s: ptr cuchar) {.
    importc, cdecl.}
proc crypto_core_ristretto255_scalar_add*(z: ptr cuchar; x: ptr cuchar;
    y: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ristretto255_scalar_sub*(z: ptr cuchar; x: ptr cuchar;
    y: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ristretto255_scalar_mul*(z: ptr cuchar; x: ptr cuchar;
    y: ptr cuchar) {.importc, cdecl.}
proc crypto_core_ristretto255_scalar_reduce*(r: ptr cuchar; s: ptr cuchar) {.
    importc, cdecl.}
proc crypto_scalarmult_ed25519_CONSTANT_BYTES*(): uint {.
    importc: "crypto_scalarmult_ed25519_bytes", cdecl.}
proc crypto_scalarmult_ed25519_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_scalarmult_ed25519_scalarbytes", cdecl.}
proc crypto_scalarmult_ed25519*(q: ptr cuchar; n: ptr cuchar; p: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_ed25519_noclamp*(q: ptr cuchar; n: ptr cuchar;
                                        p: ptr cuchar): cint {.importc, cdecl.}
proc crypto_scalarmult_ed25519_base*(q: ptr cuchar; n: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_ed25519_base_noclamp*(q: ptr cuchar; n: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_ristretto255_CONSTANT_BYTES*(): uint {.
    importc: "crypto_scalarmult_ristretto255_bytes", cdecl.}
proc crypto_scalarmult_ristretto255_CONSTANT_SCALARBYTES*(): uint {.
    importc: "crypto_scalarmult_ristretto255_scalarbytes", cdecl.}
proc crypto_scalarmult_ristretto255*(q: ptr cuchar; n: ptr cuchar; p: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_scalarmult_ristretto255_base*(q: ptr cuchar; n: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_secretbox_xchacha20poly1305_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_secretbox_xchacha20poly1305_keybytes", cdecl.}
proc crypto_secretbox_xchacha20poly1305_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_secretbox_xchacha20poly1305_noncebytes", cdecl.}
proc crypto_secretbox_xchacha20poly1305_CONSTANT_MACBYTES*(): uint {.
    importc: "crypto_secretbox_xchacha20poly1305_macbytes", cdecl.}
proc crypto_secretbox_xchacha20poly1305_messagebytes_max*(): uint {.importc,
    cdecl.}
proc crypto_secretbox_xchacha20poly1305_easy*(c: ptr cuchar; m: ptr cuchar;
    mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_xchacha20poly1305_open_easy*(m: ptr cuchar; c: ptr cuchar;
    clen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_xchacha20poly1305_detached*(c: ptr cuchar;
    mac: ptr cuchar; m: ptr cuchar; mlen: culonglong; n: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_secretbox_xchacha20poly1305_open_detached*(m: ptr cuchar;
    c: ptr cuchar; mac: ptr cuchar; clen: culonglong; n: ptr cuchar;
    k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_BYTES_MIN*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_bytes_min", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_BYTES_MAX*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_bytes_max", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_PASSWD_MIN*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_passwd_min", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_PASSWD_MAX*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_passwd_max", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_SALTBYTES*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_saltbytes", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_STRBYTES*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_strbytes", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_STRPREFIX*(): cstring {.
    importc: "crypto_pwhash_scryptsalsa208sha256_strprefix", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_OPSLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_opslimit_min", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_OPSLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_opslimit_max", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_MEMLIMIT_MIN*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_memlimit_min", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_MEMLIMIT_MAX*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_memlimit_max", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_OPSLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_opslimit_interactive", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_MEMLIMIT_INTERACTIVE*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_memlimit_interactive", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_OPSLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_opslimit_sensitive", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_CONSTANT_MEMLIMIT_SENSITIVE*(): uint {.
    importc: "crypto_pwhash_scryptsalsa208sha256_memlimit_sensitive", cdecl.}
proc crypto_pwhash_scryptsalsa208sha256*(`out`: ptr cuchar; outlen: culonglong;
    passwd: cstring; passwdlen: culonglong; salt: ptr cuchar;
    opslimit: culonglong; memlimit: uint): cint {.importc, cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str*(`out`: array[102'u, cchar];
    passwd: cstring; passwdlen: culonglong; opslimit: culonglong; memlimit: uint): cint {.
    importc, cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str_verify*(str: array[102'u, cchar];
    passwd: cstring; passwdlen: culonglong): cint {.importc, cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_ll*(passwd: ptr uint8; passwdlen: uint;
    salt: ptr uint8; saltlen: uint; N: uint64; r: uint32; p: uint32;
    buf: ptr uint8; buflen: uint): cint {.importc, cdecl.}
proc crypto_pwhash_scryptsalsa208sha256_str_needs_rehash*(
    str: array[102'u, cchar]; opslimit: culonglong; memlimit: uint): cint {.
    importc, cdecl.}
proc crypto_stream_salsa2012_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_salsa2012_keybytes", cdecl.}
proc crypto_stream_salsa2012_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_salsa2012_noncebytes", cdecl.}
proc crypto_stream_salsa2012_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_salsa2012*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                              k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_salsa2012_xor*(c: ptr cuchar; m: ptr cuchar;
                                  mlen: culonglong; n: ptr cuchar; k: ptr cuchar): cint {.
    importc, cdecl.}
proc crypto_stream_salsa2012_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
proc crypto_stream_salsa208_CONSTANT_KEYBYTES*(): uint {.
    importc: "crypto_stream_salsa208_keybytes", cdecl.}
proc crypto_stream_salsa208_CONSTANT_NONCEBYTES*(): uint {.
    importc: "crypto_stream_salsa208_noncebytes", cdecl.}
proc crypto_stream_salsa208_messagebytes_max*(): uint {.importc, cdecl.}
proc crypto_stream_salsa208*(c: ptr cuchar; clen: culonglong; n: ptr cuchar;
                             k: ptr cuchar): cint {.importc, cdecl.}
proc crypto_stream_salsa208_xor*(c: ptr cuchar; m: ptr cuchar; mlen: culonglong;
                                 n: ptr cuchar; k: ptr cuchar): cint {.importc,
    cdecl.}
proc crypto_stream_salsa208_keygen*(k: array[32'u, cuchar]) {.importc, cdecl.}
{.pop.}
