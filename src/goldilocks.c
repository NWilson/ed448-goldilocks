/* Copyright (c) 2014 Cryptography Research, Inc.
 * Released under the MIT License.  See LICENSE.txt for license information.
 */

#include "config.h"
#include "word.h"

#include <errno.h>

#if GOLDILOCKS_USE_PTHREAD
#include <pthread.h>
#else
static const char *
compare_and_swap (
    const char *volatile* target,
    const char *old,
    const char *new
) {
    const char* ret = *target; if (*target == old) *target = new; return ret;
}
static int
bool_compare_and_swap (
    const char *volatile* target,
    const char *old,
    const char *new
) {
    if (*target != old) return 0;
    *target = new;
    return 1;
}
#endif

#include "goldilocks.h"
#include "ec_point.h"
#include "scalarmul.h"
#include "barrett_field.h"

#define GOLDI_DIVERSIFY_BYTES 8

/* These are just unique identifiers */
static const char *G_INITING = "initializing";
static const char *G_INITED = "initialized";
static const char *G_FAILED = "failed to initialize";

struct goldilocks_precomputed_public_key_t {
    struct goldilocks_public_key_t pub;
    struct fixed_base_table_t table;
};

/* FUTURE: auto. */
static struct {
    const char * volatile state;
#if GOLDILOCKS_USE_PTHREAD
    pthread_mutex_t mutex;
#endif
    struct tw_niels_t combs[COMB_N << (COMB_T-1)];
    struct fixed_base_table_t fixed_base;
    struct tw_niels_t wnafs[1<<WNAF_PRECMP_BITS];
} goldilocks_global;

static inline mask_t
goldilocks_check_init() {
    if (likely(goldilocks_global.state == G_INITED)) {
        return MASK_SUCCESS;
    } else {
        return MASK_FAILURE;
    }
}

int
goldilocks_init () {
    const char *res = compare_and_swap(&goldilocks_global.state, NULL, G_INITING);
    if (res == G_INITED) return GOLDI_EALREADYINIT;
    else if (res) {
        return GOLDI_ECORRUPT;
    }

#if GOLDILOCKS_USE_PTHREAD
    int ret = pthread_mutex_init(&goldilocks_global.mutex, NULL);
    if (ret) goto fail;
#endif
    
    struct extensible_t ext;
    struct tw_extensible_t text;
    
    /* Sanity check: the base point is on the curve. */
    assert(validate_affine(&goldilocks_base_point));
    
    /* Convert it to twisted Edwards. */
    convert_affine_to_extensible(&ext, &goldilocks_base_point);
    twist_even(&text, &ext);
    
    /* Precompute the tables. */
    mask_t succ;

    succ =  precompute_fixed_base(&goldilocks_global.fixed_base, &text,
        COMB_N, COMB_T, COMB_S, goldilocks_global.combs);
    succ &= precompute_fixed_base_wnaf(goldilocks_global.wnafs, &text, WNAF_PRECMP_BITS);

    if (succ) {
        if (!bool_compare_and_swap(&goldilocks_global.state, G_INITING, G_INITED)) {
            abort();
        }
        return 0;
    }
    
    /* it failed! fall though... */
#if GOLDILOCKS_USE_PTHREAD
fail:
#endif
    if (!bool_compare_and_swap(&goldilocks_global.state, G_INITING, G_FAILED)) {
        /* ok something is seriously wrong */
        abort();
    }
    return -1;
}

int
goldilocks_derive_private_key (
    struct goldilocks_private_key_t *privkey,
    const unsigned char proto[GOLDI_FIELD_BYTES]
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    struct tw_extensible_t exta;
    struct field_t pk;

    word_t sk[GOLDI_FIELD_WORDS];
    barrett_deserialize_and_reduce(sk, proto, GOLDI_FIELD_BYTES, &curve_prime_order);
    barrett_serialize(privkey->opaque, sk, GOLDI_FIELD_BYTES);

    scalarmul_fixed_base(&exta, sk, GOLDI_SCALAR_BITS, &goldilocks_global.fixed_base);
    untwist_and_double_and_serialize(&pk, &exta);
    
    field_serialize(&privkey->opaque[GOLDI_FIELD_BYTES], &pk);
    
    return GOLDI_EOK;
}

int
goldilocks_keygen (
    struct goldilocks_private_key_t *privkey,
    struct goldilocks_public_key_t *pubkey,
    const unsigned char proto[GOLDI_FIELD_BYTES]
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }

    int ret = goldilocks_derive_private_key(privkey, proto);

    if (!ret) ret = goldilocks_private_to_public(pubkey, privkey);

    return ret;
}

int
goldilocks_private_to_public (
    struct goldilocks_public_key_t *pubkey,
    const struct goldilocks_private_key_t *privkey
) {
    struct field_t pk;
    mask_t msucc = field_deserialize(&pk,&privkey->opaque[GOLDI_FIELD_BYTES]);
    
    if (msucc) {
        field_serialize(pubkey->opaque, &pk);
        return GOLDI_EOK;
    } else {
        return GOLDI_ECORRUPT;
    }
}

static int
goldilocks_shared_secret_core (
    uint8_t shared[GOLDI_FIELD_BYTES],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_public_key_t *your_pubkey,
    const struct goldilocks_precomputed_public_key_t *pre
) {
    /* This function doesn't actually need anything in goldilocks_global,
     * so it doesn't check init.
     */
    
    word_t sk[GOLDI_FIELD_WORDS];
    struct field_t pk;
    
    mask_t succ = field_deserialize(&pk,your_pubkey->opaque), msucc = -1;
    
    msucc &= barrett_deserialize(sk,my_privkey->opaque,&curve_prime_order);
    
#if GOLDI_IMPLEMENT_PRECOMPUTED_KEYS
    if (pre) {
        struct tw_extensible_t tw;
        succ &= scalarmul_fixed_base(&tw, sk, GOLDI_SCALAR_BITS, &pre->table);
        untwist_and_double_and_serialize(&pk, &tw);
    } else {
        succ &= montgomery_ladder(&pk,&pk,sk,GOLDI_SCALAR_BITS,1);
    }
#else
    (void)pre;
    succ &= montgomery_ladder(&pk,&pk,sk,GOLDI_SCALAR_BITS,1);
#endif
    
    
    field_serialize(shared,&pk);
    
    return (GOLDI_ECORRUPT & ~msucc)
        | (GOLDI_EINVAL & msucc &~ succ)
        | (GOLDI_EOK & msucc & succ);
}

int
goldilocks_shared_secret (
    uint8_t shared[GOLDI_SHARED_SECRET_BYTES],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_public_key_t *your_pubkey
) {
    return goldilocks_shared_secret_core(
        shared,
        my_privkey,
        your_pubkey,
        NULL
    );
}

#ifdef GOLDI_IMPLEMENT_SIGNATURES
static void
goldilocks_derive_challenge(
    word_t challenge[GOLDI_FIELD_WORDS],
    const unsigned char pubkey[GOLDI_FIELD_BYTES],
    const unsigned char gnonce[GOLDI_FIELD_BYTES],
    const unsigned char *message,
    uint64_t message_len
) {
    /* challenge = H(pk, [nonceG], message). */
    unsigned char sha_out[SHA512_OUTPUT_BYTES];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, pubkey, GOLDI_FIELD_BYTES);
    sha512_update(&ctx, gnonce, GOLDI_FIELD_BYTES);
    sha512_update(&ctx, message, message_len);
    sha512_final(&ctx, sha_out);
    barrett_deserialize_and_reduce(challenge, sha_out, sizeof(sha_out), &curve_prime_order);
}

int
goldilocks_sign (
    uint8_t signature_out[GOLDI_SIGNATURE_BYTES],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_private_key_t *privkey
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    /* challenge = H(pk, [nonceG], message). */
    word_t skw[GOLDI_FIELD_WORDS];
    mask_t succ = barrett_deserialize(skw,privkey->opaque,&curve_prime_order);
    if (!succ) {
        really_memset(skw,0,sizeof(skw));
        return GOLDI_ECORRUPT;
    }
        
    /* Derive a nonce.  TODO: use HMAC. FUTURE: factor. */
    unsigned char sha_out[SHA512_OUTPUT_BYTES];
    word_t tk[GOLDI_FIELD_WORDS];
    struct sha512_ctx_t ctx;
    sha512_init(&ctx);
    sha512_update(&ctx, (const unsigned char *)"signonce", 8);
    sha512_update(&ctx, &privkey->opaque[2*GOLDI_FIELD_BYTES], GOLDI_SYMKEY_BYTES);
    sha512_update(&ctx, message, message_len);
    sha512_update(&ctx, &privkey->opaque[2*GOLDI_FIELD_BYTES], GOLDI_SYMKEY_BYTES);
    sha512_final(&ctx, sha_out);
    barrett_deserialize_and_reduce(tk, sha_out, SHA512_OUTPUT_BYTES, &curve_prime_order);
    
    /* 4[nonce]G */
    uint8_t signature_tmp[GOLDI_FIELD_BYTES];
    struct tw_extensible_t exta;
    struct field_t gsk;
    scalarmul_fixed_base(&exta, tk, GOLDI_SCALAR_BITS, &goldilocks_global.fixed_base);
    double_tw_extensible(&exta);
    untwist_and_double_and_serialize(&gsk, &exta);
    field_serialize(signature_tmp, &gsk);
    
    word_t challenge[GOLDI_FIELD_WORDS];
    goldilocks_derive_challenge (
        challenge,
        &privkey->opaque[GOLDI_FIELD_BYTES],
        signature_tmp,
        message,
        message_len
    );
    
    /* reduce challenge and sub. */
    barrett_negate(challenge,GOLDI_FIELD_WORDS,&curve_prime_order);

    barrett_mac(
        tk,GOLDI_FIELD_WORDS,
        challenge,GOLDI_FIELD_WORDS,
        skw,GOLDI_FIELD_WORDS,
        &curve_prime_order
    );
        
    word_t carry = add_nr_ext_packed(tk,tk,GOLDI_FIELD_WORDS,tk,GOLDI_FIELD_WORDS,-1);
    barrett_reduce(tk,GOLDI_FIELD_WORDS,carry,&curve_prime_order);
        
    memcpy(signature_out, signature_tmp, GOLDI_FIELD_BYTES);
    barrett_serialize(signature_out+GOLDI_FIELD_BYTES, tk, GOLDI_FIELD_BYTES);
    really_memset((unsigned char *)tk,0,sizeof(tk));
    really_memset((unsigned char *)skw,0,sizeof(skw));
    really_memset((unsigned char *)challenge,0,sizeof(challenge));
    
    /* response = 2(nonce_secret - sk*challenge)
     * Nonce = 8[nonce_secret]*G
     * PK = 2[sk]*G, except doubled (TODO)
     * so [2] ( [response]G + 2[challenge]PK ) = Nonce
     */
    
    return 0;
}

int
goldilocks_verify (
    const uint8_t signature[GOLDI_SIGNATURE_BYTES],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_public_key_t *pubkey
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }
    
    struct field_t pk;
    word_t s[GOLDI_FIELD_WORDS];
    
    mask_t succ = field_deserialize(&pk,pubkey->opaque);
    if (!succ) return GOLDI_EINVAL;
    
    succ = barrett_deserialize(s, &signature[GOLDI_FIELD_BYTES], &curve_prime_order);
    if (!succ) return GOLDI_EINVAL;
    
    word_t challenge[GOLDI_FIELD_WORDS];
    goldilocks_derive_challenge(challenge, pubkey->opaque, signature, message, message_len);
    
    struct field_t eph;
    struct tw_extensible_t pk_text;
    
    /* deserialize [nonce]G */
    succ = field_deserialize(&eph, signature);
    if (!succ) return GOLDI_EINVAL;
    
    succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
    if (!succ) return GOLDI_EINVAL;
    
    linear_combo_var_fixed_vt( &pk_text,
        challenge, GOLDI_SCALAR_BITS,
        s, GOLDI_SCALAR_BITS,
        goldilocks_global.wnafs, WNAF_PRECMP_BITS );
    
    untwist_and_double_and_serialize( &pk, &pk_text );
    field_sub(&eph, &eph, &pk);
    field_bias(&eph, 2);
    
    succ = field_is_zero(&eph);
    
    return succ ? 0 : GOLDI_EINVAL;
}
#endif

#if GOLDI_IMPLEMENT_PRECOMPUTED_KEYS

struct goldilocks_precomputed_public_key_t *
goldilocks_precompute_public_key (
    const struct goldilocks_public_key_t *pub    
) {
    struct goldilocks_precomputed_public_key_t *precom;
    precom = (struct goldilocks_precomputed_public_key_t *)
        malloc(sizeof(*precom));
    
    if (!precom) return NULL;
    
    struct tw_extensible_t pk_text;
    
    struct field_t pk;
    mask_t succ = field_deserialize(&pk, pub->opaque);
    if (!succ) {
        free(precom);
        return NULL;
    }
    
    succ = deserialize_and_twist_approx(&pk_text, &sqrt_d_minus_1, &pk);
    if (!succ) {
        free(precom);
        return NULL;
    }

    succ =  precompute_fixed_base(&precom->table, &pk_text,
        COMB_N, COMB_T, COMB_S, NULL);
    if (!succ) {
        free(precom);
        return NULL;
    }
    
    memcpy(&precom->pub,pub,sizeof(*pub));
    
    return precom;
}

void
goldilocks_destroy_precomputed_public_key (
    struct goldilocks_precomputed_public_key_t *precom
) {
    if (!precom) return;
    destroy_fixed_base(&precom->table);
    really_memset(&precom->pub.opaque, 0, sizeof(precom->pub));
    free(precom);
}

int
goldilocks_verify_precomputed (
    const uint8_t signature[GOLDI_SIGNATURE_BYTES],
    const uint8_t *message,
    uint64_t message_len,
    const struct goldilocks_precomputed_public_key_t *pubkey
) {
    if (!goldilocks_check_init()) {
        return GOLDI_EUNINIT;
    }

    word_t s[GOLDI_FIELD_WORDS];
    mask_t succ = barrett_deserialize(s, &signature[GOLDI_FIELD_BYTES], &curve_prime_order);
    if (!succ) return GOLDI_EINVAL;
    
    word_t challenge[GOLDI_FIELD_WORDS];
    goldilocks_derive_challenge(challenge, pubkey->pub.opaque, signature, message, message_len);
    
    struct field_t eph, pk;
    struct tw_extensible_t pk_text;
    
    /* deserialize [nonce]G */
    succ = field_deserialize(&eph, signature);
    if (!succ) return GOLDI_EINVAL;
        
    succ = linear_combo_combs_vt (
        &pk_text,
        challenge, GOLDI_SCALAR_BITS, &pubkey->table,
        s, GOLDI_SCALAR_BITS, &goldilocks_global.fixed_base
    );
    if (!succ) return GOLDI_EINVAL;
    
    untwist_and_double_and_serialize( &pk, &pk_text );
    field_sub(&eph, &eph, &pk);
    field_bias(&eph, 2);
    
    succ = field_is_zero(&eph);
    
    return succ ? 0 : GOLDI_EINVAL;
}

int
goldilocks_shared_secret_precomputed (
    uint8_t shared[GOLDI_SHARED_SECRET_BYTES],
    const struct goldilocks_private_key_t *my_privkey,
    const struct goldilocks_precomputed_public_key_t *your_pubkey
) {
    return goldilocks_shared_secret_core(
        shared,
        my_privkey,
        &your_pubkey->pub,
        your_pubkey
    );
}

#endif /* GOLDI_IMPLEMENT_PRECOMPUTED_KEYS */

