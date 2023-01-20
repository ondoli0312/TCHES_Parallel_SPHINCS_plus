#include "type.cuh"
void CPU_u32_to_bytes(uint8_t* out, uint32_t in) {
    out[0] = (uint8_t)(in >> 24);
    out[1] = (uint8_t)(in >> 16);
    out[2] = (uint8_t)(in >> 8);
    out[3] = (uint8_t)in;
}
void CPU_ull_to_bytes(uint8_t* out, uint32_t outlen, uint64_t in) {
    int i;
    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}
void CPU_set_tree_addr(uint32_t addr[8], uint64_t tree) {
    CPU_ull_to_bytes(&((uint8_t*)addr)[OFFSET_TREE], 8, tree);
}
void CPU_set_keypair_addr(uint32_t addr[8], uint32_t keypair) {
#if FULL_HEIGHT/SUBTREE_LAYER > 8
    ((uint8_t*)addr)[OFFSET_KP_ADDR2] = keypair;
#endif
    ((uint8_t*)addr)[OFFSET_KP_ADDR1] = keypair;
}
void CPU_message_to_indices(uint32_t* indices, uint8_t* m) {
    uint32_t i, j;
    uint32_t offset = 0;
    for (i = 0; i < FORS_TREE; i++) {
        indices[i] = 0;
        for (j = 0; j < FORS_HEIGHT; j++) {
            indices[i] ^= ((m[offset >> 3] >> (offset & 0x7)) & 0x1) << j;
            offset++;
        }
    }
}
void CPU_store_bigendian_32(uint8_t* x, uint64_t u) {
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}
void CPU_store_bigendian_64(uint8_t* x, uint64_t u) {
    x[7] = (uint8_t)u;
    u >>= 8;
    x[6] = (uint8_t)u;
    u >>= 8;
    x[5] = (uint8_t)u;
    u >>= 8;
    x[4] = (uint8_t)u;
    u >>= 8;
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}
uint64_t CPU_bytes_to_ull(uint8_t* in, uint32_t inlen) {
    uint64_t retval = 0;
    uint32_t i;
    for (i = 0; i < inlen; i++) {
        retval |= ((uint64_t)in[i]) << (8 * (inlen - 1 - i));
    }
    return retval;
}
uint32_t CPU_load_bigendian_32(uint8_t* x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
        (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}
uint64_t CPU_load_bigendian_64(const uint8_t* x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
        (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
        (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
        (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}

#ifdef USE_GPU_SPHINCS_SHA256
//!SHA256 MACRO
#define SHR(x, c) ((x) >> (c))
#define ROTR_32(x, c) (((x) >> (c)) | ((x) << (32 - (c))))
#define ROTR_64(x, c) (((x) >> (c)) | ((x) << (64 - (c))))

#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define Sigma0_32(x) (ROTR_32(x, 2) ^ ROTR_32(x,13) ^ ROTR_32(x,22))
#define Sigma1_32(x) (ROTR_32(x, 6) ^ ROTR_32(x,11) ^ ROTR_32(x,25))
#define sigma0_32(x) (ROTR_32(x, 7) ^ ROTR_32(x,18) ^ SHR(x, 3))
#define sigma1_32(x) (ROTR_32(x,17) ^ ROTR_32(x,19) ^ SHR(x,10))

#define M_32(w0, w14, w9, w1) w0 = sigma1_32(w14) + (w9) + sigma0_32(w1) + (w0);

#define EXPAND_32           \
    M_32(w0, w14, w9, w1)   \
    M_32(w1, w15, w10, w2)  \
    M_32(w2, w0, w11, w3)   \
    M_32(w3, w1, w12, w4)   \
    M_32(w4, w2, w13, w5)   \
    M_32(w5, w3, w14, w6)   \
    M_32(w6, w4, w15, w7)   \
    M_32(w7, w5, w0, w8)    \
    M_32(w8, w6, w1, w9)    \
    M_32(w9, w7, w2, w10)   \
    M_32(w10, w8, w3, w11)  \
    M_32(w11, w9, w4, w12)  \
    M_32(w12, w10, w5, w13) \
    M_32(w13, w11, w6, w14) \
    M_32(w14, w12, w7, w15) \
    M_32(w15, w13, w8, w0)

#define F_32(w, k)                                   \
    T1 = h + Sigma1_32(e) + Ch(e, f, g) + (k) + (w); \
    T2 = Sigma0_32(a) + Maj(a, b, c);                \
    h = g;                                           \
    g = f;                                           \
    f = e;                                           \
    e = d + T1;                                      \
    d = c;                                           \
    c = b;                                           \
    b = a;                                           \
    a = T1 + T2;

//!SHA256 functions
uint8_t iv_256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};
void CPU_sha256_inc_init(uint8_t* state) {
    for (int i = 0; i < 32; i++)
        state[i] = iv_256[i];
    for (int i = 32; i < 40; i++)
        state[i] = 0;
}
size_t CPU_crypto_hashblock_sha256(uint8_t* statebytes, uint8_t* in, size_t inlen) {
    uint32_t state[8];
    uint32_t a;
    uint32_t b;
    uint32_t c;
    uint32_t d;
    uint32_t e;
    uint32_t f;
    uint32_t g;
    uint32_t h;
    uint32_t T1;
    uint32_t T2;

    a = CPU_load_bigendian_32(statebytes + 0);
    state[0] = a;
    b = CPU_load_bigendian_32(statebytes + 4);
    state[1] = b;
    c = CPU_load_bigendian_32(statebytes + 8);
    state[2] = c;
    d = CPU_load_bigendian_32(statebytes + 12);
    state[3] = d;
    e = CPU_load_bigendian_32(statebytes + 16);
    state[4] = e;
    f = CPU_load_bigendian_32(statebytes + 20);
    state[5] = f;
    g = CPU_load_bigendian_32(statebytes + 24);
    state[6] = g;
    h = CPU_load_bigendian_32(statebytes + 28);
    state[7] = h;

    while (inlen >= 64) {
        uint32_t w0 = CPU_load_bigendian_32(in + 0);
        uint32_t w1 = CPU_load_bigendian_32(in + 4);
        uint32_t w2 = CPU_load_bigendian_32(in + 8);
        uint32_t w3 = CPU_load_bigendian_32(in + 12);
        uint32_t w4 = CPU_load_bigendian_32(in + 16);
        uint32_t w5 = CPU_load_bigendian_32(in + 20);
        uint32_t w6 = CPU_load_bigendian_32(in + 24);
        uint32_t w7 = CPU_load_bigendian_32(in + 28);
        uint32_t w8 = CPU_load_bigendian_32(in + 32);
        uint32_t w9 = CPU_load_bigendian_32(in + 36);
        uint32_t w10 = CPU_load_bigendian_32(in + 40);
        uint32_t w11 = CPU_load_bigendian_32(in + 44);
        uint32_t w12 = CPU_load_bigendian_32(in + 48);
        uint32_t w13 = CPU_load_bigendian_32(in + 52);
        uint32_t w14 = CPU_load_bigendian_32(in + 56);
        uint32_t w15 = CPU_load_bigendian_32(in + 60);

        F_32(w0, 0x428a2f98)
            F_32(w1, 0x71374491)
            F_32(w2, 0xb5c0fbcf)
            F_32(w3, 0xe9b5dba5)
            F_32(w4, 0x3956c25b)
            F_32(w5, 0x59f111f1)
            F_32(w6, 0x923f82a4)
            F_32(w7, 0xab1c5ed5)
            F_32(w8, 0xd807aa98)
            F_32(w9, 0x12835b01)
            F_32(w10, 0x243185be)
            F_32(w11, 0x550c7dc3)
            F_32(w12, 0x72be5d74)
            F_32(w13, 0x80deb1fe)
            F_32(w14, 0x9bdc06a7)
            F_32(w15, 0xc19bf174)

            EXPAND_32

            F_32(w0, 0xe49b69c1)
            F_32(w1, 0xefbe4786)
            F_32(w2, 0x0fc19dc6)
            F_32(w3, 0x240ca1cc)
            F_32(w4, 0x2de92c6f)
            F_32(w5, 0x4a7484aa)
            F_32(w6, 0x5cb0a9dc)
            F_32(w7, 0x76f988da)
            F_32(w8, 0x983e5152)
            F_32(w9, 0xa831c66d)
            F_32(w10, 0xb00327c8)
            F_32(w11, 0xbf597fc7)
            F_32(w12, 0xc6e00bf3)
            F_32(w13, 0xd5a79147)
            F_32(w14, 0x06ca6351)
            F_32(w15, 0x14292967)

            EXPAND_32

            F_32(w0, 0x27b70a85)
            F_32(w1, 0x2e1b2138)
            F_32(w2, 0x4d2c6dfc)
            F_32(w3, 0x53380d13)
            F_32(w4, 0x650a7354)
            F_32(w5, 0x766a0abb)
            F_32(w6, 0x81c2c92e)
            F_32(w7, 0x92722c85)
            F_32(w8, 0xa2bfe8a1)
            F_32(w9, 0xa81a664b)
            F_32(w10, 0xc24b8b70)
            F_32(w11, 0xc76c51a3)
            F_32(w12, 0xd192e819)
            F_32(w13, 0xd6990624)
            F_32(w14, 0xf40e3585)
            F_32(w15, 0x106aa070)

            EXPAND_32

            F_32(w0, 0x19a4c116)
            F_32(w1, 0x1e376c08)
            F_32(w2, 0x2748774c)
            F_32(w3, 0x34b0bcb5)
            F_32(w4, 0x391c0cb3)
            F_32(w5, 0x4ed8aa4a)
            F_32(w6, 0x5b9cca4f)
            F_32(w7, 0x682e6ff3)
            F_32(w8, 0x748f82ee)
            F_32(w9, 0x78a5636f)
            F_32(w10, 0x84c87814)
            F_32(w11, 0x8cc70208)
            F_32(w12, 0x90befffa)
            F_32(w13, 0xa4506ceb)
            F_32(w14, 0xbef9a3f7)
            F_32(w15, 0xc67178f2)

            a += state[0];
        b += state[1];
        c += state[2];
        d += state[3];
        e += state[4];
        f += state[5];
        g += state[6];
        h += state[7];

        state[0] = a;
        state[1] = b;
        state[2] = c;
        state[3] = d;
        state[4] = e;
        state[5] = f;
        state[6] = g;
        state[7] = h;

        in += 64;
        inlen -= 64;
    }

    CPU_store_bigendian_32(statebytes + 0, state[0]);
    CPU_store_bigendian_32(statebytes + 4, state[1]);
    CPU_store_bigendian_32(statebytes + 8, state[2]);
    CPU_store_bigendian_32(statebytes + 12, state[3]);
    CPU_store_bigendian_32(statebytes + 16, state[4]);
    CPU_store_bigendian_32(statebytes + 20, state[5]);
    CPU_store_bigendian_32(statebytes + 24, state[6]);
    CPU_store_bigendian_32(statebytes + 28, state[7]);

    return inlen;
}
void CPU_sha256_inc_block(uint8_t* state, uint8_t* in, size_t inblocks) {
    uint64_t bytes = CPU_load_bigendian_64(state + 32);
    CPU_crypto_hashblock_sha256(state, in, 64 * inblocks);
    bytes += (64 * inblocks);
    CPU_store_bigendian_64(state + 32, bytes);
}
void CPU_sha256_seed_state(uint8_t* pub_seed, uint8_t* state_seeded) {
    uint8_t block[HASH_BLOCK];
    size_t i;

    for (int i = 0; i < HASH_DIGEST; i++)
        block[i] = pub_seed[i];
    for (i = HASH_DIGEST; i < HASH_BLOCK; i++) {
        block[i] = 0;
    }
    CPU_sha256_inc_init(state_seeded);
    CPU_sha256_inc_block(state_seeded, block, 1);
}
void CPU_sha256_initialize_hash_function(uint8_t* pub_seed, uint8_t* sk_seed, uint8_t* state_seed) {
    CPU_sha256_seed_state(pub_seed, state_seed);
}
void CPU_sha256_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = CPU_load_bigendian_64(state + 32) + inlen;

    CPU_crypto_hashblock_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;

    for (size_t i = 0; i < inlen; ++i) {
        padded[i] = in[i];
    }
    padded[inlen] = 0x80;

    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; ++i) {
            padded[i] = 0;
        }
        padded[56] = (uint8_t)(bytes >> 53);
        padded[57] = (uint8_t)(bytes >> 45);
        padded[58] = (uint8_t)(bytes >> 37);
        padded[59] = (uint8_t)(bytes >> 29);
        padded[60] = (uint8_t)(bytes >> 21);
        padded[61] = (uint8_t)(bytes >> 13);
        padded[62] = (uint8_t)(bytes >> 5);
        padded[63] = (uint8_t)(bytes << 3);
        CPU_crypto_hashblock_sha256(state, padded, 64);
    }
    else {
        for (size_t i = inlen + 1; i < 120; ++i) {
            padded[i] = 0;
        }
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        CPU_crypto_hashblock_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < 32; ++i) {
        out[i] = state[i];
    }
}
void CPU_sha256(uint8_t* out, uint8_t* in, size_t inlen) {
    uint8_t state[40];
    CPU_sha256_inc_init(state);
    CPU_sha256_inc_finalize(out, state, in, inlen);
}

void CPU_hash_inc_init(uint8_t* state) {
    CPU_sha256_inc_init(state);
}
void CPU_crypto_hashblock(uint8_t* statebytes, uint8_t* in, size_t inlen) {
    CPU_crypto_hashblock_sha256(statebytes, in, inlen);
}
void CPU_hash_inc_blocks(uint8_t* state, uint8_t* in, size_t inblocks) {
    CPU_sha256_inc_block(state, in, inblocks);
}
void CPU_hash_seed_state(uint8_t* pub_seed, uint8_t* state_seeded) {
    CPU_sha256_seed_state(pub_seed, state_seeded);
}
void CPU_hash_initialize_hash_function(uint8_t* pub_seed, uint8_t* sk_seed, uint8_t* state_seed) {
    CPU_sha256_initialize_hash_function(pub_seed, sk_seed, state_seed);
}
void CPU_hash_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    CPU_sha256_inc_finalize(out, state, in, inlen);
}
void CPU_hash(uint8_t* out, uint8_t* in, size_t inlen) {
    CPU_sha256(out, in, inlen);
}
#endif
void CPU_gen_message_random(uint8_t* sig, uint8_t* sk_prf, uint8_t* optrand, uint8_t* m, size_t mlen) {
    uint8_t buf[HASH_BLOCK + HASH_OUTBYTE] = { 0, };
    uint8_t state[40];

    for (int i = 0; i < HASH_DIGEST; i++)
        buf[i] = 0x36 ^ sk_prf[i];
    memset(buf + HASH_DIGEST, 0x36, HASH_BLOCK - HASH_DIGEST);

    CPU_hash_inc_init(state);
    CPU_hash_inc_blocks(state, buf, 1);

    memcpy(buf, optrand, HASH_DIGEST);
    if (HASH_DIGEST + mlen < HASH_BLOCK) {
        memcpy(buf + HASH_DIGEST, m, mlen);
        CPU_hash_inc_finalize(buf + HASH_BLOCK, state, buf, mlen + HASH_DIGEST);
    }
    else {
        memcpy(buf + HASH_DIGEST, m, HASH_BLOCK - HASH_DIGEST);
        CPU_hash_inc_blocks(state, buf, 1);

        m += (HASH_BLOCK - HASH_DIGEST);
        mlen -= (HASH_BLOCK - HASH_DIGEST);
        CPU_hash_inc_finalize(buf + HASH_BLOCK, state, m, mlen);
    }

    for (int i = 0; i < HASH_DIGEST; i++)
        buf[i] = 0x5c ^ sk_prf[i];
    memset(buf + HASH_DIGEST, 0x5c, HASH_BLOCK - HASH_DIGEST);

    CPU_hash(buf, buf, HASH_BLOCK + HASH_OUTBYTE);
    memcpy(sig, buf, HASH_DIGEST);
}
void CPU_mgf1(uint8_t* out, unsigned long outlen, uint8_t* in, unsigned long inlen) {
    uint32_t i = 0;
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t* inbuf = (uint8_t*)malloc(inlen + 4);
    if (inbuf == NULL)
        return;
    memcpy(inbuf, in, inlen);
    for (i = 0; (i + 1) * HASH_OUTBYTE <= outlen; i++) {
        CPU_u32_to_bytes(inbuf + inlen, i);
        CPU_hash(out, inbuf, inlen + 4);
        out += HASH_OUTBYTE;
    }
    if (outlen > i * HASH_OUTBYTE) {
        CPU_u32_to_bytes(inbuf + inlen, i);
        CPU_hash(outbuf, inbuf, inlen + 4);
        memcpy(out, outbuf, outlen - i * HASH_OUTBYTE);
    }
    free(inbuf);
}
void CPU_hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, uint8_t* R, uint8_t* pk, uint8_t* m, uint64_t mlen) {
#define SPX_TREE_BITS (TREE_HEIGHT * (SUBTREE_LAYER - 1))
#define SPX_TREE_BYTES ((SPX_TREE_BITS + 7) / 8)
#define SPX_LEAF_BITS TREE_HEIGHT
#define SPX_LEAF_BYTES ((SPX_LEAF_BITS + 7) / 8)
#define SPX_DGST_BYTES (FORS_MSG_BYTE + SPX_TREE_BYTES + SPX_LEAF_BYTES)
#define SPX_INBLOCKS (((HASH_DIGEST + PK_BYTE + HASH_BLOCK - 1) & \
                        -HASH_BLOCK) / HASH_BLOCK)

    uint8_t seed[HASH_OUTBYTE];
    uint8_t inbuf[SPX_INBLOCKS * HASH_BLOCK];
    uint8_t buf[SPX_DGST_BYTES];
    uint8_t* bufp = buf;
    uint8_t state[40];

    CPU_hash_inc_init(state);
    memcpy(inbuf, R, HASH_DIGEST);
    memcpy(inbuf + HASH_DIGEST, pk, PK_BYTE);

    if (HASH_DIGEST + PK_BYTE + mlen < SPX_INBLOCKS * HASH_BLOCK) {
        memcpy(inbuf + HASH_DIGEST + PK_BYTE, m, mlen);
        CPU_hash_inc_finalize(seed, state, inbuf, HASH_DIGEST + PK_BYTE + mlen);
    }
    else {
        memcpy(inbuf + HASH_DIGEST + PK_BYTE, m, SPX_INBLOCKS * HASH_BLOCK - HASH_DIGEST - PK_BYTE);
        CPU_hash_inc_blocks(state, inbuf, SPX_INBLOCKS);

        m += SPX_INBLOCKS * HASH_BLOCK - HASH_DIGEST - PK_BYTE;
        mlen -= SPX_INBLOCKS * HASH_BLOCK - HASH_DIGEST - PK_BYTE;
        CPU_hash_inc_finalize(seed, state, m, mlen);
    }

    CPU_mgf1(bufp, SPX_DGST_BYTES, seed, HASH_OUTBYTE);
    memcpy(digest, bufp, FORS_MSG_BYTE);
    bufp += FORS_MSG_BYTE;

    *tree = CPU_bytes_to_ull(bufp, SPX_TREE_BYTES);
    *tree &= (~(uint64_t)0) >> (64 - SPX_TREE_BITS);
    bufp += SPX_TREE_BYTES;

    *leaf_idx = CPU_bytes_to_ull(bufp, SPX_LEAF_BYTES);
    *leaf_idx &= (~(uint32_t)0) >> (32 - SPX_LEAF_BITS);
}
void CPU_randombytes(uint8_t* in, size_t len) {
    for (int i = 0; i < len; i++)
        in[i] = i;
}

