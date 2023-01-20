#include "type.cuh"
#include "CPU_Phase.c"

//! GPU Utils
__device__ uint32_t GPU_load_bigendian_32(uint8_t* x) {
    return (uint32_t)(x[3]) | (((uint32_t)(x[2])) << 8) |
        (((uint32_t)(x[1])) << 16) | (((uint32_t)(x[0])) << 24);
}
__device__ uint64_t GPU_load_bigendian_64(uint8_t* x) {
    return (uint64_t)(x[7]) | (((uint64_t)(x[6])) << 8) |
        (((uint64_t)(x[5])) << 16) | (((uint64_t)(x[4])) << 24) |
        (((uint64_t)(x[3])) << 32) | (((uint64_t)(x[2])) << 40) |
        (((uint64_t)(x[1])) << 48) | (((uint64_t)(x[0])) << 56);
}
__device__ void GPU_store_bigendian_32(uint8_t* x, uint64_t u) {
    x[3] = (uint8_t)u;
    u >>= 8;
    x[2] = (uint8_t)u;
    u >>= 8;
    x[1] = (uint8_t)u;
    u >>= 8;
    x[0] = (uint8_t)u;
}
__device__ void GPU_store_bigendian_64(uint8_t* x, uint64_t u) {
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
__device__ void GPU_u32_to_bytes(uint8_t* out, uint32_t in) {
    out[0] = (uint8_t)(in >> 24);
    out[1] = (uint8_t)(in >> 16);
    out[2] = (uint8_t)(in >> 8);
    out[3] = (uint8_t)in;
}
__device__ void GPU_set_type(uint32_t* addr, uint32_t type) {
    ((uint8_t*)addr)[OFFSET_TYPE] = type;
}
__device__ void GPU_set_tree_height(uint32_t* addr, uint32_t tree_height) {
    ((uint8_t*)addr)[OFFSET_TREE_HGT] = tree_height;
}
__device__ void GPU_set_tree_index(uint32_t* addr, uint32_t tree_index) {
    GPU_u32_to_bytes(&((uint8_t*)addr)[OFFSET_TREE_INDEX], tree_index);
}
__device__ void GPU_set_layer_addr(uint32_t* addr, uint32_t layer) {
    ((uint8_t*)addr)[OFFSET_LAYER] = layer;
}
__device__ void GPU_set_keypair_addr(uint32_t* addr, uint32_t keypair) {
    ((uint8_t*)addr)[OFFSET_KP_ADDR1] = keypair;
}
__device__ void GPU_set_chain_addr(uint32_t* addr, uint32_t chain) {
    ((uint8_t*)addr)[OFFSET_CHAIN_ADDR] = chain;
}
__device__ void GPU_set_hash_addr(uint32_t* addr, uint32_t hash) {
    ((uint8_t*)addr)[OFFSET_HASH_ADDR] = hash;
}
__device__ void GPU_copy_keypair_addr(uint32_t* out, uint32_t* in) {
    for (int i = 0; i < OFFSET_TREE + 8; i++)
        ((uint8_t*)out)[i] = ((uint8_t*)in)[i];
    ((uint8_t*)out)[OFFSET_KP_ADDR1] = ((uint8_t*)in)[OFFSET_KP_ADDR1];
}
__device__ void GPU_copy_subtree_addr(uint32_t* out, uint32_t* in) {
    for (int i = 0; i < (OFFSET_TREE + 8); i++)
        ((uint8_t*)out)[i] = ((uint8_t*)in)[i];
}
__device__ void GPU_ull_to_bytes(unsigned char* out, unsigned int outlen, unsigned long long in)
{
    int i;

    /* Iterate over out in decreasing order, for big-endianness. */
    for (i = outlen - 1; i >= 0; i--) {
        out[i] = in & 0xff;
        in = in >> 8;
    }
}
__device__ void GPU_set_tree_addr(uint32_t* addr, uint64_t tree) {
    GPU_ull_to_bytes(&((unsigned char*)addr)[OFFSET_TREE], 8, tree);
}

#ifdef USE_GPU_SPHINCS_SHA256
//!SHA256 MACRO
#define hc_add3(a, b, c)	(a + b + c)
#define hc_rotl32(x, n)		(((x) << (n)) | ((x) >> (32 - (n))))
#define SHIFT_RIGHT_32(x,n) ((x) >> (n))

#define SHA256_F0(x,y,z)	(((x) & (y)) | ((z) & ((x) ^ (y))))
#define SHA256_F1(x,y,z)	((z) ^ ((x) & ((y) ^ (z))))
#define SHA256_F0o(x,y,z) (SHA256_F0 ((x), (y), (z)))
#define SHA256_F1o(x,y,z) (SHA256_F1 ((x), (y), (z)))

#define SHA256_S0(x) (hc_rotl32 ((x), 25u) ^ hc_rotl32 ((x), 14u) ^ SHIFT_RIGHT_32 ((x),  3u))
#define SHA256_S1(x) (hc_rotl32 ((x), 15u) ^ hc_rotl32 ((x), 13u) ^ SHIFT_RIGHT_32 ((x), 10u))
#define SHA256_S2(x) (hc_rotl32 ((x), 30u) ^ hc_rotl32 ((x), 19u) ^ hc_rotl32 ((x), 10u))
#define SHA256_S3(x) (hc_rotl32 ((x), 26u) ^ hc_rotl32 ((x), 21u) ^ hc_rotl32 ((x),  7u))

#define SHA256_STEP(F0,F1,a,b,c,d,e,f,g,h,x,K)    \
{                                                 \
  h = hc_add3 (h, K, x);                          \
  h = hc_add3 (h, SHA256_S3 (e), F1 (e,f,g));     \
  d += h;                                         \
  h = hc_add3 (h, SHA256_S2 (a), F0 (a,b,c));     \
}

#define SHA256_EXPAND(x,y,z,w) (SHA256_S1 (x) + y + SHA256_S0 (z) + w)
#define ROTL32(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define ROTR32(x, n)			(((x) >> (n)) | ((x) << (32 - (n))))

__constant__ uint8_t GPU_iv_256[32] = {
    0x6a, 0x09, 0xe6, 0x67, 0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72, 0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f, 0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab, 0x5b, 0xe0, 0xcd, 0x19
};
__device__ size_t GPU_crypto_hashblock_sha256(uint8_t* statebytes, uint8_t* in, size_t inlen) {
    uint32_t state[8];
    uint32_t a = GPU_load_bigendian_32(statebytes + 0); state[0] = a;
    uint32_t b = GPU_load_bigendian_32(statebytes + 4);	state[1] = b;
    uint32_t c = GPU_load_bigendian_32(statebytes + 8);	state[2] = c;
    uint32_t d = GPU_load_bigendian_32(statebytes + 12); state[3] = d;
    uint32_t e = GPU_load_bigendian_32(statebytes + 16); state[4] = e;
    uint32_t f = GPU_load_bigendian_32(statebytes + 20); state[5] = f;
    uint32_t g = GPU_load_bigendian_32(statebytes + 24); state[6] = g;
    uint32_t h = GPU_load_bigendian_32(statebytes + 28); state[7] = h;

    while (inlen >= 64) {
        uint32_t w0_t = GPU_load_bigendian_32(in + 0);
        uint32_t w1_t = GPU_load_bigendian_32(in + 4);
        uint32_t w2_t = GPU_load_bigendian_32(in + 8);
        uint32_t w3_t = GPU_load_bigendian_32(in + 12);
        uint32_t w4_t = GPU_load_bigendian_32(in + 16);
        uint32_t w5_t = GPU_load_bigendian_32(in + 20);
        uint32_t w6_t = GPU_load_bigendian_32(in + 24);
        uint32_t w7_t = GPU_load_bigendian_32(in + 28);
        uint32_t w8_t = GPU_load_bigendian_32(in + 32);
        uint32_t w9_t = GPU_load_bigendian_32(in + 36);
        uint32_t wa_t = GPU_load_bigendian_32(in + 40);
        uint32_t wb_t = GPU_load_bigendian_32(in + 44);
        uint32_t wc_t = GPU_load_bigendian_32(in + 48);
        uint32_t wd_t = GPU_load_bigendian_32(in + 52);
        uint32_t we_t = GPU_load_bigendian_32(in + 56);
        uint32_t wf_t = GPU_load_bigendian_32(in + 60);

        SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x428a2f98);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x71374491);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0xb5c0fbcf);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0xe9b5dba5);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x3956c25b);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x59f111f1);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x923f82a4);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0xab1c5ed5);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xd807aa98);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x12835b01);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x243185be);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x550c7dc3);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x72be5d74);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0x80deb1fe);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x9bdc06a7);
        SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc19bf174);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0xe49b69c1);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0xefbe4786);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x0fc19dc6);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x240ca1cc);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x2de92c6f);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4a7484aa);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5cb0a9dc);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x76f988da);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x983e5152);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa831c66d);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xb00327c8);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xbf597fc7);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xc6e00bf3);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd5a79147);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0x06ca6351);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x14292967);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x27b70a85);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x2e1b2138);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x4d2c6dfc);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x53380d13);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x650a7354);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x766a0abb);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x81c2c92e);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x92722c85);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0xa2bfe8a1);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0xa81a664b);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0xc24b8b70);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0xc76c51a3);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0xd192e819);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xd6990624);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xf40e3585);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0x106aa070);

        w0_t = SHA256_EXPAND(we_t, w9_t, w1_t, w0_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w0_t, 0x19a4c116);
        w1_t = SHA256_EXPAND(wf_t, wa_t, w2_t, w1_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w1_t, 0x1e376c08);
        w2_t = SHA256_EXPAND(w0_t, wb_t, w3_t, w2_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, w2_t, 0x2748774c);
        w3_t = SHA256_EXPAND(w1_t, wc_t, w4_t, w3_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, w3_t, 0x34b0bcb5);
        w4_t = SHA256_EXPAND(w2_t, wd_t, w5_t, w4_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, w4_t, 0x391c0cb3);
        w5_t = SHA256_EXPAND(w3_t, we_t, w6_t, w5_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, w5_t, 0x4ed8aa4a);
        w6_t = SHA256_EXPAND(w4_t, wf_t, w7_t, w6_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, w6_t, 0x5b9cca4f);
        w7_t = SHA256_EXPAND(w5_t, w0_t, w8_t, w7_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, w7_t, 0x682e6ff3);
        w8_t = SHA256_EXPAND(w6_t, w1_t, w9_t, w8_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, a, b, c, d, e, f, g, h, w8_t, 0x748f82ee);
        w9_t = SHA256_EXPAND(w7_t, w2_t, wa_t, w9_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, h, a, b, c, d, e, f, g, w9_t, 0x78a5636f);
        wa_t = SHA256_EXPAND(w8_t, w3_t, wb_t, wa_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, g, h, a, b, c, d, e, f, wa_t, 0x84c87814);
        wb_t = SHA256_EXPAND(w9_t, w4_t, wc_t, wb_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, f, g, h, a, b, c, d, e, wb_t, 0x8cc70208);
        wc_t = SHA256_EXPAND(wa_t, w5_t, wd_t, wc_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, e, f, g, h, a, b, c, d, wc_t, 0x90befffa);
        wd_t = SHA256_EXPAND(wb_t, w6_t, we_t, wd_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, d, e, f, g, h, a, b, c, wd_t, 0xa4506ceb);
        we_t = SHA256_EXPAND(wc_t, w7_t, wf_t, we_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, c, d, e, f, g, h, a, b, we_t, 0xbef9a3f7);
        wf_t = SHA256_EXPAND(wd_t, w8_t, w0_t, wf_t); SHA256_STEP(SHA256_F0o, SHA256_F1o, b, c, d, e, f, g, h, a, wf_t, 0xc67178f2);

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
    GPU_store_bigendian_32(statebytes + 0, state[0]);
    GPU_store_bigendian_32(statebytes + 4, state[1]);
    GPU_store_bigendian_32(statebytes + 8, state[2]);
    GPU_store_bigendian_32(statebytes + 12, state[3]);
    GPU_store_bigendian_32(statebytes + 16, state[4]);
    GPU_store_bigendian_32(statebytes + 20, state[5]);
    GPU_store_bigendian_32(statebytes + 24, state[6]);
    GPU_store_bigendian_32(statebytes + 28, state[7]);
    return inlen;
}
__device__ void GPU_sha256_inc_init(uint8_t* state) {
    for (size_t i = 0; i < 32; i++)
        state[i] = GPU_iv_256[i];
    for (size_t i = 32; i < 40; i++)
        state[i] = 0;
}
__device__ void GPU_sha256_inc_block(uint8_t* state, uint8_t* in, size_t inblocks) {
    uint64_t bytes = GPU_load_bigendian_64(state + 32);
    GPU_crypto_hashblock_sha256(state, in, 64 * inblocks);
    bytes += 64 * inblocks;
    GPU_store_bigendian_64(state + 32, bytes);
}
__device__ void GPU_sha256_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    uint8_t padded[128];
    uint64_t bytes = GPU_load_bigendian_64(state + 32) + inlen;
    GPU_crypto_hashblock_sha256(state, in, inlen);
    in += inlen;
    inlen &= 63;
    in -= inlen;
    for (size_t i = 0; i < inlen; i++)
        padded[i] = in[i];
    padded[inlen] = 0x80;
    if (inlen < 56) {
        for (size_t i = inlen + 1; i < 56; i++)
            padded[i] = 0;
        padded[56] = (uint8_t)(bytes >> 53);
        padded[57] = (uint8_t)(bytes >> 45);
        padded[58] = (uint8_t)(bytes >> 37);
        padded[59] = (uint8_t)(bytes >> 29);
        padded[60] = (uint8_t)(bytes >> 21);
        padded[61] = (uint8_t)(bytes >> 13);
        padded[62] = (uint8_t)(bytes >> 5);
        padded[63] = (uint8_t)(bytes << 3);
        GPU_crypto_hashblock_sha256(state, padded, 64);
    }

    else {
        for (size_t i = inlen + 1; i < 120; i++)
            padded[i] = 0;
        padded[120] = (uint8_t)(bytes >> 53);
        padded[121] = (uint8_t)(bytes >> 45);
        padded[122] = (uint8_t)(bytes >> 37);
        padded[123] = (uint8_t)(bytes >> 29);
        padded[124] = (uint8_t)(bytes >> 21);
        padded[125] = (uint8_t)(bytes >> 13);
        padded[126] = (uint8_t)(bytes >> 5);
        padded[127] = (uint8_t)(bytes << 3);
        GPU_crypto_hashblock_sha256(state, padded, 128);
    }

    for (size_t i = 0; i < HASH_OUTBYTE; i++)
        out[i] = state[i];
}
__device__ void GPU_sha256(uint8_t* out, uint8_t* in, size_t inlen) {
    uint8_t state[40];
    GPU_sha256_inc_init(state);
    GPU_sha256_inc_finalize(out, state, in, inlen);
}
__device__ void GPU_hash_inc_init(uint8_t* state) {
    GPU_sha256_inc_init(state);
}
__device__ void GPU_hash_inc_block(uint8_t* state, uint8_t* in, size_t inblocks) {
    GPU_sha256_inc_block(state, in, inblocks);
}
__device__ void GPU_hash_inc_finalize(uint8_t* out, uint8_t* state, uint8_t* in, size_t inlen) {
    GPU_sha256_inc_finalize(out, state, in, inlen);
}
__device__ void GPU_hash(uint8_t* out, uint8_t* in, size_t inlen) {
    GPU_sha256(out, in, inlen);
}
#endif

//! GPU FORS Iternal Functions
__device__ void GPU_fors_gen_sk(uint8_t* out, uint8_t* key, uint32_t* addr) {
    uint8_t buf[HASH_DIGEST + HASH_ADDR_BYTES];
    uint8_t outbuf[HASH_OUTBYTE];
    memcpy(buf, key, HASH_DIGEST);
    memcpy(buf + HASH_DIGEST, addr, HASH_ADDR_BYTES);
    GPU_hash(outbuf, buf, HASH_DIGEST + HASH_ADDR_BYTES);
    memcpy(out, outbuf, HASH_DIGEST);
}
__device__ void GPU_fors_sk_to_leaf(uint8_t* leaf, uint8_t* sk, uint8_t* pub_seed, uint32_t* fors_leaf_addr, uint8_t* state_seed) {
    uint8_t buf[HASH_ADDR_BYTES + HASH_DIGEST];
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t hash_state[HASH_OUTBYTE + 8];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, fors_leaf_addr, HASH_ADDR_BYTES);
    memcpy(buf + HASH_ADDR_BYTES, sk, HASH_DIGEST);

    GPU_hash_inc_finalize(outbuf, hash_state, buf, HASH_ADDR_BYTES + HASH_DIGEST);
    memcpy(leaf, outbuf, HASH_DIGEST);
}
__device__ void GPU_fors_gen_leaf(uint8_t* leaf, uint8_t* sk_seed, uint8_t* pub_seed, uint32_t addr_idx, uint32_t* fors_tree_addr, uint8_t* state_seed) {
    uint32_t fors_leaf_addr[8] = { 0, };
    GPU_copy_keypair_addr(fors_leaf_addr, fors_tree_addr);
    GPU_set_type(fors_leaf_addr, ADDR_TYPE_FORSTREE);
    GPU_set_tree_index(fors_leaf_addr, addr_idx);
    GPU_fors_gen_sk(leaf, sk_seed, fors_leaf_addr);
    GPU_fors_sk_to_leaf(leaf, leaf, pub_seed, fors_leaf_addr, state_seed);
}
__device__ void GPU_tree_thash_2depth(uint8_t* out, uint8_t* in0, uint8_t* in1, uint8_t* pub_seed, uint32_t* addr, uint8_t* state_seed) {
    uint8_t buf[HASH_ADDR_BYTES + (2 * HASH_DIGEST)];
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t hash_state[40];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, addr, HASH_ADDR_BYTES);
    memcpy(buf + HASH_ADDR_BYTES, in0, HASH_DIGEST);
    memcpy(buf + HASH_ADDR_BYTES + HASH_DIGEST, in1, HASH_DIGEST);
    GPU_hash_inc_finalize(outbuf, hash_state, buf, HASH_ADDR_BYTES + (2 * HASH_DIGEST));
    memcpy(out, outbuf, HASH_DIGEST);
}
__device__ void GPU_fors_final_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint32_t* addr, uint8_t* state_seed) {
    uint8_t buf[HASH_ADDR_BYTES + (HASH_DIGEST * FORS_TREE)];
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t hash_state[40];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, addr, HASH_ADDR_BYTES);
    memcpy(buf + HASH_ADDR_BYTES, in, HASH_DIGEST * FORS_TREE);

    GPU_hash_inc_finalize(outbuf, hash_state, buf, HASH_ADDR_BYTES + (HASH_DIGEST * FORS_TREE));
    memcpy(out, outbuf, HASH_DIGEST);

}
__device__ void GPU_chain_lengths(uint32_t* lengths, uint8_t* msg);

//! GPU FORS Core

//WOTS+
__device__ void GPU_base_w(uint32_t* output, int out_len, uint8_t* input) {
    int in = 0;
    int out = 0;
    int bits = 0;
    int consumed;
    uint8_t total;
    for (consumed = 0; consumed < out_len; consumed++) {
        if (bits == 0) {
            total = input[in];
            in++;
            bits += 8;
        }
        bits -= WOTS_LOGW;
        output[out] = (total >> bits) & (WOTS_W - 1);
        out++;
    }
}
__device__ void GPU_WOTS_checksum(uint32_t* csum_base_w, uint32_t* msg_base_w) {
    unsigned int csum = 0;
    unsigned char csum_bytes[(WOTS_LEN2 * WOTS_LOGW + 7) / 8];
    unsigned int i;

    /* Compute checksum. */
    for (i = 0; i < WOTS_LEN1; i++) {
        csum += WOTS_W - 1 - msg_base_w[i];
    }

    /* Convert checksum to base_w. */
    /* Make sure expected empty zero bits are the least significant bits. */
    csum = csum << ((8 - ((WOTS_LEN2 * WOTS_LOGW) % 8)) % 8);
    GPU_ull_to_bytes(csum_bytes, sizeof(csum_bytes), csum);
    GPU_base_w(csum_base_w, WOTS_LEN2, csum_bytes);
}
__device__ void GPU_chain_lengths(uint32_t* lengths, uint8_t* msg) {
    GPU_base_w(lengths, WOTS_LEN1, msg);
    GPU_WOTS_checksum(lengths + WOTS_LEN1, lengths);
}
__device__ void GPU_wots_chain_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint8_t buf[HASH_DIGEST + HASH_ADDR_BYTES];
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t hash_state[40];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, addr, HASH_ADDR_BYTES);
    memcpy(buf + HASH_ADDR_BYTES, in, HASH_DIGEST);

    GPU_hash_inc_finalize(outbuf, hash_state, buf, HASH_ADDR_BYTES + HASH_DIGEST);
    memcpy(out, outbuf, HASH_DIGEST);
}
__device__ void GPU_gen_chain(uint8_t* out, uint8_t* in, uint32_t start, uint32_t steps, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint32_t i = 0;
    memcpy(out, in, HASH_DIGEST);
    for (i = start; i < (start + steps) && i < WOTS_W; i++) {
        GPU_set_hash_addr(addr, i);
        GPU_wots_chain_thash(out, out, pub_seed, state_seed, addr);
    }
}
__device__ void GPU_wots_gen_sk(uint8_t* sk, uint8_t* sk_seed, uint32_t* wots_addr) {
    GPU_set_hash_addr(wots_addr, 0);

    uint8_t buf[HASH_ADDR_BYTES + HASH_DIGEST];
    uint8_t outbuf[HASH_OUTBYTE];

    memcpy(buf, sk_seed, HASH_DIGEST);
    memcpy(buf + HASH_DIGEST, wots_addr, HASH_ADDR_BYTES);

    GPU_hash(outbuf, buf, HASH_DIGEST + HASH_ADDR_BYTES);
    memcpy(sk, outbuf, HASH_DIGEST);
}
__device__ void GPU_wots_gen_pk(uint8_t* pk, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint32_t i = 0;
    for (int i = 0; i < WOTS_LEN; i++) {
        GPU_set_chain_addr(addr, i);
        GPU_wots_gen_sk(pk + i * HASH_DIGEST, sk_seed, addr);
        GPU_gen_chain(pk + i * HASH_DIGEST, pk + i * HASH_DIGEST, 0, WOTS_W - 1, pub_seed, state_seed, addr);
    }
}
__device__ void GPU_wots_gen_leaf_thash(uint8_t* out, uint8_t* in, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* addr) {
    uint8_t buf[(WOTS_LEN * HASH_DIGEST) + HASH_ADDR_BYTES];
    uint8_t outbuf[HASH_OUTBYTE];
    uint8_t hash_state[40];

    memcpy(hash_state, state_seed, 40);
    memcpy(buf, addr, HASH_ADDR_BYTES);
    memcpy(buf + HASH_ADDR_BYTES, in, WOTS_LEN * HASH_DIGEST);

    GPU_hash_inc_finalize(outbuf, hash_state, buf, 22 + (WOTS_LEN * HASH_DIGEST));
    memcpy(out, outbuf, HASH_DIGEST);
}
__device__ void GPU_wots_gen_leaf(uint8_t* leaf, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t addr_idx, uint32_t* tree_addr) {
    uint8_t pk[WOTS_BYTES];
    uint32_t wots_addr[8] = { 0, };
    uint32_t wots_pk_addr[8] = { 0, };

    GPU_set_type(wots_addr, 0);
    GPU_set_type(wots_pk_addr, 1);

    GPU_copy_subtree_addr(wots_addr, tree_addr);
    GPU_set_keypair_addr(wots_addr, addr_idx);
    GPU_wots_gen_pk(pk, sk_seed, pub_seed, state_seed, wots_addr);

    GPU_copy_keypair_addr(wots_pk_addr, wots_addr);
    GPU_wots_gen_leaf_thash(leaf, pk, pub_seed, state_seed, wots_pk_addr);
}
__global__ void GPU_fors_sign_throughput_security_level_3_oneblock(uint8_t* sig, uint32_t* indices, uint8_t* sk_seed, uint8_t* pub_seed, uint32_t fors_addr[8], uint8_t* state_seed, uint32_t* lengths) {
    __shared__ uint8_t shared_stack[HASH_DIGEST * (1 << FORS_HEIGHT)];
    __shared__ uint8_t root[HASH_DIGEST * FORS_TREE];
    uint8_t iternal_pub_seed[PK_BYTE] = { 0, };
    uint8_t iternal_sk_seed[SK_BYTE] = { 0, };
    uint8_t iternal_state_seed[HASH_OUTBYTE + 8] = { 0, };
    uint8_t temp[HASH_DIGEST] = { 0, };
    uint32_t fors_tree_addr[8] = { 0, };
    uint32_t fors_pk_addr[8] = { 0, };
    uint32_t idx_offset = 0;
    uint32_t tree_idx = 0;
    uint32_t leaf_idx = 0;
    uint32_t sig_index = FORS_BYTES * blockIdx.x;
    //uint32_t sig_index = (FORS_TREE * HASH_DIGEST * (FORS_HEIGHT + 1)) * blockIdx.x;

    for (int i = 0; i < PK_BYTE; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SK_BYTE; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < HASH_OUTBYTE + 8; i++)
        iternal_state_seed[i] = state_seed[i];

    GPU_copy_keypair_addr(fors_tree_addr, fors_addr);
    GPU_copy_keypair_addr(fors_pk_addr, fors_addr);

    GPU_set_type(fors_tree_addr, ADDR_TYPE_FORSTREE);
    GPU_set_type(fors_pk_addr, ADDR_TYPE_FORS_PK);

    for (int i = 0; i < FORS_TREE; i++) {
        idx_offset = (i) * (1 << FORS_HEIGHT);
        leaf_idx = indices[i + blockIdx.x * FORS_TREE];
        if (threadIdx.x == 0) {
            GPU_set_tree_height(fors_tree_addr, 0);
            GPU_set_tree_index(fors_tree_addr, leaf_idx + idx_offset);
            GPU_fors_gen_sk(sig + sig_index, iternal_sk_seed, fors_tree_addr);
        }

        //!Depth 0 [FORS LEAF GEN]
        GPU_fors_gen_leaf(shared_stack + (HASH_DIGEST * threadIdx.x), iternal_sk_seed, iternal_pub_seed, threadIdx.x + idx_offset, fors_tree_addr, iternal_state_seed);
        if ((leaf_idx ^ 0x1) == threadIdx.x)
            memcpy(sig + HASH_DIGEST + sig_index, shared_stack + (HASH_DIGEST * threadIdx.x), HASH_DIGEST);
        __syncthreads();

        //!Depth 1[FORS 256 -> 128]
        if (threadIdx.x < 128) {
            GPU_set_tree_height(fors_tree_addr, 1);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 1));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x), shared_stack + (2 * HASH_DIGEST * threadIdx.x),
                shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 1) ^ 0x1) == threadIdx.x)
                memcpy(sig + (2 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x), HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 2[FORS 128 -> 64]
        if (threadIdx.x < 64) {
            GPU_set_tree_height(fors_tree_addr, 2);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 2));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, shared_stack + (4 * HASH_DIGEST * threadIdx.x),
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 2 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 2) ^ 0x1) == threadIdx.x)
                memcpy(sig + (3 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 3[FORS 64- > 32]
        if (threadIdx.x < 32) {
            GPU_set_tree_height(fors_tree_addr, 3);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 3));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x), shared_stack + (4 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST,
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 3 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 3) ^ 0x1) == threadIdx.x)
                memcpy(sig + (4 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x), HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 4[FORS 32- > 16]
        if (threadIdx.x < 16) {
            GPU_set_tree_height(fors_tree_addr, 4);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 4));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, shared_stack + (4 * HASH_DIGEST * threadIdx.x),
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 2 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 4) ^ 0x1) == threadIdx.x)
                memcpy(sig + (5 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 5[FORS 16- > 8]
        if (threadIdx.x < 8) {
            GPU_set_tree_height(fors_tree_addr, 5);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 5));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x), shared_stack + (4 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST,
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 3 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 5) ^ 0x1) == threadIdx.x)
                memcpy(sig + (6 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x), HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 6[FORS 8- >4]
        if (threadIdx.x < 4) {
            GPU_set_tree_height(fors_tree_addr, 6);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 6));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, shared_stack + (4 * HASH_DIGEST * threadIdx.x),
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 2 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 6) ^ 0x1) == threadIdx.x)
                memcpy(sig + (7 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, HASH_DIGEST);
        }
        __syncthreads();

        //!Depth 7[FORS 4->2]
        if (threadIdx.x < 2) {
            GPU_set_tree_height(fors_tree_addr, 7);
            GPU_set_tree_index(fors_tree_addr, threadIdx.x + (idx_offset >> 7));
            GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x), shared_stack + (4 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST,
                shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 3 * HASH_DIGEST, iternal_pub_seed, fors_tree_addr, iternal_state_seed);
            if (((leaf_idx >> 7) ^ 0x1) == threadIdx.x)
                memcpy(sig + (8 * HASH_DIGEST) + sig_index, shared_stack + (2 * HASH_DIGEST * threadIdx.x), HASH_DIGEST);
        }
        __syncthreads();
        //!Depth 8[FORS 2->1]
        if (threadIdx.x == 0) {
            GPU_set_tree_height(fors_tree_addr, 8);
            GPU_set_tree_index(fors_tree_addr, idx_offset >> 8);
            GPU_tree_thash_2depth(root + (HASH_DIGEST * i), shared_stack, shared_stack + (2 * HASH_DIGEST), iternal_pub_seed, fors_tree_addr, iternal_state_seed);
        }
        sig_index += 9 * HASH_DIGEST;
    }
    __syncthreads();
    if (threadIdx.x == 0) {
        GPU_fors_final_thash(temp, root, iternal_pub_seed, fors_pk_addr, iternal_state_seed);
        GPU_chain_lengths(lengths + (blockIdx.x * (WOTS_LEN * (SUBTREE_LAYER + 1))), temp);
    }
}
__global__ void GPU_sphincs_tree_hash_security_level_3_oneblock(uint32_t* lengths, uint8_t* sig, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* leaf_idx, uint64_t* tree) {
    __shared__ uint8_t shared_stack[HASH_DIGEST * (SUBTREE_LAYER * (1 << TREE_HEIGHT))];
    uint8_t sphincs_root[HASH_DIGEST];
    uint8_t iternal_sk_seed[SK_BYTE];
    uint8_t iternal_pub_seed[PK_BYTE];
    uint8_t iternal_state_seed[40];
    uint32_t sphincs_idx_offset = 0;
    uint32_t sig_store_index = 0;
    uint32_t iternal_layeridx = 0;
    uint32_t sphincs_leaf[SUBTREE_LAYER];
    uint64_t sphincs_tree[SUBTREE_LAYER];
    uint32_t sphincs_tree_addr[8] = { 0, };

    iternal_layeridx = threadIdx.x / (1 << TREE_HEIGHT);
    sig_store_index = ((iternal_layeridx + 1)) * (WOTS_BYTES + (HASH_DIGEST * TREE_HEIGHT)) - (HASH_DIGEST * TREE_HEIGHT) + (blockIdx.x * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST));
    sphincs_leaf[0] = leaf_idx[0];
    sphincs_tree[0] = tree[0];

    for (int i = 1; i < SUBTREE_LAYER; i++) {
        sphincs_leaf[i] = (sphincs_tree[i - 1] & ((1 << TREE_HEIGHT) - 1));
        sphincs_tree[i] = sphincs_tree[i - 1] >> TREE_HEIGHT;
    }

    for (int i = 0; i < SK_BYTE; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < PK_BYTE; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < 40; i++)
        iternal_state_seed[i] = state_seed[i];

    GPU_set_type(sphincs_tree_addr, 2);
    GPU_set_layer_addr(sphincs_tree_addr, iternal_layeridx);
    GPU_set_tree_addr(sphincs_tree_addr, sphincs_tree[iternal_layeridx]);

    GPU_wots_gen_leaf(shared_stack + HASH_DIGEST * threadIdx.x, iternal_sk_seed, iternal_pub_seed, iternal_state_seed, (sphincs_idx_offset + (threadIdx.x % 8)), sphincs_tree_addr);
    if (((sphincs_leaf[iternal_layeridx]) ^ 0x1) == (threadIdx.x % 8)) {
        memcpy(sig + sig_store_index, shared_stack + HASH_DIGEST * threadIdx.x, HASH_DIGEST);
    }
    __syncthreads();

    if (threadIdx.x < (blockDim.x >> 1)) {
        iternal_layeridx = (threadIdx.x / 4);
        sig_store_index = ((iternal_layeridx + 1)) * (WOTS_BYTES + (HASH_DIGEST * TREE_HEIGHT)) - (HASH_DIGEST * TREE_HEIGHT) + (blockIdx.x * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST));
        GPU_set_layer_addr(sphincs_tree_addr, iternal_layeridx);
        GPU_set_tree_addr(sphincs_tree_addr, sphincs_tree[iternal_layeridx]);

        GPU_set_tree_height(sphincs_tree_addr, 1);
        GPU_set_tree_index(sphincs_tree_addr, (threadIdx.x % 4) + (sphincs_idx_offset >> 1));
        GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x), shared_stack + (2 * HASH_DIGEST * threadIdx.x),
            shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);

        if (((sphincs_leaf[iternal_layeridx] >> 1) ^ 0x1) == (threadIdx.x % 4))
            memcpy(sig + sig_store_index + HASH_DIGEST, shared_stack + (2 * HASH_DIGEST * threadIdx.x), HASH_DIGEST);
    }
    __syncthreads();

    if (threadIdx.x < (blockDim.x >> 2)) {
        iternal_layeridx = (threadIdx.x / 2);
        sig_store_index = ((iternal_layeridx + 1)) * (WOTS_BYTES + (HASH_DIGEST * TREE_HEIGHT)) - (HASH_DIGEST * TREE_HEIGHT) + (blockIdx.x * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST));

        GPU_set_layer_addr(sphincs_tree_addr, iternal_layeridx);
        GPU_set_tree_addr(sphincs_tree_addr, sphincs_tree[iternal_layeridx]);

        GPU_set_tree_height(sphincs_tree_addr, 2);
        GPU_set_tree_index(sphincs_tree_addr, (threadIdx.x % 2) + (sphincs_idx_offset >> 2));
        GPU_tree_thash_2depth(shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, shared_stack + (4 * HASH_DIGEST * threadIdx.x),
            shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 2 * HASH_DIGEST, iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);

        if (((sphincs_leaf[iternal_layeridx] >> 2) ^ 0x1) == (threadIdx.x % 2))
            memcpy(sig + sig_store_index + 2 * HASH_DIGEST, shared_stack + (2 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, HASH_DIGEST);
    }
    __syncthreads();

    if (threadIdx.x < (blockDim.x >> 3)) {
        iternal_layeridx = (threadIdx.x);
        sig_store_index = ((iternal_layeridx + 1)) * (WOTS_BYTES + (HASH_DIGEST * TREE_HEIGHT)) - (HASH_DIGEST * TREE_HEIGHT) + (blockIdx.x * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST));

        GPU_set_layer_addr(sphincs_tree_addr, iternal_layeridx);
        GPU_set_tree_addr(sphincs_tree_addr, sphincs_tree[iternal_layeridx]);
        GPU_set_tree_height(sphincs_tree_addr, 3);
        GPU_set_tree_index(sphincs_tree_addr, (sphincs_idx_offset >> 3));
        GPU_tree_thash_2depth(sphincs_root, shared_stack + (4 * HASH_DIGEST * threadIdx.x) + HASH_DIGEST, shared_stack + (4 * HASH_DIGEST * threadIdx.x) + 3 * HASH_DIGEST, iternal_pub_seed, sphincs_tree_addr, iternal_state_seed);
        GPU_chain_lengths(lengths + WOTS_LEN + (WOTS_LEN * iternal_layeridx) + (WOTS_LEN * blockIdx.x * (SUBTREE_LAYER + 1)), sphincs_root);
    }
}

//<<<msg, (SUB-LAYER >> 1) * (WOTS_LEN)
__global__ void GPU_sphincs_wots_sign_security_level_3_oneblock(uint8_t* sig, uint32_t* lengths, uint8_t* sk_seed, uint8_t* pub_seed, uint8_t* state_seed, uint32_t* leaf_idx, uint64_t* tree) {
    uint8_t hash_value[HASH_DIGEST];
    uint8_t hash_temp[HASH_DIGEST];
    uint8_t iternal_pub_seed[PK_BYTE];
    uint8_t iternal_sk_seed[SK_BYTE];
    uint8_t iternal_state_seed[40];

    uint32_t tree_addr[8] = { 0, };
    uint32_t wots_addr[8] = { 0, };
    uint32_t sig_store_index = 0;
    uint32_t iternal_layer = 0;
    uint32_t iternal_lengths = 0;
    uint32_t iternal_leaf_idx = 0;

    uint64_t iternal_tree = 0;
    ///LAYER 10 ¹Ì¸¸
    iternal_layer = threadIdx.x / WOTS_LEN;
    sig_store_index = ((iternal_layer) * (WOTS_BYTES + (TREE_HEIGHT * HASH_DIGEST))) + blockIdx.x * (SIG_BYTE - FORS_BYTES - HASH_DIGEST);
    iternal_tree = tree[0];
    iternal_leaf_idx = leaf_idx[0];
    for (int i = 0; i < iternal_layer; i++) {
        iternal_leaf_idx = (iternal_tree & ((1 << TREE_HEIGHT) - 1));
        iternal_tree = iternal_tree >> TREE_HEIGHT;
    }
    iternal_lengths = lengths[threadIdx.x + (WOTS_LEN * (SUBTREE_LAYER + 1) * blockIdx.x)];

    for (int i = 0; i < PK_BYTE; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SK_BYTE; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < 40; i++)
        iternal_state_seed[i] = state_seed[i];

    GPU_set_type(tree_addr, ADDR_TYPE_HASHTREE);
    GPU_set_layer_addr(tree_addr, iternal_layer);
    GPU_set_tree_addr(tree_addr, iternal_tree);
    GPU_copy_subtree_addr(wots_addr, tree_addr);
    GPU_set_keypair_addr(wots_addr, iternal_leaf_idx);
    GPU_set_chain_addr(wots_addr, threadIdx.x % WOTS_LEN);

    GPU_wots_gen_sk(hash_temp, iternal_sk_seed, wots_addr);
    GPU_gen_chain(hash_temp, hash_temp, 0, iternal_lengths, iternal_pub_seed, iternal_state_seed, wots_addr);
    memcpy(sig + sig_store_index + (HASH_DIGEST * (threadIdx.x % WOTS_LEN)), hash_temp, HASH_DIGEST);

    //LAYER 11 ~ 21
    iternal_layer = (threadIdx.x / WOTS_LEN) + (SUBTREE_LAYER >> 1);
    sig_store_index = ((iternal_layer) * (WOTS_BYTES + (TREE_HEIGHT * HASH_DIGEST))) + blockIdx.x * (SIG_BYTE - FORS_BYTES - HASH_DIGEST);
    iternal_tree = tree[0];
    iternal_leaf_idx = leaf_idx[0];
    iternal_lengths = lengths[threadIdx.x + blockDim.x + (WOTS_LEN * (SUBTREE_LAYER + 1) * blockIdx.x)];

    for (int i = 0; i < iternal_layer; i++) {
        iternal_leaf_idx = (iternal_tree & ((1 << TREE_HEIGHT) - 1));
        iternal_tree = iternal_tree >> TREE_HEIGHT;
    }
    for (int i = 0; i < PK_BYTE; i++)
        iternal_pub_seed[i] = pub_seed[i];
    for (int i = 0; i < SK_BYTE; i++)
        iternal_sk_seed[i] = sk_seed[i];
    for (int i = 0; i < 40; i++)
        iternal_state_seed[i] = state_seed[i];

    GPU_set_type(tree_addr, ADDR_TYPE_HASHTREE);
    GPU_set_layer_addr(tree_addr, iternal_layer);
    GPU_set_tree_addr(tree_addr, iternal_tree);
    GPU_copy_subtree_addr(wots_addr, tree_addr);
    GPU_set_keypair_addr(wots_addr, iternal_leaf_idx);
    GPU_set_chain_addr(wots_addr, threadIdx.x % WOTS_LEN);
    GPU_wots_gen_sk(hash_temp, iternal_sk_seed, wots_addr);
    GPU_gen_chain(hash_temp, hash_temp, 0, iternal_lengths, iternal_pub_seed, iternal_state_seed, wots_addr);
    memcpy(sig + sig_store_index + (HASH_DIGEST * (threadIdx.x % WOTS_LEN)), hash_temp, HASH_DIGEST);
}

int crypto_sign_signature_security_level_3(uint8_t* sig, size_t* siglen, uint8_t* m, size_t mlen, uint8_t* sk, uint32_t msgNum) {
    uint8_t* sk_seed = sk;
    uint8_t* sk_prf = sk + HASH_DIGEST;
    uint8_t* pk = sk + (2 * HASH_DIGEST);
    uint8_t* pub_seed = pk;
    uint8_t state_seed[40];
    uint8_t optrand[HASH_DIGEST];
    uint8_t mhash[FORS_MSG_BYTE];
    uint8_t root[HASH_DIGEST];
    uint32_t idx_leaf = 0;
    uint32_t indices[FORS_TREE] = { 0, };
    uint32_t wots_addr[8] = { 0, };
    uint32_t tree_addr[8] = { 0, };
    uint64_t i = 0;
    uint64_t tree = 0;
    uint64_t sig_index = 0;
    CPU_hash_initialize_hash_function(pub_seed, sk_seed, state_seed);
    CPU_randombytes(optrand, HASH_DIGEST);
    CPU_gen_message_random(sig, sk_prf, optrand, m, mlen);
    CPU_hash_message(mhash, &tree, &idx_leaf, sig + sig_index, pk, m, mlen); sig_index += HASH_DIGEST;
    CPU_set_tree_addr(wots_addr, tree);
    CPU_set_keypair_addr(wots_addr, idx_leaf);
    CPU_message_to_indices(indices, mhash);

    //! GPU FORS Params set
    uint8_t* gpu_sk_seed = NULL;
    uint8_t* gpu_pub_seed = NULL;
    uint8_t* gpu_state_seed = NULL;
    uint32_t* gpu_wots_addr = NULL;
    uint8_t* gpu_fors_throughput_test = NULL;
    uint32_t* gpu_fors_throughput_indices = NULL;
    uint32_t* gpu_fors_throughput_lengths = NULL;
    uint8_t* cpu_fors_sign = (uint8_t*)malloc(msgNum * FORS_BYTES);

    //! GPU WOTS+ Params set
    uint8_t* gpu_wots_sig = NULL;
    uint32_t* gpu_idx_leaf = NULL;
    uint64_t* gpu_tree = NULL;
    uint8_t* cpu_wots_sign = (uint8_t*)malloc(msgNum * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST));

    //! GPU FORS Malloc & Memcopy Copy
    cudaMalloc((void**)&gpu_sk_seed, sizeof(uint8_t) * SK_BYTE);
    cudaMalloc((void**)&gpu_pub_seed, sizeof(uint8_t) * PK_BYTE);
    cudaMalloc((void**)&gpu_state_seed, sizeof(uint8_t) * 40);
    cudaMalloc((void**)&gpu_wots_addr, sizeof(uint32_t) * 8);
    cudaMalloc((void**)&gpu_fors_throughput_test, msgNum * FORS_BYTES);
    cudaMalloc((void**)&gpu_fors_throughput_indices, sizeof(uint32_t) * FORS_TREE * msgNum);
    cudaMalloc((void**)&gpu_fors_throughput_lengths, msgNum * sizeof(uint32_t) * WOTS_LEN * (SUBTREE_LAYER + 1));

    cudaMemcpy(gpu_sk_seed, sk_seed, sizeof(uint8_t) * SK_BYTE, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_pub_seed, pub_seed, sizeof(uint8_t) * PK_BYTE, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_wots_addr, wots_addr, sizeof(uint32_t) * 8, cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_state_seed, state_seed, sizeof(uint8_t) * 40, cudaMemcpyHostToDevice);

    //! GPU WOTS+ Malloc & Memory Copy
    cudaMalloc((void**)&gpu_idx_leaf, sizeof(uint32_t));
    cudaMalloc((void**)&gpu_tree, sizeof(uint64_t));
    cudaMalloc((void**)&gpu_wots_sig, msgNum * SUBTREE_LAYER * (WOTS_BYTES + (TREE_HEIGHT * HASH_DIGEST)));
    cudaMemcpy(gpu_idx_leaf, &idx_leaf, sizeof(uint32_t), cudaMemcpyHostToDevice);
    cudaMemcpy(gpu_tree, &tree, sizeof(uint64_t), cudaMemcpyHostToDevice);

    //FORS start
    for (int i = 0; i < msgNum; i++)
        cudaMemcpy(gpu_fors_throughput_indices + (i * FORS_TREE), indices, sizeof(uint32_t) * FORS_TREE, cudaMemcpyHostToDevice);


    float elapsed_time_ms = 0.0f;
    cudaEvent_t start, stop;
    cudaError_t err;

    cudaEventCreate(&start);
    cudaEventCreate(&stop);
    cudaEventRecord(start, 0);

    for (int i = 0; i < 100; i++) {
        GPU_fors_sign_throughput_security_level_3_oneblock << <msgNum, (1 << FORS_HEIGHT) >> > (gpu_fors_throughput_test, gpu_fors_throughput_indices, gpu_sk_seed, gpu_pub_seed, gpu_wots_addr, gpu_state_seed, gpu_fors_throughput_lengths);
        GPU_sphincs_tree_hash_security_level_3_oneblock << <msgNum, SUBTREE_LAYER* (1 << TREE_HEIGHT) >> > (gpu_fors_throughput_lengths, gpu_wots_sig, gpu_sk_seed, gpu_pub_seed, gpu_state_seed, gpu_idx_leaf, gpu_tree);
        cudaMemcpy(cpu_fors_sign, gpu_fors_throughput_test, msgNum * FORS_BYTES, cudaMemcpyDeviceToHost);
        GPU_sphincs_wots_sign_security_level_3_oneblock << <msgNum, 11 * 51 >> > (gpu_wots_sig, gpu_fors_throughput_lengths, gpu_sk_seed, gpu_pub_seed, gpu_state_seed, gpu_idx_leaf, gpu_tree);
        cudaMemcpy(cpu_wots_sign, gpu_wots_sig, msgNum * SUBTREE_LAYER * (WOTS_BYTES + TREE_HEIGHT * HASH_DIGEST), cudaMemcpyDeviceToHost);
    }
    cudaEventRecord(stop, 0);
    cudaDeviceSynchronize();
    cudaEventSynchronize(start);
    cudaEventSynchronize(stop);
    cudaEventElapsedTime(&elapsed_time_ms, start, stop);


    elapsed_time_ms /= 100;
    elapsed_time_ms = 1000 / elapsed_time_ms;
    elapsed_time_ms = elapsed_time_ms * msgNum;

    printf("SPHINCS+ = %4.2f kops\n", elapsed_time_ms / 1000);

    cudaFree(gpu_sk_seed);
    cudaFree(gpu_pub_seed);
    cudaFree(gpu_state_seed);
    cudaFree(gpu_wots_addr);
    cudaFree(gpu_idx_leaf);
    cudaFree(gpu_tree);
    cudaFree(gpu_wots_sig);
    return 0;
}
int main() {
    printf("SPX_BYTES = %d\n", SIG_BYTE);
    printf("FORS_BYTES = %d\n", FORS_BYTES);
    printf("SPX_WOTS_BYTES = %d\n", WOTS_BYTES);

    uint64_t siglen = 0;
    uint8_t sig[SIG_BYTE] = { 0, };
    uint8_t m[SK_BYTE];
    uint8_t sk[SK_BYTE];
    for (int i = 0; i < SK_BYTE; i++) {
        m[i] = i;
        sk[i] = i * i - i;
    }
    uint32_t msgNum[10] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, 512 };

    for (int i = 0; i < 10; i++) {
        crypto_sign_signature_security_level_3(sig, &siglen, m, SK_BYTE, sk, msgNum[i]);
    }
}