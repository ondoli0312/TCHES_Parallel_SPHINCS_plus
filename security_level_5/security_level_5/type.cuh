#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//! Data type Define
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

//! Hash output length in bytes
#define SPX_N	32
#define SPX_SHA256_BLOCK_BYTES	64
#define SPX_SHA256_OUTPUT_BYTES	32
#define SPX_SHA256_ADDR_BYTES	22
#define CRYPTO_SEEDBYTES		96
//! SPHINCS+ iternal index define
#define SPX_OFFSET_LAYER	0
#define SPX_OFFSET_TREE		1
#define SPX_OFFSET_TYPE		9
#define SPX_OFFSET_KP_ADDR2	12
#define SPX_OFFSET_KP_ADDR1	13
#define SPX_OFFSET_TREE_HGT 17
#define SPX_OFFSET_CHAIN_ADDR	17
#define SPX_OFFSET_TREE_INDEX	18
#define SPX_OFFSET_HASH_ADDR	21
#define SPX_SHA256_ADDR_BYTES	22

//! FORS \& WOTS+ signature index define
#define SPX_FORS_HEIGHT		9
#define SPX_FORS_TREES		35
#define SPX_FORS_MSG_BYTES	(((SPX_FORS_HEIGHT * SPX_FORS_TREES + 7) / 8))
#define SPX_FORS_BYTES		((SPX_FORS_HEIGHT + 1) * SPX_FORS_TREES * SPX_N)
#define SPX_FORS_PK_BYTES	SPX_N

//! WOTS+ parameter define
#define SPX_WOTS_W			16
#define SPX_WOTS_LOGW		4
#define SPX_WOTS_LEN1		(8 * SPX_N / SPX_WOTS_LOGW)
#define SPX_WOTS_LEN2		3
#define SPX_WOTS_LEN		(SPX_WOTS_LEN1 + SPX_WOTS_LEN2)
#define SPX_WOTS_BYTES		(SPX_WOTS_LEN * SPX_N)

//! SPHINCS+ ADDR define
#define SPX_ADDR_TYPE_WOTS 0
#define SPX_ADDR_TYPE_WOTSPK 1
#define SPX_ADDR_TYPE_HASHTREE 2
#define SPX_ADDR_TYPE_FORSTREE 3
#define SPX_ADDR_TYPE_FORSPK 4

//! SPHINCS+ parameter define
#define SPX_OPTRAND_BYTES 32
#define SPX_FULL_HEIGHT 68
#define SPX_D 17
#define SPX_TREE_HEIGHT (SPX_FULL_HEIGHT / SPX_D)
#define SPX_PK_BYTES (2 * SPX_N)
#define SPX_SK_BYTES (2 * SPX_N + SPX_PK_BYTES)
#define SPX_BYTES	(SPX_N + SPX_FORS_BYTES + (SPX_D * SPX_WOTS_BYTES) + SPX_FULL_HEIGHT * SPX_N)

//! gpu_sha256_define
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

//! GPU_AES define
#define ROTL(x, n)			(((x) << (n)) | ((x) >> (32 - (n))))
#define GPU_ENDIAN_CHANGE(X)	((ROTL((X),  8) & 0x00ff00ff) | (ROTL((X), 24) & 0xff00ff00))


