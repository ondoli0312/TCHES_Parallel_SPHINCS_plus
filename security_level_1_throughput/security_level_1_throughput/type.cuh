#pragma once
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_GPU_SPHINCS_SECURITY_LEVEL1
#define USE_GPU_SPHINCS_SHA256
//!Data type Define
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

//!SPHINCS+_iternal_index Define
#define OFFSET_LAYER	0
#define OFFSET_TREE		1
#define OFFSET_KP_ADDR1	13
#define OFFSET_KP_ADDR2	12
#define OFFSET_TYPE		9
#define OFFSET_TREE_HGT 17
#define OFFSET_TREE_INDEX 18
#define OFFSET_CHAIN_ADDR	17
#define OFFSET_HASH_ADDR 21
#define ADDR_TYPE_FORSTREE	3
#define ADDR_TYPE_FORS_PK	4
#define ADDR_TYPE_HASHTREE	2
#define ADDR_TYPE_WOTS		0

#ifdef USE_GPU_SPHINCS_SECURITY_LEVEL1
//!Parameter Define
#define HASH_DIGEST		16
#define HASH_BLOCK		64
#define HASH_OUTBYTE	32
#define HASH_ADDR_BYTES	22

//!SPHINCS+ Parameter Define
#define optrand_size	32
#define FULL_HEIGHT		66
#define SUBTREE_LAYER	22
#define TREE_HEIGHT		(FULL_HEIGHT / SUBTREE_LAYER)
#define PK_BYTE			(2 * HASH_DIGEST)
#define SK_BYTE			(2 * HASH_DIGEST + PK_BYTE)

//!FORS Parameter Define
#define FORS_HEIGHT		6
#define FORS_TREE		33
#define FORS_MSG_BYTE	((FORS_HEIGHT * FORS_TREE + 7) / 8)
#define	FORS_BYTES		((FORS_HEIGHT + 1) * FORS_TREE * HASH_DIGEST)

//!WOTS Parameter Define
#define WOTS_W			16
#define WOTS_LOGW		4
#define WOTS_LEN1		(8 * HASH_DIGEST / WOTS_LOGW)
#define WOTS_LEN2		3
#define WOTS_LEN		(WOTS_LEN1 + WOTS_LEN2)
#define WOTS_BYTES		(WOTS_LEN * HASH_DIGEST)

//!SPHINCS+ Sig size Define
#define SIG_BYTE	(HASH_DIGEST + FORS_BYTES + SUBTREE_LAYER * WOTS_BYTES + FULL_HEIGHT * HASH_DIGEST)
#endif

//!CPU_Phase Functions
void CPU_hash_initialize_hash_function(uint8_t* pub_seed, uint8_t* sk_seed, uint8_t* state_seed);
void CPU_randombytes(uint8_t* in, size_t len);
void CPU_gen_message_random(uint8_t* sig, uint8_t* sk_prf, uint8_t* optrand, uint8_t* m, size_t mlen);
void CPU_hash_message(uint8_t* digest, uint64_t* tree, uint32_t* leaf_idx, uint8_t* R, uint8_t* pk, uint8_t* m, uint64_t mlen);
