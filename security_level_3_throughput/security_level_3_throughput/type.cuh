#pragma once
#include "cuda_runtime.h"
#include "device_launch_parameters.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define USE_GPU_SPHINCS_SECURITY_LEVEL2
#define USE_GPU_SPHINCS_SHA256
//!Data type Define
typedef unsigned char uint8_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;

//!SPHINCS+_iternal_index Define
#define ADDR_TYPE_WOTS		0
#define ADDR_TYPE_WOTSPK	1
#define ADDR_TYPE_HASHTREE	2
#define ADDR_TYPE_FORSTREE	3
#define ADDR_TYPE_FORS_PK	4

#define OFFSET_LAYER	0
#define OFFSET_TREE		1
#define OFFSET_TYPE		9
#define OFFSET_KP_ADDR2	12
#define OFFSET_KP_ADDR1	13
#define OFFSET_TREE_HGT 17
#define OFFSET_CHAIN_ADDR	17
#define OFFSET_TREE_INDEX 18
#define OFFSET_HASH_ADDR 21

#ifdef USE_GPU_SPHINCS_SECURITY_LEVEL2
//!Parameter Define
#define HASH_DIGEST		24
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
#define FORS_HEIGHT		8
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