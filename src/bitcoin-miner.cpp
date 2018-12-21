// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Copyright (c) 2017-2018 The Bitcoin LE Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "init.h"
#include "miner.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "crypto/sha256.h"
#include "fs.h"
#include "key.h"
#include "validation.h"
#include "miner.h"
#include "net_processing.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "wallet/wallet.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "rpc/server.h"
#include "rpc/register.h"
#include "script/sigcache.h"
#include "base58.h"
#include "scheduler.h"
#include "metronome_helper.h"

#if defined(__aarch32__) || defined(__aarch64__)
#include <arm_neon.h>
#endif

#include <boost/thread.hpp>
#include <thread>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>     // std::cout, std::fixed
#include <iomanip>      // std::setprecision

uint32_t MAX_N_THREADS = std::thread::hardware_concurrency();

struct MinerHandler {
	bool found;
	bool interrupt;
	bool stop;
	CBlock block;
	int64_t mineStartTime;
	uint32_t* currentOffset;
	MinerHandler() : found(false), interrupt(false), stop(false), block(CBlock()) {
	}
	~MinerHandler() {
		delete currentOffset;
	}
	void init() {
		currentOffset = new uint32_t[MAX_N_THREADS];
	}
	void clear() {
		found = false;
		block = CBlock();
		interrupt = false;
		stop = false;
		mineStartTime = 0;
	}
};

MinerHandler handler;

void proofOfWorkFinder(uint32_t idx, CBlock block, uint32_t from, uint32_t to, MinerHandler* handler, uint32_t PAGE_SIZE_MINER);
void proofOfWorkFinderArmV8(uint32_t idx, CBlock block, uint32_t from, uint32_t to, MinerHandler* handler);
bool hasPeers();

void wait4Sync() {
	uint64_t height = 0;
	CBlockIndex* headBlock = chainActive.Tip();
	if (headBlock) {
		height = headBlock->nHeight;
	}
	// if height is stable for 30 seconds, assume sync
	int SYNC_WAIT = 10;
	while(true) {
		if (handler.interrupt) {
			return;
		}
		CBlockIndex* newHeadBlock;
		for (int i = 0; i <= SYNC_WAIT; ++i) {
			newHeadBlock = chainActive.Tip();
			if (newHeadBlock && newHeadBlock->nHeight == height) {
				printf("Analyzing blocks... BLOCK=%d (%d\%)\r", height, (int) (i * 100.0 / SYNC_WAIT));
			}
			else {
				printf("Analyzing blocks... BLOCK=%d (%d\%)\r", newHeadBlock ? newHeadBlock->nHeight : height, 0);
			}
			MilliSleep(1000);
		}
		if (newHeadBlock && newHeadBlock->nHeight == height) {
			return;
		}
		if (!newHeadBlock) {
			height = 0;
		}
		else {
			height = newHeadBlock->nHeight;
		}
	}
};

uint64_t wait4Peers() {
	printf("\n");
	uint64_t i = 0;
	while (!hasPeers()) {
		if (handler.interrupt) {
			return 0;
		}
		printf("NOTICE: waiting for BitcoinLE Peer Node(s) to connect (%lu)\n", i);
		++i;
		MilliSleep(1000);
	}
	return i;
}

typedef struct uint32x4x6_t
{
  uint32x4_t val[6];
} uint32x4x6_t;

typedef struct uint32x4x14_t
{
  uint32x4_t val[14];
} uint32x4x14_t;


typedef struct uint32x4x24_t
{
  uint32x4_t STATEA0;
  uint32x4_t STATEA1;
  uint32x4_t STATEB0;
  uint32x4_t STATEB1;
  uint32x4_t STATEC0;
  uint32x4_t STATEC1;
  uint32x4_t STATED0;
  uint32x4_t STATED1;
  uint32x4_t MSGA0;
  uint32x4_t MSGA1;
  uint32x4_t MSGA2;
  uint32x4_t MSGA3;
  uint32x4_t MSGB0;
  uint32x4_t MSGB1;
  uint32x4_t MSGB2;
  uint32x4_t MSGB3;
  uint32x4_t MSGC0;
  uint32x4_t MSGC1;
  uint32x4_t MSGC2;
  uint32x4_t MSGC3;
  uint32x4_t MSGD0;
  uint32x4_t MSGD1;
  uint32x4_t MSGD2;
  uint32x4_t MSGD3;
} uint32x4x24_t;

alignas(16) static const uint32_t K[64] = {
	0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,
	0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
	0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,
	0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
	0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,
	0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
	0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,
	0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
	0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,
	0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
	0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,
	0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
	0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,
	0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
	0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,
	0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

// Customized hasher for BitcoinLE BlockHeader Miner 
uint32x4x14_t BleMinerTransform1(unsigned char* blockheaders)
{
    alignas(16) uint32x4_t STATEA0, STATEA1/*, STATEA0_BACKUP, STATEA1_BACKUP*/;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load initial state
    STATEA0 = (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    STATEA1 = (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    alignas(16) const uint8x16_t* input32 = reinterpret_cast<const uint8x16_t*>(blockheaders);

		// Transform 1
        // Load and Convert input chunk to Big Endian
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA3 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEA1 = vaddq_u32(STATEA1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });

        // Load next 48 bytes and Convert input chunk to Big Endian.
	// Patching in padding1 applied with bswap32 to missing 16 bytes.
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
	// Last member contains nNonce. Return as Little Endian to allow easier incrementing.
        MSGA2 = vreinterpretq_u32_u8(*input32++);
        MSGA3 = (const uint32x4_t) { 0x80000000, 0x00000000, 0x00000000, 0x00000380 };

	uint32x4x14_t scratchpad;

	scratchpad.val[0] = STATEA0;
	scratchpad.val[1] = STATEA1;
	scratchpad.val[2] = vsha256su0q_u32(MSGA0, MSGA1);
	scratchpad.val[3] = MSGA1;
	scratchpad.val[4] = MSGA2;
	scratchpad.val[5] = MSGA3;

	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        //MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        //MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        //MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

	scratchpad.val[12] = STATEA0;
	scratchpad.val[13] = STATEA1;

	return scratchpad;
}

// Customized hasher for BitcoinLE BlockHeader Miner 
void BleMinerInitialTransform(const unsigned char* blockheaders, uint32_t* scratchpad)
{
    alignas(16) uint32x4_t STATEA0, STATEA1, STATEA0_BACKUP, STATEA1_BACKUP;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load initial state
    STATEA0 = (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    STATEA1 = (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    alignas(16) const uint8x16_t* input32 = reinterpret_cast<const uint8x16_t*>(blockheaders);

		// Transform 1
        // Load and Convert input chunk to Big Endian
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA3 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEA1 = vaddq_u32(STATEA1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });

        // Load next 48 bytes and Convert input chunk to Big Endian.
	// Patching in padding1 applied with bswap32 to missing 16 bytes.
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
	// 2nd and 4th lanes contains nTime & nNonce.
	// Return as Little Endian to allow easier incrementing.
        MSGA2 = vreinterpretq_u32_u8(*input32++);
        MSGA3 = (const uint32x4_t) { 0x80000000, 0x00000000, 0x00000000, 0x00000380 };

	uint32x4_t SHA256INIT0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
	uint32x4_t SHA256INIT1 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

	uint32x4_t PADDING2A = { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
	uint32x4_t PADDING2B = { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };

	vst1q_u32(&scratchpad[ 0], STATEA0);
	vst1q_u32(&scratchpad[ 4], STATEA1);
	vst1q_u32(&scratchpad[ 8], MSGA0);
	vst1q_u32(&scratchpad[12], MSGA1);
	vst1q_u32(&scratchpad[16], MSGA2);
	vst1q_u32(&scratchpad[20], MSGA3);
	vst1q_u32(&scratchpad[24], SHA256INIT0);
	vst1q_u32(&scratchpad[28], SHA256INIT1);
	vst1q_u32(&scratchpad[32], PADDING2A);
	vst1q_u32(&scratchpad[36], PADDING2B);
}

// Customized hasher for BitcoinLE BlockHeader Miner 
uint32x4x2_t inline BleMiner(uint32x4x6_t stateandmessage)
{

    alignas(16) uint32x4_t STATEA0, STATEA1;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

/*    alignas(16) uint32x4_t STATEB0, STATEB1, STATEB0_BACKUP, STATEB1_BACKUP;
    alignas(16) uint32x4_t MSGB0, MSGB1, MSGB2, MSGB3;*/

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load initial state
    STATEA0 = stateandmessage.val[0];
    STATEA1 = stateandmessage.val[1];
/*    STATEB0 = STATEA0;
    STATEB1 = STATEA1;*/

		// Transform 2

        MSGA0 = stateandmessage.val[2];
        MSGA1 = stateandmessage.val[3];
	// Imported as Little Endian to allow for easier nNonce increment
	// Perform to Big Endian conversion
	// stateandmessage.val[4][3]++;
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGA3 = stateandmessage.val[5];
/*      MSGB0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB3 = vreinterpretq_u32_u8(vrev32q_u8((const uint32x4_t) { 0x00000080, 0x00000000, 0x00000000, 0x80030000 }));
*/
/*
printf("\nBig Endian Loaded message digest in Transform 2\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// might be able to predefine this
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/

		// Transform 3
        // Combine previous and updated states into next message digest upper half
	// Patch in padding2 applied with bswap32 to missing lower half 32 bytes
        MSGA0 = vaddq_u32(STATEA0, stateandmessage.val[0]);
        MSGA1 = vaddq_u32(STATEA1, stateandmessage.val[1]);
	MSGA2 = (const uint32x4_t) { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
	MSGA3 = (const uint32x4_t) { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };
/*
printf("\nLoaded message digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/
/*
printf("\nmessage digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

/*
	MSGB0 = vaddq_u32(STATEB0, STATEB0_BACKUP);
        MSGB1 = vaddq_u32(STATEB1, STATEB1_BACKUP);
        MSGB2 = MSGA2;
        MSGB3 = MSGA3;
*/
    // Load initial state
    STATEA0 = (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    STATEA1 = (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
/*  STATEB0 = STATEA0;
    STATEB1 = STATEA1;
*/
        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
	// might be able to skip this
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
	// Might be able to precalculate this as 2&3 inputs are static
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
	// might be able to skip this
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// Might be able to precalculate this as MSGA2&MSGA3 inputs are static
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEA1 = vaddq_u32(STATEA1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
/*
        STATEB0 = vaddq_u32(STATEB0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEB1 = vaddq_u32(STATEB1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
*/

    // Save hash to output
 //   vst1q_u32(&blockhash[0], STATEA0);
 //   vst1q_u32(&blockhash[4], STATEA1);

	return (uint32x4x2_t) { STATEA0, STATEA1 };
/*
	vst1q_u32(&blockhash[8], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB0);
	vst1q_u32(&blockhash[12], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB1);
*/
}

// Customized hasher for BitcoinLE BlockHeader Miner 
uint32x4x4_t inline BleMiner2Way(uint32x4x6_t stateandmessage)
{

    alignas(16) uint32x4_t STATEA0, STATEA1;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

    alignas(16) uint32x4_t STATEB0, STATEB1;
    alignas(16) uint32x4_t MSGB0, MSGB1, MSGB2, MSGB3;

    alignas(16) const uint32x4_t SHA256INIT0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    alignas(16) const uint32x4_t SHA256INIT1 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    alignas(16) const uint32x4_t PADDING2A = { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
    alignas(16) const uint32x4_t PADDING2B = { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load state
    STATEA0 = stateandmessage.val[0];
    STATEA1 = stateandmessage.val[1];
    STATEB0 = stateandmessage.val[0];
    STATEB1 = stateandmessage.val[1];

		// Transform 2

        MSGA0 = stateandmessage.val[2];
        MSGA1 = stateandmessage.val[3];
	// Imported as Little Endian to allow for easier nNonce increment
	// Load Byte Swapped
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGA3 = stateandmessage.val[5];

	// Increment nNonce for 2nd Way
	stateandmessage.val[4][3]++;

	MSGB0 = stateandmessage.val[2];
        MSGB1 = stateandmessage.val[3];
	// Load Byte Swapped
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGB3 = stateandmessage.val[5];

/*
printf("\nBig Endian Loaded message digest in Transform 2\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// might be able to predefine this
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);


		// Transform 3
        // Combine previous and updated states into next message digest upper half
	// Patch in Byte Swapped padding2 to missing lower half 32 bytes
        MSGA0 = vaddq_u32(STATEA0, stateandmessage.val[0]);
        MSGA1 = vaddq_u32(STATEA1, stateandmessage.val[1]);
	MSGA2 = PADDING2A;
	MSGA3 = PADDING2B;
/*
printf("\nLoaded message digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/
/*
printf("\nmessage digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

	MSGB0 = vaddq_u32(STATEB0, stateandmessage.val[0]);
        MSGB1 = vaddq_u32(STATEB1, stateandmessage.val[1]);
        MSGB2 = PADDING2A;
        MSGB3 = PADDING2B;

    // Load initial state
    STATEA0 = SHA256INIT0;
    STATEA1 = SHA256INIT1;
    STATEB0 = SHA256INIT0;
    STATEB1 = SHA256INIT1;

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
	// might be able to skip this
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
	// Might be able to precalculate this as 2&3 inputs are static
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
	// might be able to skip this
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// Might be able to precalculate this as MSGA2&MSGA3 inputs are static
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, SHA256INIT0);
        STATEA1 = vaddq_u32(STATEA1, SHA256INIT1);

        STATEB0 = vaddq_u32(STATEB0, SHA256INIT0);
        STATEB1 = vaddq_u32(STATEB1, SHA256INIT1);


    // Save hash to output
 //   vst1q_u32(&blockhash[0], STATEA0);
 //   vst1q_u32(&blockhash[4], STATEA1);

	// Reduce overheads by not returning Byte Swapped
	return (uint32x4x4_t) { STATEA0, STATEA1, STATEB0, STATEB1 };
/*
	vst1q_u32(&blockhash[8], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB0);
	vst1q_u32(&blockhash[12], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB1);
*/
}

/* 
  High performance customized ArmV8 hasher for 
  BitcoinLE BlockHeader Miner using sha2 extensions
  Performs three rounds of hashing, incrementing nNonce accordingly
  First 64 bytes is calculated once in BleMinerTransform1()
  Neon registers are next to saturation 31/32.
*/
inline void BleMiner3Way(uint32x4x14_t& stateandmessage)
{
	// States for 3 Work Ways
    //register uint32x4x6_t STATES;

    register uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

    register uint32x4_t MSGB0, MSGB1, MSGB2, MSGB3;

    register uint32x4_t MSGC0, MSGC1, MSGC2, MSGC3;

    register const uint32x4_t SHA256INIT0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    register const uint32x4_t SHA256INIT1 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

    register const uint32x4_t PADDING2A = { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
    register const uint32x4_t PADDING2B = { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };

    register uint32x4_t TMP0, TMP2, KTMP;

		// Transform 2
    // Load state
//    stateandmessage.val[6] = stateandmessage.val[0];
//    stateandmessage.val[7] = stateandmessage.val[1];
//    stateandmessage.val[8] = stateandmessage.val[0];
 //   stateandmessage.val[9] = stateandmessage.val[1];
//    stateandmessage.val[10] = stateandmessage.val[0];
 //   stateandmessage.val[11] = stateandmessage.val[1];

	// Load message digests. Incrementing nNonces for work ways.
        MSGA0 = stateandmessage.val[2];
        MSGA1 = stateandmessage.val[3];
	// Imported as Little Endian to allow for easier nNonce increment
	// Load Byte Swapped
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGA3 = stateandmessage.val[5];

	// Increment nNonce for 2nd Way
	stateandmessage.val[4][3]++;

	MSGB0 = stateandmessage.val[2];
        MSGB1 = stateandmessage.val[3];
	// Load Byte Swapped
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGB3 = stateandmessage.val[5];

	// Increment nNonce for 3rd Way
	stateandmessage.val[4][3]++;

	MSGC0 = stateandmessage.val[2];
        MSGC1 = stateandmessage.val[3];
	// Load Byte Swapped
        MSGC2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(stateandmessage.val[4])));
        MSGC3 = stateandmessage.val[5];

	// Increment nNonce for 1st Way next iteration
	stateandmessage.val[4][3]++;

/*
printf("\nBig Endian Loaded message digest in Transform 2\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

        // Rounds 1-4
/*	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);*/
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*      TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);*/
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

/*      TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);*/
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 5-8
	//KTMP = vld1q_u32(&K[4]);
        //TMP0 = vaddq_u32(MSGA1, KTMP);
        //TMP2 = stateandmessage.val[12];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        //stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        //stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[13], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
 
        //TMP0 = vaddq_u32(MSGB1, KTMP);
        //TMP2 = stateandmessage.val[12];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        //stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        //stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[13], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        //TMP0 = vaddq_u32(MSGC1, KTMP);
        //TMP2 = stateandmessage.val[12];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2); 
        //stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        //stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[13], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        //TMP2 = stateandmessage.val[6];
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[13], stateandmessage.val[12], TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        //TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[13], stateandmessage.val[12], TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        //TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[12], stateandmessage.val[13], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[13], stateandmessage.val[12], TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// might be able to predefine this
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        //TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        //TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);


		// Transform 3
        // Combine previous and updated states into next message digest upper half
	// Patch in Byte Swapped padding2 to missing lower half 32 bytes
        MSGA0 = vaddq_u32(stateandmessage.val[6], stateandmessage.val[0]);
        MSGA1 = vaddq_u32(stateandmessage.val[7], stateandmessage.val[1]);
	MSGA2 = PADDING2A;
	MSGA3 = PADDING2B;
/*
printf("\nLoaded message digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/
/*
printf("\nmessage digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

	MSGB0 = vaddq_u32(stateandmessage.val[8], stateandmessage.val[0]);
        MSGB1 = vaddq_u32(stateandmessage.val[9], stateandmessage.val[1]);
        MSGB2 = PADDING2A;
        MSGB3 = PADDING2B;

	MSGC0 = vaddq_u32(stateandmessage.val[10], stateandmessage.val[0]);
        MSGC1 = vaddq_u32(stateandmessage.val[11], stateandmessage.val[1]);
        MSGC2 = PADDING2A;
        MSGC3 = PADDING2B;

    // Load initial state
    stateandmessage.val[6] = SHA256INIT0;
    stateandmessage.val[7] = SHA256INIT1;
    stateandmessage.val[8] = SHA256INIT0;
    stateandmessage.val[9] = SHA256INIT1;
    stateandmessage.val[10] = SHA256INIT0;
    stateandmessage.val[11] = SHA256INIT1;

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
	// might be able to skip this
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
	// Might be able to precalculate this as 2&3 inputs are static
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
	// might be able to skip this
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// Might be able to precalculate this as MSGA2&MSGA3 inputs are static
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        //TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        //TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC0 = vsha256su0q_u32(MSGC0, MSGC1);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC0 = vsha256su1q_u32(MSGC0, MSGC2, MSGC3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC1 = vsha256su0q_u32(MSGC1, MSGC2);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC1 = vsha256su1q_u32(MSGC1, MSGC3, MSGC0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC2 = vsha256su0q_u32(MSGC2, MSGC3);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC2 = vsha256su1q_u32(MSGC2, MSGC0, MSGC1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        MSGC3 = vsha256su0q_u32(MSGC3, MSGC0);
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);
        MSGC3 = vsha256su1q_u32(MSGC3, MSGC1, MSGC2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC0, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC1, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC2, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = stateandmessage.val[6];
        stateandmessage.val[6] = vsha256hq_u32(stateandmessage.val[6], stateandmessage.val[7], TMP0);
        stateandmessage.val[7] = vsha256h2q_u32(stateandmessage.val[7], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = stateandmessage.val[8];
        stateandmessage.val[8] = vsha256hq_u32(stateandmessage.val[8], stateandmessage.val[9], TMP0);
        stateandmessage.val[9] = vsha256h2q_u32(stateandmessage.val[9], TMP2, TMP0);

        TMP0 = vaddq_u32(MSGC3, KTMP);
        TMP2 = stateandmessage.val[10];
        stateandmessage.val[10] = vsha256hq_u32(stateandmessage.val[10], stateandmessage.val[11], TMP0);
        stateandmessage.val[11] = vsha256h2q_u32(stateandmessage.val[11], TMP2, TMP0);

        // Combine with initial state and store
        stateandmessage.val[6] = vaddq_u32(stateandmessage.val[6], SHA256INIT0);
        stateandmessage.val[7] = vaddq_u32(stateandmessage.val[7], SHA256INIT1);

        stateandmessage.val[8] = vaddq_u32(stateandmessage.val[8], SHA256INIT0);
        stateandmessage.val[9] = vaddq_u32(stateandmessage.val[9], SHA256INIT1);

        stateandmessage.val[10] = vaddq_u32(stateandmessage.val[10], SHA256INIT0);
        stateandmessage.val[11] = vaddq_u32(stateandmessage.val[11], SHA256INIT1);

	// Reduce overheads by not returning Byte Swapped
//	return stateandmessage;
}

/* 
  High performance customized ArmV8 hasher for 
  BitcoinLE BlockHeader Miner using sha2 extensions
  Performs three rounds of hashing, incrementing nNonce accordingly
  First 64 bytes is calculated once in BleMinerTransform1()
  Neon registers are next to saturation 31/32.
*/
inline void BleMiner4Way(uint32_t* stateandmessage, uint32x4x24_t& workpad)
{
    register uint32x4_t TMP0, TMP2, KTMP;

		// Transform 2
    workpad.STATEA0 = vld1q_u32(&stateandmessage[0]);
    workpad.STATEA1 = vld1q_u32(&stateandmessage[4]);
    workpad.STATEB0 = workpad.STATEA0;
    workpad.STATEB1 = workpad.STATEA1;
    workpad.STATEC0 = workpad.STATEA0;
    workpad.STATEC1 = workpad.STATEA1;
    workpad.STATED0 = workpad.STATEA0;
    workpad.STATED1 = workpad.STATEA1;

	// Load message digests. Incrementing nNonces for work ways.
        workpad.MSGA0 = vld1q_u32(&stateandmessage[8]);
        workpad.MSGA1 = vld1q_u32(&stateandmessage[12]);
	// Imported as Little Endian to allow for easier nNonce increment
	// Load Byte Swapped
        workpad.MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(&stateandmessage[16]))));
        workpad.MSGA3 = vld1q_u32(&stateandmessage[20]);

	// Increment nNonce for 2nd Way
	stateandmessage[19]++;
	//stateandmessage.val[4][3]++;

	workpad.MSGB0 = workpad.MSGA0;
        workpad.MSGB1 = workpad.MSGA1;
	// Load Byte Swapped
        workpad.MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(&stateandmessage[16]))));
        workpad.MSGB3 = workpad.MSGA3;

	// Increment nNonce for 3rd Way
	stateandmessage[19]++;

	workpad.MSGC0 = workpad.MSGA0;
        workpad.MSGC1 = workpad.MSGA1;
	// Load Byte Swapped
        workpad.MSGC2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(&stateandmessage[16]))));
        workpad.MSGC3 = workpad.MSGA3;

	// Increment nNonce for 4th Way
	stateandmessage[19]++;

	workpad.MSGD0 = workpad.MSGA0;
        workpad.MSGD1 = workpad.MSGA1;
	// Load Byte Swapped
        workpad.MSGD2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(vld1q_u32(&stateandmessage[16]))));
        workpad.MSGD3 = workpad.MSGA3;

	// Increment nNonce for 1st Way next iteration
	stateandmessage[19]++;

for(int i = 0; i < 2; i++) {
        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// might be able to predefine this
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

	if(i == 0) {
		// Transform 3
	// Load Transform 1 state
	TMP0 = vld1q_u32(&stateandmessage[0]);
	TMP2 = vld1q_u32(&stateandmessage[4]);

        workpad.MSGA0 = vaddq_u32(workpad.STATEA0, TMP0);
        workpad.MSGA1 = vaddq_u32(workpad.STATEA1, TMP2);
	workpad.MSGA2 = vld1q_u32(&stateandmessage[32]);
	workpad.MSGA3 = vld1q_u32(&stateandmessage[36]);

	workpad.MSGB0 = vaddq_u32(workpad.STATEB0, TMP0);
        workpad.MSGB1 = vaddq_u32(workpad.STATEB1, TMP2);
        workpad.MSGB2 = workpad.MSGA2;
        workpad.MSGB3 = workpad.MSGA3;

	workpad.MSGC0 = vaddq_u32(workpad.STATEC0, TMP0);
        workpad.MSGC1 = vaddq_u32(workpad.STATEC1, TMP2);
        workpad.MSGC2 = workpad.MSGA2;
        workpad.MSGC3 = workpad.MSGA3;

	workpad.MSGD0 = vaddq_u32(workpad.STATED0, TMP0);
        workpad.MSGD1 = vaddq_u32(workpad.STATED1, TMP2);
        workpad.MSGD2 = workpad.MSGA2;
        workpad.MSGD3 = workpad.MSGA3;

	// Load initial state
	TMP0 = vld1q_u32(&stateandmessage[24]);
	TMP2 = vld1q_u32(&stateandmessage[28]);
	workpad.STATEA0 = TMP0;
	workpad.STATEA1 = TMP2;
	workpad.STATEB0 = TMP0;
	workpad.STATEB1 = TMP2;
	workpad.STATEC0 = TMP0;
	workpad.STATEC1 = TMP2;
	workpad.STATED0 = TMP0;
	workpad.STATED1 = TMP2;

	continue;
	}
}
	        // Combine with initial state and store
	TMP0 = vld1q_u32(&stateandmessage[24]);
	TMP2 = vld1q_u32(&stateandmessage[28]);

        workpad.STATEA0 = vaddq_u32(workpad.STATEA0, TMP0);
        workpad.STATEA1 = vaddq_u32(workpad.STATEA1, TMP2);

        workpad.STATEB0 = vaddq_u32(workpad.STATEB0, TMP0);
        workpad.STATEB1 = vaddq_u32(workpad.STATEB1, TMP2);

        workpad.STATEC0 = vaddq_u32(workpad.STATEC0, TMP0);
        workpad.STATEC1 = vaddq_u32(workpad.STATEC1, TMP2);

        workpad.STATED0 = vaddq_u32(workpad.STATED0, TMP0);
        workpad.STATED1 = vaddq_u32(workpad.STATED1, TMP2);
/*
		// Transform 3
	// Load Transform 1 state
	TMP0 = vld1q_u32(&stateandmessage[0]);
	TMP2 = vld1q_u32(&stateandmessage[4]);

        workpad.MSGA0 = vaddq_u32(workpad.STATEA0, TMP0);
        workpad.MSGA1 = vaddq_u32(workpad.STATEA1, TMP2);
	workpad.MSGA2 = vld1q_u32(&stateandmessage[32]);
	workpad.MSGA3 = vld1q_u32(&stateandmessage[36]);

	workpad.MSGB0 = vaddq_u32(workpad.STATEB0, TMP0);
        workpad.MSGB1 = vaddq_u32(workpad.STATEB1, TMP2);
        workpad.MSGB2 = workpad.MSGA2;
        workpad.MSGB3 = workpad.MSGA3;

	workpad.MSGC0 = vaddq_u32(workpad.STATEC0, TMP0);
        workpad.MSGC1 = vaddq_u32(workpad.STATEC1, TMP2);
        workpad.MSGC2 = workpad.MSGA2;
        workpad.MSGC3 = workpad.MSGA3;

	workpad.MSGD0 = vaddq_u32(workpad.STATED0, TMP0);
        workpad.MSGD1 = vaddq_u32(workpad.STATED1, TMP2);
        workpad.MSGD2 = workpad.MSGA2;
        workpad.MSGD3 = workpad.MSGA3;

    // Load initial state
    TMP0 = vld1q_u32(&stateandmessage[24]);
    TMP2 = vld1q_u32(&stateandmessage[28]);
    workpad.STATEA0 = TMP0;
    workpad.STATEA1 = TMP2;
    workpad.STATEB0 = TMP0;
    workpad.STATEB1 = TMP2;
    workpad.STATEC0 = TMP0;
    workpad.STATEC1 = TMP2;
    workpad.STATED0 = TMP0;
    workpad.STATED1 = TMP2;

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
	// might be able to skip this
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
	// Might be able to precalculate this as 2&3 inputs are static
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
	// might be able to skip this
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
	// Might be able to precalculate this as workpad.MSGA2&workpad.MSGA3 inputs are static
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA0 = vsha256su0q_u32(workpad.MSGA0, workpad.MSGA1);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA0 = vsha256su1q_u32(workpad.MSGA0, workpad.MSGA2, workpad.MSGA3);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB0 = vsha256su0q_u32(workpad.MSGB0, workpad.MSGB1);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB0 = vsha256su1q_u32(workpad.MSGB0, workpad.MSGB2, workpad.MSGB3);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC0 = vsha256su0q_u32(workpad.MSGC0, workpad.MSGC1);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC0 = vsha256su1q_u32(workpad.MSGC0, workpad.MSGC2, workpad.MSGC3);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD0 = vsha256su0q_u32(workpad.MSGD0, workpad.MSGD1);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD0 = vsha256su1q_u32(workpad.MSGD0, workpad.MSGD2, workpad.MSGD3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA1 = vsha256su0q_u32(workpad.MSGA1, workpad.MSGA2);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA1 = vsha256su1q_u32(workpad.MSGA1, workpad.MSGA3, workpad.MSGA0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB1 = vsha256su0q_u32(workpad.MSGB1, workpad.MSGB2);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB1 = vsha256su1q_u32(workpad.MSGB1, workpad.MSGB3, workpad.MSGB0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC1 = vsha256su0q_u32(workpad.MSGC1, workpad.MSGC2);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC1 = vsha256su1q_u32(workpad.MSGC1, workpad.MSGC3, workpad.MSGC0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD1 = vsha256su0q_u32(workpad.MSGD1, workpad.MSGD2);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD1 = vsha256su1q_u32(workpad.MSGD1, workpad.MSGD3, workpad.MSGD0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA2 = vsha256su0q_u32(workpad.MSGA2, workpad.MSGA3);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA2 = vsha256su1q_u32(workpad.MSGA2, workpad.MSGA0, workpad.MSGA1);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB2 = vsha256su0q_u32(workpad.MSGB2, workpad.MSGB3);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB2 = vsha256su1q_u32(workpad.MSGB2, workpad.MSGB0, workpad.MSGB1);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC2 = vsha256su0q_u32(workpad.MSGC2, workpad.MSGC3);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC2 = vsha256su1q_u32(workpad.MSGC2, workpad.MSGC0, workpad.MSGC1);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD2 = vsha256su0q_u32(workpad.MSGD2, workpad.MSGD3);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD2 = vsha256su1q_u32(workpad.MSGD2, workpad.MSGD0, workpad.MSGD1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.MSGA3 = vsha256su0q_u32(workpad.MSGA3, workpad.MSGA0);
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);
        workpad.MSGA3 = vsha256su1q_u32(workpad.MSGA3, workpad.MSGA1, workpad.MSGA2);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.MSGB3 = vsha256su0q_u32(workpad.MSGB3, workpad.MSGB0);
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);
        workpad.MSGB3 = vsha256su1q_u32(workpad.MSGB3, workpad.MSGB1, workpad.MSGB2);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.MSGC3 = vsha256su0q_u32(workpad.MSGC3, workpad.MSGC0);
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);
        workpad.MSGC3 = vsha256su1q_u32(workpad.MSGC3, workpad.MSGC1, workpad.MSGC2);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.MSGD3 = vsha256su0q_u32(workpad.MSGD3, workpad.MSGD0);
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);
        workpad.MSGD3 = vsha256su1q_u32(workpad.MSGD3, workpad.MSGD1, workpad.MSGD2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(workpad.MSGA0, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB0, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC0, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD0, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(workpad.MSGA1, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB1, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC1, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD1, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(workpad.MSGA2, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB2, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC2, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD2, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(workpad.MSGA3, KTMP);
        TMP2 = workpad.STATEA0;
        workpad.STATEA0 = vsha256hq_u32(workpad.STATEA0, workpad.STATEA1, TMP0);
        workpad.STATEA1 = vsha256h2q_u32(workpad.STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGB3, KTMP);
        TMP2 = workpad.STATEB0;
        workpad.STATEB0 = vsha256hq_u32(workpad.STATEB0, workpad.STATEB1, TMP0);
        workpad.STATEB1 = vsha256h2q_u32(workpad.STATEB1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGC3, KTMP);
        TMP2 = workpad.STATEC0;
        workpad.STATEC0 = vsha256hq_u32(workpad.STATEC0, workpad.STATEC1, TMP0);
        workpad.STATEC1 = vsha256h2q_u32(workpad.STATEC1, TMP2, TMP0);

        TMP0 = vaddq_u32(workpad.MSGD3, KTMP);
        TMP2 = workpad.STATED0;
        workpad.STATED0 = vsha256hq_u32(workpad.STATED0, workpad.STATED1, TMP0);
        workpad.STATED1 = vsha256h2q_u32(workpad.STATED1, TMP2, TMP0);

        // Combine with initial state and store
	TMP0 = vld1q_u32(&stateandmessage[24]);
	TMP2 = vld1q_u32(&stateandmessage[28]);

        workpad.STATEA0 = vaddq_u32(workpad.STATEA0, TMP0);
        workpad.STATEA1 = vaddq_u32(workpad.STATEA1, TMP2);

        workpad.STATEB0 = vaddq_u32(workpad.STATEB0, TMP0);
        workpad.STATEB1 = vaddq_u32(workpad.STATEB1, TMP2);

        workpad.STATEC0 = vaddq_u32(workpad.STATEC0, TMP0);
        workpad.STATEC1 = vaddq_u32(workpad.STATEC1, TMP2);

        workpad.STATED0 = vaddq_u32(workpad.STATED0, TMP0);
        workpad.STATED1 = vaddq_u32(workpad.STATED1, TMP2);
*/
//	return workpad;
}

/*
  Highly efficient customized hasher for BitcoinLE BlockHeader Miner
  Splits into Two Ways for Transforms 2 & 3 performing two iterations of nNonce increment hashings simultaneously
*/
void inline BleMiner_2way(unsigned char* bleblockheaders, uint32_t* blockhash, uint32_t* CurrentnNonce)
{
	// 1st Way variables
    alignas(16) uint32x4_t STATEA0, STATEA1;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

	// 2nd Way variables
    alignas(16) uint32x4_t STATEB0, STATEB1;
    alignas(16) uint32x4_t MSGB0, MSGB1, MSGB2, MSGB3;

	// Cached Transform 1 message digest and state for Transforms 2 1st & 2nd Ways
    alignas(16) uint32x4_t INITIALDIGESTA0, INITIALDIGESTA1, INITIALDIGESTA2, INITIALDIGESTA3;
    alignas(16) uint32x4_t STATEA0_BACKUP, STATEA1_BACKUP;

	// SHA256 initial state
    alignas(16) const uint32x4_t INITIALSTATE0 = { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    alignas(16) const uint32x4_t INITIALSTATE1 = { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };

	// Padding1 as Big Endian for Transform 2 lower half 16 bytes of message digests
    alignas(16) const uint32x4_t PADDING1 = { 0x80000000, 0x00000000, 0x00000000, 0x00000380 };

	// Padding2 as Big Endian for Transform 3 lower half 32 bytes of message digests	
    alignas(16) const uint32x4_t PADDING2A = { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
    alignas(16) const uint32x4_t PADDING2B = { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load initial state
    STATEA0 = INITIALSTATE0;
    STATEA1 = INITIALSTATE1;
/*    STATEB0 = STATEA0;
    STATEB1 = STATEA1;*/

	// Cast pointer to input 112 byte BitcoinLE BlockHeader
    alignas(16) const uint8x16_t* blockheaders = reinterpret_cast<const uint8x16_t*>(reinterpret_cast<const void*>(bleblockheaders));

		// Transform 1
        // Load and Convert BitcoinLE's mining BlockHeader first 64 bytes as Big Endian
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGA3 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
/*      MSGB0 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB1 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB3 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
*/

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Combine with initial state and store
        STATEA0_BACKUP = vaddq_u32(STATEA0, INITIALSTATE0);
        STATEA1_BACKUP = vaddq_u32(STATEA1, INITIALSTATE1);
/*
        STATEB0_BACKUP = vaddq_u32(STATEB0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEB1_BACKUP = vaddq_u32(STATEB1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
*/

        // Load next 48 bytes and Convert input chunk to Big Endian.
	// Patching in Padding1 as Big Endian for missing final 16 bytes.
        INITIALDIGESTA0 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        INITIALDIGESTA1 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        INITIALDIGESTA2 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders));
        INITIALDIGESTA3 = PADDING1;

/*      MSGB0 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB1 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(*blockheaders++));
        MSGB3 = INITIALDIGESTA3;
*/

//printf("Nonce is %u\n", INITIALDIGESTA2[3]);
	// Results from Transform 1 are static and can be reused for Tranforms 2 & 3 repeatedly
	// Split into Two Ways, hashing two nNonces each iteration before exiting to update nTime
	// 5 Million iterations takes approximately half a second on sha2 feature enabled Cortex a53 @ 1.5ghz

	// Big Endian nNonce increment
    uint32x4_t nNonceIncrement = (const uint32x4_t) { 0, 0, 0, 0x01000000 };
/*
	uint32x4_t nonceincrementrevesed = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(nNonceIncrement)));

printf("Nonce bswapped %08x %08x %08x %08x\n", nonceincrementrevesed[0], nonceincrementrevesed[1], nonceincrementrevesed[2], nonceincrementrevesed[3]);
printf("Nonce increment without bswap %08x %08x %08x %08x\n", nNonceIncrement[0], nNonceIncrement[1], nNonceIncrement[2], nNonceIncrement[3]);
printf("Digest Nonce bswapped before workloop %08x %08x %08x %08x\n", INITIALDIGESTA2[0], INITIALDIGESTA2[1], INITIALDIGESTA2[2], INITIALDIGESTA2[3]);

        nonceincrementrevesed = vreinterpretq_u32_u8(*blockheaders);
printf("Digest Nonce without bswap32 before workloop %08x %08x %08x %08x\n\n", nonceincrementrevesed[0], nonceincrementrevesed[1], nonceincrementrevesed[2], nonceincrementrevesed[3]);
*/
    uint32_t nNonce = *CurrentnNonce;
    uint32_t limit = nNonce + 5000000;

for(; nNonce < limit; nNonce += 2) {

		// Transform 2
	// Load Trasform 1 state for both work Ways
	STATEA0 = STATEA0_BACKUP;
	STATEA1 = STATEA1_BACKUP;
	STATEB0 = STATEA0_BACKUP;
	STATEB1 = STATEA1_BACKUP;
// test that nNonce input is correct on account of big endian
        // Load message digest from Transform 1
        MSGA0 = INITIALDIGESTA0;
        MSGA1 = INITIALDIGESTA1;
	MSGA2 = vreinterpretq_u32_u8(*blockheaders); //INITIALDIGESTA2;
	MSGA2[3] = nNonce;
        MSGA3 = INITIALDIGESTA3;
	MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGA2)));
/*if(nNonce < (*CurrentnNonce + 5)) {
printf("Nonce on 1way is %08x %08x %08x %08x\n", INITIALDIGESTA2[0], INITIALDIGESTA2[1], INITIALDIGESTA2[2], INITIALDIGESTA2[3]);
}*/
	// Increment nNonce for 2nd Way
	INITIALDIGESTA2 = vaddq_u32(INITIALDIGESTA2, nNonceIncrement);

	// Load same message digest for 2nd way with nNonce incremented
	MSGB0 = INITIALDIGESTA0;
/*if(nNonce < (*CurrentnNonce + 5)) {
printf("Nonce incremented for 2way is %08x %08x %08x %08x\n", INITIALDIGESTA2[0], INITIALDIGESTA2[1], INITIALDIGESTA2[2], INITIALDIGESTA2[3]);
}*/
        MSGB1 = INITIALDIGESTA1;
        MSGB2 = vreinterpretq_u32_u8(*blockheaders); //INITIALDIGESTA2;
	MSGB2[3] = nNonce + 1;
        MSGB3 = INITIALDIGESTA3;
	MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(MSGB2)));

	// Increment again for next iteration 1st Way
	INITIALDIGESTA2 = vaddq_u32(INITIALDIGESTA2, nNonceIncrement);
 
        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
/*
if(nNonce < (*CurrentnNonce + 5)) {
printf("Nonce incremented for 1way next loop is %08x %08x %08x %08x\n\n", INITIALDIGESTA2[0], INITIALDIGESTA2[1], INITIALDIGESTA2[2], INITIALDIGESTA2[3]);
}*/
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

	TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);


		// Transform 3
        // Combine Transform 1 state and updated 2way states into next message digest upper halfs
	// Patch in Big Endian padding2 to missing lower half 32 bytes
        MSGA0 = vaddq_u32(STATEA0, STATEA0_BACKUP);
        MSGA1 = vaddq_u32(STATEA1, STATEA1_BACKUP);
	MSGA2 = PADDING2A;
	MSGA3 = PADDING2B;

	MSGB0 = vaddq_u32(STATEB0, STATEA0_BACKUP);
        MSGB1 = vaddq_u32(STATEB1, STATEA1_BACKUP);
        MSGB2 = PADDING2A;
        MSGB3 = PADDING2B;

    // Load initial state for both work Ways
    STATEA0 = INITIALSTATE0;
    STATEA1 = INITIALSTATE1;
    STATEB0 = INITIALSTATE0;
    STATEB1 = INITIALSTATE1;

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

	TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);

        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);

        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);

        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);

        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);

        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);

        // Combine with initial state
        STATEA0 = vaddq_u32(STATEA0, INITIALSTATE0);
        STATEA1 = vaddq_u32(STATEA1, INITIALSTATE1);

        STATEB0 = vaddq_u32(STATEB0, INITIALSTATE0);
        STATEB1 = vaddq_u32(STATEB1, INITIALSTATE1);


	// If first 4 bytes equals zero, exit for a full check
	if(STATEA0[0] == 0) {
		printf("1st Way found Candidate - %08x %08x %08x %08x %08x %08x %08x %08x\n", STATEA0[0], 
		STATEA0[1], STATEA0[2], STATEA0[3], STATEA1[0], STATEA1[1], STATEA1[2], STATEA1[3]);
		// Save candidate hash to output and exit for full check
		/*vst1q_u32(&blockhash[0], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEA0))));
		vst1q_u32(&blockhash[4], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEA1))));*/
		vst1q_u32(&blockhash[0], STATEA0);
		vst1q_u32(&blockhash[4], STATEA1);
     		// Record current nNonce for 1st Way work path
     		*CurrentnNonce = nNonce;
		return;
	} else if(STATEB0[0] == 0) {
		printf("2nd Way found Candidate - %08x %08x %08x %08x %08x %08x %08x %08x\n", STATEB0[0], 
		STATEB0[1], STATEB0[2], STATEB0[3], STATEB1[0], STATEB1[1], STATEB1[2], STATEB1[3]);
		// Save candidate hash to output and exit for full check
		vst1q_u32(&blockhash[0], STATEB0);
		vst1q_u32(&blockhash[4], STATEB1);
     		// Record current nNonce for 2nd Way work path
     		*CurrentnNonce = nNonce + 1;
		return;
	}
}

	*CurrentnNonce = nNonce;

/*		printf("First Way state not bswap32 - %08x %08x %08x %08x %08x %08x %08x %08x\n", STATEA0[0], 
		STATEA0[1], STATEA0[2], STATEA0[3], STATEA1[0], STATEA1[1], STATEA1[2], STATEA1[3]);

		printf("First Way state not bswap32 - %08x %08x %08x %08x %08x %08x %08x %08x\n", STATEB0[0], 
		STATEB0[1], STATEB0[2], STATEB0[3], STATEB1[0], STATEB1[1], STATEB1[2], STATEB1[3]);*/

    	vst1q_u32(&blockhash[0], STATEA0);
    	vst1q_u32(&blockhash[4], STATEA1);

    	vst1q_u32(&blockhash[8], STATEB0);
    	vst1q_u32(&blockhash[12], STATEB1);
}

// Customized hasher for BitcoinLE BlockHeader Miner 
uint32x4x2_t inline BleMiner_1way(unsigned char* blockheaders)
{
    alignas(16) uint32x4_t STATEA0, STATEA1, STATEA0_BACKUP, STATEA1_BACKUP;
    alignas(16) uint32x4_t MSGA0, MSGA1, MSGA2, MSGA3;

/*    alignas(16) uint32x4_t STATEB0, STATEB1, STATEB0_BACKUP, STATEB1_BACKUP;
    alignas(16) uint32x4_t MSGB0, MSGB1, MSGB2, MSGB3;*/

    alignas(16) uint32x4_t TMP0, TMP2, KTMP;

    // Load initial state
    STATEA0 = (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    STATEA1 = (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
/*    STATEB0 = STATEA0;
    STATEB1 = STATEA1;*/

    alignas(16) const uint8x16_t* input32 = reinterpret_cast<const uint8x16_t*>(blockheaders);

		// Transform 1
        // Load and Convert input chunk to Big Endian
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA3 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
/*      MSGB0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB3 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
*/
/*
printf("\nBig Endian Loaded message digest in Transform 1\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/
        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEA1 = vaddq_u32(STATEA1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
/*
printf("Transform 1 state %08x %08x %08x %08x %08x %08x %08x %08x\n", STATEA0[0], STATEA0[1], STATEA0[2], STATEA0[3], STATEA1[0], STATEA1[1], STATEA1[2], STATEA1[3]);
*/
/*
        STATEB0 = vaddq_u32(STATEB0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEB1 = vaddq_u32(STATEB1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
*/
 
		// Transform 2
	// Backup current states
	STATEA0_BACKUP = STATEA0;
	STATEA1_BACKUP = STATEA1;
/*	STATEB0_BACKUP = STATEB0;
	STATEB1_BACKUP = STATEB1;
*/
        // Load next 48 bytes and Convert input chunk to Big Endian.
	// Patching in padding1 applied with bswap32 to missing 16 bytes.
        MSGA0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGA3 = (const uint32x4_t) { 0x80000000, 0x00000000, 0x00000000, 0x00000380 };
/*      MSGB0 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB1 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB2 = vreinterpretq_u32_u8(vrev32q_u8(*input32++));
        MSGB3 = vreinterpretq_u32_u8(vrev32q_u8((const uint32x4_t) { 0x00000080, 0x00000000, 0x00000000, 0x80030000 }));
*/
/*
printf("\nBig Endian Loaded message digest in Transform 2\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/

		// Transform 3
        // Combine previous and updated states into next message digest upper half
	// Patch in padding2 applied with bswap32 to missing lower half 32 bytes
        MSGA0 = vaddq_u32(STATEA0, STATEA0_BACKUP);
        MSGA1 = vaddq_u32(STATEA1, STATEA1_BACKUP);
	MSGA2 = (const uint32x4_t) { 0x80000000, 0x00000000, 0x00000000, 0x00000000 };
	MSGA3 = (const uint32x4_t) { 0x00000000, 0x00000000, 0x00000000, 0x00000100 };
/*
printf("\nLoaded message digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/
/*
printf("\nmessage digest in Transform 3\n");
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n", MSGA0[0], MSGA0[1], MSGA0[2], MSGA0[3], MSGA1[0], MSGA1[1], MSGA1[2], MSGA1[3]);
printf("%08x %08x %08x %08x %08x %08x %08x %08x\n\n", MSGA2[0], MSGA2[1], MSGA2[2], MSGA2[3], MSGA3[0], MSGA3[1], MSGA3[2], MSGA3[3]);
*/

/*
	MSGB0 = vaddq_u32(STATEB0, STATEB0_BACKUP);
        MSGB1 = vaddq_u32(STATEB1, STATEB1_BACKUP);
        MSGB2 = MSGA2;
        MSGB3 = MSGA3;
*/
    // Load initial state
    STATEA0 = (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a };
    STATEA1 = (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 };
/*  STATEB0 = STATEA0;
    STATEB1 = STATEA1;
*/
        // Rounds 1-4
	KTMP = vld1q_u32(&K[0]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);

/*        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 5-8
	KTMP = vld1q_u32(&K[4]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 9-12
	KTMP = vld1q_u32(&K[8]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 13-16
	KTMP = vld1q_u32(&K[12]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 17-20
	KTMP = vld1q_u32(&K[16]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 21-24
	KTMP = vld1q_u32(&K[20]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 25-28
	KTMP = vld1q_u32(&K[24]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 29-32
	KTMP = vld1q_u32(&K[28]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 33-36
	KTMP = vld1q_u32(&K[32]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        MSGA0 = vsha256su0q_u32(MSGA0, MSGA1);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA0 = vsha256su1q_u32(MSGA0, MSGA2, MSGA3);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        MSGB0 = vsha256su0q_u32(MSGB0, MSGB1);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB0 = vsha256su1q_u32(MSGB0, MSGB2, MSGB3);
*/
        // Rounds 37-40
	KTMP = vld1q_u32(&K[36]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        MSGA1 = vsha256su0q_u32(MSGA1, MSGA2);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA1 = vsha256su1q_u32(MSGA1, MSGA3, MSGA0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        MSGB1 = vsha256su0q_u32(MSGB1, MSGB2);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB1 = vsha256su1q_u32(MSGB1, MSGB3, MSGB0);
*/
        // Rounds 41-44
	KTMP = vld1q_u32(&K[40]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        MSGA2 = vsha256su0q_u32(MSGA2, MSGA3);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA2 = vsha256su1q_u32(MSGA2, MSGA0, MSGA1);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        MSGB2 = vsha256su0q_u32(MSGB2, MSGB3);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB2 = vsha256su1q_u32(MSGB2, MSGB0, MSGB1);
*/
        // Rounds 45-48
	KTMP = vld1q_u32(&K[44]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        MSGA3 = vsha256su0q_u32(MSGA3, MSGA0);
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
        MSGA3 = vsha256su1q_u32(MSGA3, MSGA1, MSGA2);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        MSGB3 = vsha256su0q_u32(MSGB3, MSGB0);
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
        MSGB3 = vsha256su1q_u32(MSGB3, MSGB1, MSGB2);
*/
        // Rounds 49-52
	KTMP = vld1q_u32(&K[48]);
        TMP0 = vaddq_u32(MSGA0, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB0, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 53-56
	KTMP = vld1q_u32(&K[52]);
        TMP0 = vaddq_u32(MSGA1, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB1, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 57-60
	KTMP = vld1q_u32(&K[56]);
        TMP0 = vaddq_u32(MSGA2, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB2, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Rounds 61-64
	KTMP = vld1q_u32(&K[60]);
        TMP0 = vaddq_u32(MSGA3, KTMP);
        TMP2 = STATEA0;
        STATEA0 = vsha256hq_u32(STATEA0, STATEA1, TMP0);
        STATEA1 = vsha256h2q_u32(STATEA1, TMP2, TMP0);
/*
        TMP0 = vaddq_u32(MSGB3, KTMP);
        TMP2 = STATEB0;
        STATEB0 = vsha256hq_u32(STATEB0, STATEB1, TMP0);
        STATEB1 = vsha256h2q_u32(STATEB1, TMP2, TMP0);
*/
        // Combine with initial state and store
        STATEA0 = vaddq_u32(STATEA0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEA1 = vaddq_u32(STATEA1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
/*
        STATEB0 = vaddq_u32(STATEB0, (const uint32x4_t) { 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a });
        STATEB1 = vaddq_u32(STATEB1, (const uint32x4_t) { 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 });
*/

    // Save hash to output
 //   vst1q_u32(&blockhash[0], STATEA0);
 //   vst1q_u32(&blockhash[4], STATEA1);

	return (uint32x4x2_t) { STATEA0, STATEA1 };
/*
	vst1q_u32(&blockhash[8], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB0);
	vst1q_u32(&blockhash[12], vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(STATEB1);
*/
}

CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>& txns, const CScript& scriptPubKey)
{
	const CChainParams& chainparams = Params();

	const uint64_t MS_WAIT_TIME = 500;
	std::string waitingspinner = "|";
	//uint32_t spinnerposition = 0;
	bool printwaitingmessage = true;
	uint64_t secondswaiting = 0;

	//uint32_t PRINTF_PERIOD = 10000;

	std::shared_ptr<Metronome::CMetronomeBeat> beat;
	uint64_t i = wait4Peers();
	
	// if offline more than 10 minutes => wait for sync
	if (i > 60 * 10) {
		wait4Sync();
	}
	printf("\n");

	while(true) {
		if (handler.interrupt) {
			return CBlock();
		}
		if (!hasPeers()) {
			return CBlock();
		}

		CBlockIndex* headBlock = chainActive.Tip();
		
		std::shared_ptr<Metronome::CMetronomeBeat> currentBeat = Metronome::CMetronomeHelper::GetBlockInfo(headBlock->hashMetronome);
 
		if (currentBeat && !currentBeat->nextBlockHash.IsNull()) {
			//printf("Cenas = %s", currentBeat->nextBlockHash.GetHex().c_str());

			std::shared_ptr<Metronome::CMetronomeBeat> latestBeat = Metronome::CMetronomeHelper::GetBlockInfo(currentBeat->nextBlockHash);
			//std::shared_ptr<Metronome::CMetronomeBeat> latestBeat = Metronome::CMetronomeHelper::GetLatestMetronomeBeat();

			if (latestBeat) {
				int age = GetAdjustedTime() - latestBeat->blockTime;
				int sleepTime = latestBeat->blockTime - headBlock->GetBlockTime();
				printf("Found beat -> Hash: %s, Time: %lu, Age: %ds\n", latestBeat->hash.GetHex().c_str(), latestBeat->blockTime, age);
				printf("Previous Block -> Height: %d, Time: %lu, Sleep: %ds\n", headBlock->nHeight, headBlock->GetBlockTime(), sleepTime);
				printf("AdjustedTime: %d, Time: %d\n", GetAdjustedTime(), GetTime());
				beat = latestBeat;
				break;
			}
		}

		//if (i % (PRINTF_PERIOD / WAIT_TIME) == 0) {
			//printf("Current Height: %d\n", pindexPrev->nHeight);
			//printf("Waiting for metronome beat... %lu ms\n", i * WAIT_TIME);
		//}
		//printf("Waiting for metronome beat... %c \r", waitingspinner); fflush(stdout);
		if(printwaitingmessage) {
			std::cout << "Waiting for metronome beat (" << 
			(secondswaiting * (MS_WAIT_TIME * 2)) / 1000 << "s)...\r" << std::flush;
		// << waitingspinner << "\r" << std::flush;
		/*	switch(spinnerposition) {
				case 0: { spinnerposition++ ; waitingspinner = "/"; break; }
				case 1: { spinnerposition++ ; waitingspinner = "-"; break; }
				case 2: { spinnerposition++ ; waitingspinner = "\\"; break; }
				case 3: { spinnerposition = 0; waitingspinner = "|"; break; }
				default: { break; }
			}*/
		secondswaiting++;
		}
		printwaitingmessage = (printwaitingmessage) ? false : true;
		MilliSleep(MS_WAIT_TIME);
	}

	printf("\nCreating new block...\n");

	std::unique_ptr<CBlockTemplate> pblocktemplate = BlockAssembler(chainparams).CreateNewBlock(scriptPubKey, true, beat->hash);
	CBlock& block = pblocktemplate->block;

	printf("Block difficulty nBits: %x \n", block.nBits);

	arith_uint256 bnTarget;
	bool fNegative, fOverflow;
	bnTarget.SetCompact(block.nBits, &fNegative, &fOverflow);
	printf("Target Hash: %s\n", bnTarget.GetHex().c_str());

	// Replace mempool-selected txns with just coinbase plus passed-in txns:
	//block.vtx.resize(1);
	//for (const CMutableTransaction& tx : txns)
	//	block.vtx.push_back(MakeTransactionRef(tx));
	// IncrementExtraNonce creates a valid coinbase and merkleRoot
	unsigned int extraNonce = 0;

	printf("Incrementing extra nonce...\n");
	IncrementExtraNonce(&block, chainActive.Tip(), extraNonce);

	handler.clear();
	handler.mineStartTime = GetTimeMillis();

	std::thread thds[MAX_N_THREADS];
	uint32_t PAGE_SIZE_MINER = 0x100000000 / MAX_N_THREADS;
	for (uint32_t i = 0; i < MAX_N_THREADS; ++i) {
thds[i] = std::thread(proofOfWorkFinder, i, CBlock(block), i * PAGE_SIZE_MINER, (i + 1) * PAGE_SIZE_MINER, &handler, PAGE_SIZE_MINER);
//thds[i] = std::thread(proofOfWorkFinderArmV8, i, CBlock(block), i * PAGE_SIZE_MINER, (i + 1) * PAGE_SIZE_MINER, &handler);
	} 

	for (uint32_t i = 0; i < MAX_N_THREADS; ++i) {
		thds[i].join();
	}

	if (handler.found) {
		return handler.block;
	}

	return CBlock();
}

void proofOfWorkFinderArmV8(uint32_t idx, CBlock block, uint32_t from, uint32_t to, MinerHandler* handler) {
	const CChainParams& chainparams = Params();
	block.nNonce = from;
	uint256 currenthash;
	CBlock blockheader;
	handler->currentOffset[idx] = 0;
	alignas(16) unsigned char bleheaders[112];
/* 
 bool showmessage = false; // Used by testing method in work loop
 bool showmessage2 = false; 
 bool showmessage3 = false;*/

	// Compute reusable results of first 64 bytes which are static
	blockheader  = block.GetBlockHeader();
	std::memcpy(bleheaders, &blockheader, 112);
	// Bundle all registers into one struct. Low half is Transform 1 results along 
	// with incrementing nNonce & nTime. Upper half are results of 3 hashes from each iteration
	alignas(16) uint32_t msgctx[40];
	alignas(16) uint32x4x24_t workpad;
        BleMinerInitialTransform(bleheaders, msgctx);

	// Where results of 3 hashes computed against 3 incremented nOnces are returned
	//register uint32x4x6_t minedhashes;
//	register uint32x4x2_t minedhash2; // used for testing

	// Use separate variables for storing current and new BLE block hash values
	std::string hashPrevBlock, chaintipblockhash;
	if(idx == 0) {
		// Keep trying to retrieve previous hash from block object until success
		// This value is static but rereading from chainActive.Tip()->GetBlockHash() &
		// block.hashPrevBlock objects aggresively during mining has been unreliable and caused 
		// segfault or to return invalid hash string resulting in premature abort during mining.
		while(hashPrevBlock.length() < 64 && !handler->interrupt && !handler->stop) { 
			hashPrevBlock = block.hashPrevBlock.GetHex();
			MilliSleep(5);
		}
	}

	// Start the work loop
	while(true) {

		if(handler->stop) {
			// Sleep briefly freeing up cpu for post mining session operations
			MilliSleep(50);
			handler->currentOffset[idx] = block.nNonce - from;
			block.SetNull();
			break;
		}

		// Calculate hashes of 4 nNonces in one go.
		BleMiner4Way(msgctx, workpad);


		// stateandmessage.val[4][3] += 3;


/* // testing method uses built in hasher incrementing block.nNonce for it
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[0][0] && minedhash2.val[0][1] != minedhashes.val[0][1] && minedhash2.val[0][2] != minedhashes.val[0][2] && minedhash2.val[0][3] != minedhashes.val[0][3] && !showmessage) {

//printf("bleminer 1way fail %u %u %u %u %u \n", stateandmessage.val[0][0], stateandmessage.val[0][1], stateandmessage.val[0][2], stateandmessage.val[0][3], stateandmessage.val[4][3]);

printf("bleminer 1way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[0][0], minedhashes.val[0][1], minedhashes.val[0][2], minedhashes.val[0][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage=true;

}
		block.nNonce++;
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[2][0] && minedhash2.val[0][1] != minedhashes.val[2][1] && minedhash2.val[0][2] != minedhashes.val[2][2] && minedhash2.val[0][3] != minedhashes.val[2][3] && !showmessage2) {

printf("bleminer 2way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[2][0], minedhashes.val[2][1], minedhashes.val[2][2], minedhashes.val[2][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage2=true;

}
		block.nNonce++;
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[4][0] && minedhash2.val[0][1] != minedhashes.val[4][1] && minedhash2.val[0][2] != minedhashes.val[4][2] && minedhash2.val[0][3] != minedhashes.val[4][3] && !showmessage3) {

printf("bleminer 3way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[4][0], minedhashes.val[4][1], minedhashes.val[4][2], minedhashes.val[4][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage3=true;

}*/
		// Rough quick check for candidate hashes if last 
		// 4 bytes is equal to constant value of 0x00000000 in Vector 6
		// Lane 2 from Transform 1 results - (which is already rare)
		if(workpad.STATEA1[3] == msgctx[36]) {

			// miner does not return hash Byte Swapped
			workpad.STATEA0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEA0)));
			workpad.STATEA1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEA1)));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &workpad.STATEA0, 32);
 
	printf("checking if candidate hash from 1st Work Way is below target...\n%s\n",block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 1st Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Inform other threads to stop and focus on block submission
			//	handler->stop = true;
			//	break;
			}
		}

		// Test hash from 2nd Way
		block.nNonce++;
		if(workpad.STATEB1[3] == msgctx[36]) {

			// miner does not return hash Byte Swapped
			workpad.STATEB0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEB0)));
			workpad.STATEB1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEB1)));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &workpad.STATEB0, 32);
	printf("checking if candidate hash from 2nd Work Way is below target...\n%s\n",block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 2nd Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 2nd Way
			//	block.nNonce++;
				// Inform other threads to stop and focus on block submission
			//	handler->stop = true;
			//	break;
			}
		}

		// Test hash from 3rd Way
		block.nNonce++;
		if(workpad.STATEC1[3] == msgctx[36]) {

			// miner does not return hash Byte Swapped
			workpad.STATEC0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEC0)));
			workpad.STATEC1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATEC1)));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &workpad.STATEC0, 32);
	printf("checking if candidate hash from 3rd Work Way is below target...\n%s\n",block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 3rd Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 3rd Way
			//	block.nNonce += 2;
				// Inform other threads to stop and focus on block submission
			//	handler->stop = true;
			//	break;
			}
		}
		// Test hash from 3rd Way
		block.nNonce++;
		if(workpad.STATED1[3] == msgctx[36]) {

			// miner does not return hash Byte Swapped
			workpad.STATED0 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATED0)));
			workpad.STATED1 = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(workpad.STATED1)));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &workpad.STATED0, 32);
	printf("checking if candidate hash from 4th Work Way is below target...\n%s\n",block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 3rd Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 3rd Way
			//	block.nNonce += 3;
				// Inform other threads to stop and focus on block submission
			//	handler->stop = true;
			//	break;
			}
		}
		block.nNonce++;

		// Increment nNonce for block object which is used used by block submission
		//block.nNonce += 3;

		// Exit checks & blockhead nTime property update done every 6m cycles
		// or approximately once per second on a Cortex-a53 @ 1.5ghz
		// Modulus constant must be a multiple of 3
		if(block.nNonce % 6000000 == 0) {

			// block.nNonce & block.nTime need to be kept in
			// sync as they are used for block submission
			block.nTime = GetAdjustedTime();
			// Neon registers that store nTime & nNonce for custom ArmV8 hasher
			msgctx[17] = block.nTime;
	//		msgctx.val[4][1] = block.nTime; 
			// printf("block.nTime, stateandmessage.val[4][1] %08x %08x\n", block.nTime, stateandmessage.val[4][1]);

			// Only have the first thread check for externally found blocks and process cancellations
			// informing other mining threads to quit via new handler member 'stop' value
			if(idx == 0) {
				if(handler->interrupt) {
					handler->stop = true;
				}
				// Free up cpu on thread give chainActive chance to update
				MilliSleep(5);
				// Persistant retrieval for added externally mined block hash
				while((chaintipblockhash != chainActive.Tip()->GetBlockHash().GetHex() 
					|| chaintipblockhash.length() < 64) && !handler->stop && !handler->interrupt) {
					MilliSleep(5);
					chaintipblockhash = chainActive.Tip()->GetBlockHash().GetHex();
				}
				if(chaintipblockhash != hashPrevBlock) {
					printf("\nSomeone else mined the block! Restarting...\n");
					handler->stop = true;
				}
				if(block.nNonce >= to || block.nNonce < from) {
					printf("\nNonces are exhausted.\n");
					printf("If this Metronome Beat is still unclaimed, a new MerkleRoot ");
					printf("will be generated and mining resumes...\n");
					MilliSleep(10);
					block.SetNull();
					handler->stop = true;
				}
			}
		} // if(block.nNonce % 600000 == 0)
	}

	// Mining performance summary.
	if(idx == 0 && block.IsNull()) {
		uint32_t totalNonceCount = 0;
		for (uint32_t i = 0; i < MAX_N_THREADS; ++i) {
			totalNonceCount += (handler->currentOffset[i]);
		}
		if((GetTimeMillis() - handler->mineStartTime) >= 1000) {
			std::cout << totalNonceCount << " Hashes:" << " in " << (GetTimeMillis() - handler->mineStartTime) << " Milliseconds.";
		}
	}

	if (block.IsNull()) {
		//printf("Ending thread: %d\n", idx);
		return;
	}
	
	if(!hasPeers()) { 
		printf("\nWARNING: No connections to Node Peers for block submission...retrying for 5 seconds\n");
		// If no peers retry for 5 seconds
		uint32_t waitforpeers = 50;
		while(!hasPeers() && waitforpeers) {
			MilliSleep(100);
			waitforpeers--;
		}
		// Give up submitting new block if still no peers
		if(!hasPeers()) { return; }
	}
	//handler->stop = true; CheckProofOfWork conditional already sets this
	handler->found = true;
	handler->block = block;

	//MilliSleep(1000);
	//block.nTime += 120;

	std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
	bool success = ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

	printf("\nSubmitting newly mined block: %s, BlockTime: %lu, Now: %lu\n", block.GetHash().GetHex().c_str(), block.GetBlockTime(), GetTime());

	printf("Ending... Block accepted? %s.\n", success ? "Yes" : "No");
	//MilliSleep(10000);
}

void proofOfWorkFinder(uint32_t idx, CBlock block, uint32_t from, uint32_t to, MinerHandler* handler, uint32_t PAGE_SIZE_MINER) {
	const CChainParams& chainparams = Params();
	block.nNonce = from;
	uint256 currenthash;
	CBlock blockheader;
	handler->currentOffset[idx] = 0;
	alignas(16) unsigned char bleheaders[112];
/* 
 bool showmessage = false; // Used by testing method in work loop
 bool showmessage2 = false; 
 bool showmessage3 = false;*/

	// Compute reusable results of first 64 bytes which are static
	blockheader  = block.GetBlockHeader();
	std::memcpy(bleheaders, &blockheader, 112);
	// Bundle all registers into one struct. Low half is Transform 1 results along 
	// with incrementing nNonce & nTime. Upper half are results of 3 hashes from each iteration
	register uint32x4x14_t msgctx = BleMinerTransform1(bleheaders);

	// Where results of 3 hashes computed against 3 incremented nOnces are returned
	//register uint32x4x6_t minedhashes;
//	register uint32x4x2_t minedhash2; // used for testing

	// Use separate variables for storing current and new BLE block hash values
	std::string hashPrevBlock, chaintipblockhash;
	if(idx == 0) {
		// Keep trying to retrieve previous hash from block object until success
		// This value is static but rereading from chainActive.Tip()->GetBlockHash() &
		// block.hashPrevBlock objects aggresively during mining has been unreliable and caused 
		// segfault or to return invalid hash string resulting in premature abort during mining.
		while(hashPrevBlock.length() < 64 && !handler->interrupt && !handler->stop) { 
			hashPrevBlock = block.hashPrevBlock.GetHex();
			MilliSleep(5);
		}
	}

	// Start the work loop
	while(true) {

		if(handler->stop) {
			// Sleep briefly freeing up cpu for post mining session operations
			handler->currentOffset[idx] = msgctx.val[4][3] - from;
			MilliSleep(50);
			block.SetNull();
			break;
		}

		// Calculate hashes of 3 nNonces in one go.
		BleMiner3Way(msgctx);

		// Increment nOnce to account for 3way - now handled internally in BleMiner3Way
		// stateandmessage.val[4][3] += 3;


/* // testing method uses built in hasher incrementing block.nNonce for it
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[0][0] && minedhash2.val[0][1] != minedhashes.val[0][1] && minedhash2.val[0][2] != minedhashes.val[0][2] && minedhash2.val[0][3] != minedhashes.val[0][3] && !showmessage) {

//printf("bleminer 1way fail %u %u %u %u %u \n", stateandmessage.val[0][0], stateandmessage.val[0][1], stateandmessage.val[0][2], stateandmessage.val[0][3], stateandmessage.val[4][3]);

printf("bleminer 1way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[0][0], minedhashes.val[0][1], minedhashes.val[0][2], minedhashes.val[0][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage=true;

}
		block.nNonce++;
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[2][0] && minedhash2.val[0][1] != minedhashes.val[2][1] && minedhash2.val[0][2] != minedhashes.val[2][2] && minedhash2.val[0][3] != minedhashes.val[2][3] && !showmessage2) {

printf("bleminer 2way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[2][0], minedhashes.val[2][1], minedhashes.val[2][2], minedhashes.val[2][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage2=true;

}
		block.nNonce++;
	currenthash = block.GetHash();

	std::memcpy(&minedhash2, &currenthash, 32);

//	minedhash = BleMiner_1way(bleheaders);

if(minedhash2.val[0][0] != minedhashes.val[4][0] && minedhash2.val[0][1] != minedhashes.val[4][1] && minedhash2.val[0][2] != minedhashes.val[4][2] && minedhash2.val[0][3] != minedhashes.val[4][3] && !showmessage3) {

printf("bleminer 3way fail\n");
printf(" %08x %08x %08x %08x \n", minedhashes.val[4][0], minedhashes.val[4][1], minedhashes.val[4][2], minedhashes.val[4][3]);
printf(" %08x %08x %08x %08x \n", minedhash2.val[0][0], minedhash2.val[0][1], minedhash2.val[0][2], minedhash2.val[0][3]);

showmessage3=true;

}*/
		// Rough quick check for candidate hashes if last 
		// 4 bytes is equal to constant value of 0x00000000 in Vector 6
		// Lane 2 from Transform 1 results - (which is already rare)
		//block.nNonce = (msgctx.val[4][3] - 3);
		if(msgctx.val[7][3] == 0) {

			// miner does not return hash Byte Swapped
			msgctx.val[6] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[6])));
			msgctx.val[7] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[7])));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &msgctx.val[6], 32);
 
//printf("checking if candidate hash from 1st Work Way is below target...%u %u\n%s\n", (msgctx.val[4][3] - 3), block.nNonce ,block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 1st Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 1st Way
				block.nNonce = (msgctx.val[4][3] - 3);
				// Inform other threads to stop and focus on block submission
				handler->stop = true;
				break;
			}
		}

		// Test hash from 2nd Way
		//block.nNonce = (msgctx.val[4][3] - 2); //used for testing only
		if(msgctx.val[9][3] == 0) {

			// miner does not return hash Byte Swapped
			msgctx.val[8] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[8])));
			msgctx.val[9] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[9])));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &msgctx.val[8], 32);
//printf("checking if candidate hash from 1st Work Way is below target...%u %u\n%s\n", (msgctx.val[4][3] - 2), block.nNonce, block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 2nd Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 2nd Way
				block.nNonce = (msgctx.val[4][3] - 2);
				// Inform other threads to stop and focus on block submission
				handler->stop = true;
				break;
			}
		}

		// Test hash from 3rd Way
		//block.nNonce = (msgctx.val[4][3] - 1);
		if(msgctx.val[11][3] == 0) {

			// miner does not return hash Byte Swapped
			msgctx.val[10] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[10])));
			msgctx.val[11] = vreinterpretq_u32_u8(vrev32q_u8(vreinterpretq_u8_u32(msgctx.val[11])));

			// Copy hash to uint256 that Bitcoin LE Core understands
			std::memcpy(&currenthash, &msgctx.val[10], 32);
//printf("checking if candidate hash from 1st Work Way is below target...%u %u\n%s\n", (msgctx.val[4][3] - 1), block.nNonce, block.GetHash().GetHex().c_str());
			printf("checking if candidate hash from 3rd Work Way is below target...\n%s\n",currenthash.GetHex().c_str());
			// If true, do a full check whether hash is below target and exit for block submission
			if(CheckProofOfWork(currenthash, block.nBits, chainparams.GetConsensus())) {
				// Increment nNonce to account for 3rd Way
				block.nNonce = (msgctx.val[4][3] - 1);
				// Inform other threads to stop and focus on block submission
				handler->stop = true;
				break;
			}
		}
		//block.nNonce++; //used for testing only

		// Increment nNonce for block object which is used used by block submission
		//block.nNonce += 3; // this is now done when valid block is found

		// Exit checks & blockhead nTime property update done every 3m cycles
		// or approximately twice per second on a Cortex-a53 @ 1.5ghz
		// Modulus constant must be a multiple of 3
		if(msgctx.val[4][3] % 3000000 == 0) {

			// block.nNonce & block.nTime need to be kept in
			// sync as they are used for block submission
			block.nTime = GetAdjustedTime();
			// Neon registers that store nTime & nNonce for custom ArmV8 hasher
			msgctx.val[4][1] = block.nTime; 
			// printf("block.nTime, stateandmessage.val[4][1] %08x %08x\n", block.nTime, stateandmessage.val[4][1]);

			// Only have the first thread check for externally found blocks and process cancellations
			// informing other mining threads to quit via new handler member 'stop' value
			if(idx == 0) {
				if(handler->interrupt) {
					handler->stop = true;
				}
				// Free up cpu on thread give chainActive chance to update
				MilliSleep(5);
				// Persistant retrieval for added externally mined block hash
				while((chaintipblockhash != chainActive.Tip()->GetBlockHash().GetHex() 
					|| chaintipblockhash.length() < 64) && !handler->stop && !handler->interrupt) {
					MilliSleep(5);
					chaintipblockhash = chainActive.Tip()->GetBlockHash().GetHex();
				}
				if(chaintipblockhash != hashPrevBlock) {
					printf("\nSomeone else mined the block! Restarting...\n");
					handler->stop = true;
				}
				if(block.nNonce >= to || block.nNonce < from) {
					printf("\nNonces are exhausted.\n");
					printf("If this Metronome Beat is still unclaimed, a new MerkleRoot ");
					printf("will be generated and mining resumes...\n");
					handler->stop = true;
					MilliSleep(10);
					block.SetNull();
				}
			}
		} // if(block.nNonce % 600000 == 0)
	}

	// Mining performance summary.
	if(idx == 0 && block.IsNull()) {
		uint32_t totalNonceCount = 0;
		for (uint32_t i = 0; i < MAX_N_THREADS; ++i) {
			totalNonceCount += handler->currentOffset[i];
		}
		if((GetTimeMillis() - handler->mineStartTime) >= 1000) {
			std::cout << totalNonceCount << " Hashes:" << " in " << (GetTimeMillis() - handler->mineStartTime) << " Milliseconds.";
		}
	}

	if (block.IsNull()) {
		//printf("Ending thread: %d\n", idx);
		return;
	}
	
	if(!hasPeers()) { 
		printf("\nWARNING: No connections to Node Peers for block submission...retrying for 5 seconds\n");
		// If no peers retry for 5 seconds
		uint32_t waitforpeers = 50;
		while(!hasPeers() && waitforpeers) {
			MilliSleep(100);
			waitforpeers--;
		}
		// Give up submitting new block if still no peers
		if(!hasPeers()) { return; }
	}
	//handler->stop = true; CheckProofOfWork conditional already sets this
	handler->found = true;
	handler->block = block;

	//MilliSleep(1000);
	//block.nTime += 120;

	std::shared_ptr<const CBlock> shared_pblock = std::make_shared<const CBlock>(block);
	bool success = ProcessNewBlock(chainparams, shared_pblock, true, nullptr);

	printf("\nSubmitting newly mined block: %s, BlockTime: %lu, Now: %lu\n", block.GetHash().GetHex().c_str(),
		block.GetBlockTime(), GetTime());

	printf("Ending... Block accepted? %s.\n", success ? "Yes" : "No");
	//MilliSleep(10000);
}

static void my_handler(int s) {
	//printf("Caught signal %d\n", s);
	printf("Shutting down... Please wait...\n", s);

	handler.interrupt = true;
	MilliSleep(100);

	//Shutdown();
	//exit(1);
}

bool hasPeers() {
	if (!g_connman) {
		return false;
	}

	std::vector<CNodeStats> vstats;
	g_connman->GetNodeStats(vstats);

	return !vstats.empty();
}

int main(int argc, char* argv[])
{
	// signal(SIGINT, my_handler);

	boost::thread_group threadGroup;
	CScheduler scheduler;

	gArgs.ParseParameters(argc, argv);

	try
	{
		gArgs.ReadConfigFile(gArgs.GetArg("-conf", BITCOIN_CONF_FILENAME));
		MAX_N_THREADS = gArgs.GetArg("-threads", MAX_N_THREADS);
	}
	catch (const std::exception& e) {
		fprintf(stderr, "Error reading configuration file: %s\n", e.what());
		return false;
	}

	handler.init();
	SelectParams(CBaseChainParams::MAIN);

	InitLogging();
	InitParameterInteraction();
	if (!AppInitBasicSetup())
	{
		// InitError will have been called with detailed error, which ends up on console
		exit(EXIT_FAILURE);
	}
	if (!AppInitParameterInteraction())
	{
		// InitError will have been called with detailed error, which ends up on console
		exit(EXIT_FAILURE);
	}
	if (!AppInitSanityChecks())
	{
		// InitError will have been called with detailed error, which ends up on console
		exit(EXIT_FAILURE);
	}

	if (!AppInitLockDataDirectory())
	{
		// If locking the data directory failed, exit immediately
		exit(EXIT_FAILURE);
	}
	bool fRet = AppInitMain(threadGroup, scheduler);

#ifdef _WIN32
	signal(SIGINT, my_handler);
#else
	struct sigaction satmp;
	sigemptyset(&satmp.sa_mask);
	satmp.sa_flags = 0;
	satmp.sa_handler = my_handler;
	sigaction(SIGTERM, &satmp, NULL);
	sigaction(SIGQUIT, &satmp, NULL);
	if (sigaction(SIGINT, &satmp, NULL) == -1) {
		printf("Could not register SIGINT handler.\n");
	}
#endif

	std::vector<CTransaction> coinbaseTxns;
	CKey coinbaseKey;
	coinbaseKey.MakeNewKey(true);
	//printf("Payment Address: %s\n", coinbaseKey.GetPubKey().GetID().GetHex().c_str());

	// Como converter uma coinbase key em bitcoin address
	//CBitcoinAddress addr(coinbaseKey.GetPubKey().GetID());
#if defined(__aarch32__) || defined(__aarch64__)
	std::cout << std::endl << "You are using BitcoinLE Core ArmV8 Solo Miner Whale 6x Edition (alpha 16.8) " << std::endl;
	std::cout << "https://github.com/rollmeister/bitcoinle-core-armv8" << std::endl;
	std::cout << "It is recommended to sync its blockchain by first running bitcoinled" << std::endl;
	std::cout << "for at least 10 minutes beforehand, if the last sync was done over 6 hours ago..." << std::endl;
	std::cout << "You can also copy over the 'blocks' and 'chainstate' folders of a recently run " << std::endl;
	std::cout << "and fully synced BitcoinLE-qt wallet." << std::endl;
	std::cout << "Delete those two folders inside the solo miner's local work folder (default is '.bitcoinLE')" << std::endl;
	std::cout << "first if you intend to do so." << std::endl;
#endif
	std::cout << "Wallet Count: " << vpwallets.size() << std::endl;
	// CBitcoinAddress addr("JhZGKE8uFDTmCA1gce1wnr4FU9ip7LRe3f");
	// std::string s = addr.ToString();
	// printf("Payment Address: %s\n\n", s.c_str());

	//CScript scriptPubKey = CScript() << ToByteVector(coinbaseKey.GetPubKey().GetHash()) << OP_CHECKSIG;
	std::shared_ptr<CReserveScript> scriptPubKey = std::make_shared<CReserveScript>();
	vpwallets[0]->GetScriptForMining(scriptPubKey);

	wait4Peers();
	wait4Sync();
	
	for (;;)
	{
		try {
			if (handler.interrupt) {
				break;
			}
			std::vector<CMutableTransaction> noTxns;
			CBlock b = CreateAndProcessBlock(noTxns, scriptPubKey->reserveScript);
			if (!b.IsNull()) {
				coinbaseTxns.push_back(*b.vtx[0]);
			}
		}
		catch (...) {
			std::cout << "Exception raised!" << std::endl;
		}
	}

	Interrupt(threadGroup);
	Shutdown();
	return 0;
}
