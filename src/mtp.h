//
// Created by Zcoin developer
//

#ifndef ZCOIN_MTP_H
#define ZCOIN_MTP_H

#include <openssl/sha.h>

#include "argon2/core.h"
#include "argon2/argon2.h"
#include "argon2/thread.h"
#include "argon2/blake2/blake2.h"
#include "argon2/blake2/blake2-impl.h"
#include "argon2/blake2/blamka-round-opt.h"
#include "uint256.h"

class CBlock;

/* Size of MTP proof */
const unsigned int MTP_PROOF_SIZE = 1431;
/* Size of MTP block proof size */
const unsigned int MTP_BLOCK_PROOF_SIZE = 70;
/* Size of MTP block */
const unsigned int MTP_BLOCK_SIZE = 140;

typedef struct block_mtpProof_ {
    block memory;
    char proof[MTP_PROOF_SIZE];
} block_mtpProof;

typedef struct mtp_Proof_ {
    char proof[MTP_PROOF_SIZE];
} mtp_Proof;



bool mtp_hash(uint256* output, const char* input, uint256 hashTarget, CBlock *pblock);

bool mtp_verifier(uint256 hashTarget, CBlock *pblock, uint256 *yL);

bool mtp_verifier(uint256 hashTarget, uint256 mtpMerkleRoot, unsigned int nNonce,const block_mtpProof blockWithMTPProof[MTP_BLOCK_SIZE], mtp_Proof mtpProof, uint256 *yL);

#endif //ZCOIN_MTP_H
