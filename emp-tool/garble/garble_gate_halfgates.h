#ifndef LIBGARBLE_GARBLE_GATE_HALFGATES_H
#define LIBGARBLE_GARBLE_GATE_HALFGATES_H

#include "emp-tool/utils/aes.h"
#include <string.h>
namespace emp {

inline void garble_gate_eval_halfgates(block A, block B, 
		block *out, const block *table, uint64_t idx, const AES_KEY *key) {
	block HA, HB, W;
	bool sa, sb;
	block tweak1, tweak2;

	sa = getLSB_block(A);
	sb = getLSB_block(B);

	tweak1 = make_block(2 * idx,  0);
	tweak2 = make_block(2 * idx + 1, 0);

	{
		block keys[2];
		block masks[2];

		keys[0] = xor_block(ortho_block(A), tweak1);
		keys[1] = xor_block(ortho_block(B), tweak2);
		masks[0] = keys[0];
		masks[1] = keys[1];
		AES_ecb_encrypt_blks(keys, 2, key);
		HA = xor_block(keys[0], masks[0]);
		HB = xor_block(keys[1], masks[1]);
	}

	W = xor_block(HA, HB);
	if (sa)
		W = xor_block(W, table[0]);
	if (sb) {
		W = xor_block(W, table[1]);
		W = xor_block(W, A);
	}
	*out = W;
}

inline void garble_gate_garble_halfgates(block LA0, block A1, block LB0, block B1, block *out0, block *out1, block delta, block *table, uint64_t idx, const AES_KEY *key) {
	bool pa = getLSB_block(LA0);
	bool pb = getLSB_block(LB0);
	block tweak1, tweak2;
	block HLA0, HA1, HLB0, HB1;
	block tmp, W0;

	tweak1 = make_block(2 * idx,  0);
	tweak2 = make_block(2 * idx + 1, 0);

	{
		block masks[4], keys[4];

		keys[0] = xor_block(ortho_block(LA0), tweak1);
		keys[1] = xor_block(ortho_block(A1), tweak1);
		keys[2] = xor_block(ortho_block(LB0), tweak2);
		keys[3] = xor_block(ortho_block(B1), tweak2);
		memcpy(masks, keys, sizeof keys);
		AES_ecb_encrypt_blks(keys, 4, key);
		HLA0 = xor_block(keys[0], masks[0]);
		HA1 = xor_block(keys[1], masks[1]);
		HLB0 = xor_block(keys[2], masks[2]);
		HB1 = xor_block(keys[3], masks[3]);
	}

	table[0] = xor_block(HLA0, HA1);
	if (pb)
		table[0] = xor_block(table[0], delta);
	W0 = HLA0;
	if (pa)
		W0 = xor_block(W0, table[0]);
	tmp = xor_block(HLB0, HB1);
	table[1] = xor_block(tmp, LA0);
	W0 = xor_block(W0, HLB0);
	if (pb)
		W0 = xor_block(W0, tmp);

	*out0 = W0;
	*out1 = xor_block(*out0, delta);
}
}
#endif
