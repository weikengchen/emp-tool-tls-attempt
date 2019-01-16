#ifndef PRIVACY_FREE_GEN_H__
#define PRIVACY_FREE_GEN_H__
#include "emp-tool/io/io_channel.h"
#include "emp-tool/io/net_io_channel.h"
#include "emp-tool/utils/block.h"
#include "emp-tool/utils/utils.h"
#include "emp-tool/utils/crh.h"
#include "emp-tool/utils/hash.h"
#include "emp-tool/execution/circuit_execution.h"
#include "emp-tool/garble/garble_gate_privacy_free.h"
#include <iostream>
namespace emp {
template<typename T>
class PrivacyFreeGen: public CircuitExecution{ 
public:
	block delta;
	CRH crh;
	T * io;
	block constant[2];
	int64_t gid = 0;
	PrivacyFreeGen(T * io) :io(io) {
		PRG tmp;
		block a;
		tmp.random_block(&a, 1);
		set_delta(a);
	}
	bool is_public(const block & b, int party) {
		return false;
	}
	bool isDelta(const block & b) {
		return cmp_blocks(&b, &delta, 1);
	}
	void set_delta(const block &_delta) {
		this->delta = make_delta(_delta);
		PRG prg2(fix_key);prg2.random_block(constant, 2);
		*((char *) &constant[0]) &= 0xfe;
		*((char *) &constant[1]) |= 0x01;
		constant[1] = xor_block(constant[1], delta);
	}
	block public_label(bool b) {
		return constant[b];
	}
	block and_gate(const block& a, const block& b) {
		block out[2], table[2];
		garble_gate_garble_privacy_free(a, xor_block(a,delta), b, xor_block(b,delta), 
				&out[0], &out[1], delta, table, gid++, &crh.aes);
		io->send_block(table, 1);
		return out[0];
	}
	block xor_gate(const block&a, const block& b) {
		return xor_block(a, b);
	}
	block not_gate(const block& a) {
		return gen_xor(a, public_label(true));
	}
	void privacy_free_to_xor(const block* new_b0,const block * b0, const block * b1, int length){
		block h[2];
		for(int i = 0; i < length; ++i) {
			h[0] = crh.H(b0[i], i);
			h[1] = crh.H(b1[i], i);
			h[0] = xor_block(new_b0[i], h[0]);	
			h[1] = xor_block(new_b0[i], h[1]);	
			h[1] = xor_block(delta, h[1]);
			io->send_block(h, 2);
		}
	}
};
}
#endif// PRIVACY_FREE_GEN_H__
