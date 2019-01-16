#include "emp-tool/utils/prp.h"
#include <stdio.h>
#ifndef TCCRH_H__
#define TCCRH_H__
/** @addtogroup BP
  @{
 */
namespace emp {

class TCCRH: public PRP { public:
	block H(block in, uint64_t i) {
		permute_block(&in, 1);
		block t = xor_block(in, make_block(0, i));
		permute_block(&t, 1);
		return xor_block(t, in);
	}

#ifdef __GNUC__
	#ifndef __clang__
		#pragma GCC push_options
		#pragma GCC optimize ("unroll-loops")
	#endif
#endif

	template<int n>
	void H(block out[n], block in[n], uint64_t id) {
		block tmp[n];
		for(int i = 0; i < n; ++i)
			tmp[i] = in[i];
		permute_block(tmp, n);
		for(int i = 0; i < n; ++i) {
			out[i] = xor_block(tmp[i], make_block(0, id));
			++id;
		}
		permute_block(out, n);
		xor_blocks(out, tmp, out, n);
	}

#ifdef __GNUC__
	#ifndef __clang__
		#pragma GCC pop_options
	#endif
#endif


	void Hn(block*out, block* in, uint64_t id, int length, block * scratch = nullptr) {
		bool del = false;
		if(scratch == nullptr) {
			del = true;
			scratch = new block[length];
		} 
		for(int i = 0; i < length; ++i)
			scratch[i] = in[i];
		permute_block(scratch, length);
		for(int i = 0; i < length; ++i) {
			out[i] = xor_block(scratch[i], make_block(0, id));
			++id;
		}
		permute_block(out, length);
		xor_blocks(out, scratch, out, length);

		if(del) {
			delete[] scratch;
			scratch = nullptr;
		}
	}

};
}
/**@}*/
#endif// TCCRH_H__
