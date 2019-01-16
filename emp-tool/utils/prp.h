#include "emp-tool/utils/block.h"
#include "emp-tool/utils/constants.h"
#include "emp-tool/garble/aes.h"
#include <stdio.h>
#ifndef PRP_H__
#define PRP_H__
/** @addtogroup BP
  @{
 */
namespace emp {

class PRP { public:
	AES_KEY aes;

	PRP(const char * seed = nullptr) {
		if (seed == nullptr)
			AES_set_encrypt_key(fix_key, &aes);
		else
			AES_set_encrypt_key(_mm_loadu_si128((block*)seed), &aes);
	}

	PRP(block key) {
		AES_set_encrypt_key(key, &aes);
	}

	void permute_block(block *data, int nblocks) {
		int i = 0;
		for(; i < nblocks-AES_BATCH_SIZE; i+=AES_BATCH_SIZE) {
			AES_ecb_encrypt_blks(data+i, AES_BATCH_SIZE, &aes);
		}
		AES_ecb_encrypt_blks(data+i, (AES_BATCH_SIZE >  nblocks-i) ? nblocks-i:AES_BATCH_SIZE, &aes);
	}

	void permute_data(void*data, int nbytes) {
		permute_block((block *)data, nbytes/16);
		if (nbytes % 16 != 0) {
			uint8_t extra[16];
			memset(extra, 0, 16);
			memcpy(extra, (nbytes/16*16)+(char *) data, nbytes%16);
			permute_block((block*)extra, 1);
			memcpy((nbytes/16*16)+(char *) data, &extra, nbytes%16);
		}
	}
};
}
/**@}*/
#endif// PRP_H__
