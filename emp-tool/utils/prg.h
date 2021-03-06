#ifndef PRG_H__
#define PRG_H__
#include "utils_ec.h"
#include "block.h"
#include "emp-tool/garble/aes.h"
#include "config.h"
//#include <stdio.h>
//#include <stdarg.h>
#include <gmp.h>
#include <random>
#include <mutex>
/** @addtogroup BP
    @{
  */


class PRG {
public:
    enum RandomSource
    {
        Uninitialized = 0,
        OsRandom = 1
    };

    uint64_t counter = 0;
    AES_KEY aes;
    PRG(RandomSource source = Uninitialized)
    {
        reseed(source);
    }

    PRG(const char * seed, int id = 0)
        :PRG(*(block*)seed, id)
    { }

    PRG(block seedBlk, int id = 0)
    {
        reseed(&seedBlk, id);
    }

    void reseed(RandomSource source = OsRandom)
    {
        if (source == OsRandom)
        {
            static PRG rnd(OsRandom);
            static std::mutex _rnd_mtx;
            block seed;

            {
                std::lock_guard<std::mutex> lock(_rnd_mtx);
                if (&rnd == this) {

                    //FILE *fp;
                    //fp = fopen("/dev/urandom", "r");
                    //int r_bytes = 0;
                    //while (r_bytes < 16) {
                    //	int r = fread(&data, 1, 16, fp);
                    //	if (r < 0) exit(1);
                    //	r_bytes += r;
                    //}
                    //fclose(fp);

                    int data[sizeof(block) / sizeof(int)];
                    // this will be "/dev/urandom" when possible...
                    std::random_device rand_div;
                    for (int i = 0; i < sizeof(block) / sizeof(int); ++i)
                        data[i] = rand_div();

                    reseed(data);
                }
                seed = rnd.random_block();
            }

            reseed(&seed);
        }
        else
        {
            aes.rounds = 0;
        }
    }

    void reseed(const void * key, uint64_t id = 0) {
        const char * k = (const char *)key;
        __m128i v = _mm_load_si128((__m128i*)&k[0]);
        v = xorBlocks(v, makeBlock(0LL, id));
        AES_set_encrypt_key(v, &aes);
        counter = 0;
    }

    void random_data(void *data, int nbytes) {
        random_block((block *)data, nbytes / 16);
        if (nbytes % 16 != 0) {
            block extra;
            random_block(&extra, 1);
            memcpy((nbytes / 16 * 16) + (char *)data, &extra, nbytes % 16);
        }
    }
    void random_bool(bool * data, int length) {
        uint8_t * uint_data = (uint8_t*)data;
        random_data(uint_data, length);
        for (int i = 0; i < length; ++i)
            data[i] = uint_data[i] & 1;
    }
    void random_data_unaligned(void *data, int nbytes) {
        block tmp[AES_BATCH_SIZE];
        for (int i = 0; i < nbytes / (AES_BATCH_SIZE * 16); i++) {
            random_block(tmp, AES_BATCH_SIZE);
            memcpy((16 * i*AES_BATCH_SIZE) + (uint8_t*)data, tmp, 16 * AES_BATCH_SIZE);
        }
        if (nbytes % (16 * AES_BATCH_SIZE) != 0) {
            random_block(tmp, AES_BATCH_SIZE);
            memcpy((nbytes / (16 * AES_BATCH_SIZE)*(16 * AES_BATCH_SIZE)) + (uint8_t*)data, tmp, nbytes % (16 * AES_BATCH_SIZE));
        }
    }
    block random_block()
    {
        block b;
        random_block(&b);
        return b;
    }
    void random_block(block * data, int nblocks = 1) {
#if defined(_MSC_VER) | !defined(NDEBUG)
        if (aes.rounds == 0) throw std::runtime_error("unititialized PRG " LOCATION);
#endif // _MSC_VER

        for (int i = 0; i < nblocks; ++i) {
            data[i] = makeBlock(0LL, counter++);
        }
        int i = 0;
        for (; i < nblocks - AES_BATCH_SIZE; i += AES_BATCH_SIZE) {
            AES_ecb_encrypt_blks(data + i, AES_BATCH_SIZE, &aes);
        }
        AES_ecb_encrypt_blks(data + i, (AES_BATCH_SIZE > nblocks - i) ? nblocks - i : AES_BATCH_SIZE, &aes);
    }

    template<typename T, typename ... L>
    void random_bn(T t, L... l) {
        random_bn(l...);
        random_bn(t);
    }

    void random_bn(bn_t a, int sign = BN_POS, int bits = BIT_LEN) {
        int digits;
        SPLIT(bits, digits, bits, BN_DIG_LOG);
        digits += (bits > 0 ? 1 : 0);
        bn_grow(a, digits);
        random_data((uint8_t*)a->dp, digits * sizeof(dig_t));
        a->used = digits;
        a->sign = sign;
        if (bits > 0) {
            dig_t mask = ((dig_t)1 << (dig_t)bits) - 1;
            a->dp[a->used - 1] &= mask;
        }
        bn_trim(a);
    }

    void random_bn(bn_t *a, int length = 1, int sign = BN_POS, int bits = BIT_LEN) {
        for (int i = 0; i < length; ++i)
            random_bn(a[i]);
    }

    template<typename T, typename ... L>
    void random_eb(T t, L... l) {
        random_eb(l...);
        random_eb(t);
    }

    void random_eb(eb_t p) {
        bn_t n, k;
        bn_new(k);
        bn_new(n);
        eb_curve_get_ord(n);
        random_bn(k, BN_POS, bn_bits(n));
        bn_mod(k, k, n);
        eb_mul_gen(p, k);
    }

    void random_eb(eb_t *p, int length = 1) {
        bn_t n, k;
        bn_new(k);
        bn_new(n);
        eb_curve_get_ord(n);
        for (int i = 0; i < length; ++i) {
            random_bn(k, BN_POS, bn_bits(n));
            bn_mod(k, k, n);
            eb_mul_gen(p[i], k);
        }
    }

    void random_mpz(mpz_t out, int nbits) {
        int nbytes = (nbits + 7) / 8;
        uint8_t * data = new uint8_t[nbytes];
        random_data(data, nbytes);
        //int n = nbytes;
        //for(int i = 3; i >= 0; i--) {
        //	data[i] = (unsigned char) (n % (1 << 8));
        //	n /= (1 << 8);
        //}
        //FILE *fp = fmemopen(data, nbytes+16, "rb");
        //
        //int res = mpz_inp_raw(out, fp);
        //assert(res != 0);
        data[0] %= (1 << (nbits % 8));
        mpz_import(out, nbytes, 1, 1, 0, 0, data);
    }
    void random_mpz(mpz_t rop, const mpz_t n) {
        auto size = mpz_sizeinbase(n, 2);
        while (1) {
            random_mpz(rop, (int)size);
            if (mpz_cmp(rop, n) < 0) {
                break;
            }
        }
    }
};
/**@}*/
#endif// PRP_H__
