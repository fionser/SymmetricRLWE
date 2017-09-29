#include <gtest/gtest.h>
#include <HElib/FHE.h>
#include <HElib/FHEContext.h>

#include "SymRLWE/Cipher.hpp"
#include "SymRLWE/PrivateKey.hpp"
#include "SymRLWE/types.hpp"
#include "SymRLWE/GreaterThan.hpp"
namespace testing
{
 namespace internal
 {
   enum GTestColor {
         COLOR_DEFAULT,
         COLOR_RED,
         COLOR_GREEN,
         COLOR_YELLOW
     };
 
   extern void ColoredPrintf(GTestColor color, const char* fmt, ...);
  }
}

#define PRINTF(...)  \
    do { \
        testing::internal::ColoredPrintf(testing::internal::COLOR_GREEN, "[          ] "); \
        testing::internal::ColoredPrintf(testing::internal::COLOR_YELLOW, __VA_ARGS__); } \
    while(0)

namespace {
    const long M = 8192;
    const long level = 4;
    const long prime = 1031;
    FHEcontext context(M, prime, 1);
    PrivateKey *key = nullptr;
    enum CipherNum {
        _100 = 0,
        _200 = 1,
        _400 = 2,
        _800 = 3,
        _1600 = 4,
        NUM = 5
    };
    std::vector<Cipher> ciphers[CipherNum::NUM];

    class GreaterThanBenchmark : public ::testing::Test {
    protected:
        static void SetUpTestCase() {
            buildModChain(context, level);
            key = new PrivateKey(context);
            PRINTF("Security Level: %f\n", context.securityLevel());
        }
        static void TearDownTestCase() {
            delete key;
        }
    };

    TEST_F(GreaterThanBenchmark, Encryption100) {
        const long phiM = phi_N(M);
        ciphers[CipherNum::_100].resize(100);
        for (int i = 0; i < 100; i++) {
            long value = NTL::RandomBnd(phiM);
            key->EncryptOnDegree(&(ciphers[CipherNum::_100].at(i)), value);
        }
    }    

    TEST_F(GreaterThanBenchmark, Encryption200) {
        const long phiM = phi_N(M);
        ciphers[CipherNum::_200].resize(200);
        for (int i = 0; i < 200; i++) {
            long value = NTL::RandomBnd(phiM);
            key->EncryptOnDegree(&(ciphers[CipherNum::_200].at(i)), value);
        }
    }

    TEST_F(GreaterThanBenchmark, Encryption400) {
        const long phiM = phi_N(M);
        ciphers[CipherNum::_400].resize(400);
        for (int i = 0; i < 400; i++) {
            long value = NTL::RandomBnd(phiM);
            key->EncryptOnDegree(&(ciphers[CipherNum::_400].at(i)), value);
        }
    }

    TEST_F(GreaterThanBenchmark, Encryption800) {
        const long phiM = phi_N(M);
        ciphers[CipherNum::_800].resize(800);
        for (int i = 0; i < 800; i++) {
            long value = NTL::RandomBnd(phiM);
            key->EncryptOnDegree(&(ciphers[CipherNum::_800].at(i)), value);
        }
    }

    TEST_F(GreaterThanBenchmark, Encryption1600) {
        const long phiM = phi_N(M);
        ciphers[CipherNum::_1600].resize(1600);
        for (int i = 0; i < 1600; i++) {
            long value = NTL::RandomBnd(phiM);
            key->EncryptOnDegree(&(ciphers[CipherNum::_1600].at(i)), value);
        }
    }

}
