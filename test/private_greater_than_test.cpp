//
// Created by riku on 10/5/17.
//
#include <gtest/gtest.h>
#include <HElib/FHE.h>

#include "PrivateGreaterThan/GreaterThan.hpp"
#include "SymRLWE/PrivateKey.hpp"
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
    const long M = 1024 << 3;
    const long TRIALS = 100;
    FHEcontext context(M, 1031, 1);
    FHESecKey *secret_key;
    FHEPubKey *public_key;

    class PrivateGreaterThanTest : public ::testing::Test {
    protected:
        static void SetUpTestCase() {
            context.bitsPerLevel -= 5;
            buildModChain(context, 5);
            PRINTF("Security Level %f\n", context.securityLevel());
            PRINTF("m = %ld\n", context.zMStar.getPhiM());
            secret_key = new FHESecKey(context);
            secret_key->GenSecKey(64);
            setup_auxiliary_for_greater_than(secret_key);
            public_key = new FHEPubKey(*secret_key);
        }
        static void TearDownTestCase() {
            delete secret_key;
            delete public_key;
        }
    };

    TEST_F(PrivateGreaterThanTest, Encoding) {
        NTL::ZZX zero_term;
        zero_term.SetLength(phi_N(M));
        NTL::SetCoeff(zero_term, 0, 1);
        {
            NTL::ZZX poly;
            encodeOnDegree(&poly, 0, context);
            ASSERT_EQ(zero_term, poly);
        }

        NTL::ZZX firt_term;
        firt_term.SetLength(phi_N(M));
        NTL::SetCoeff(firt_term, 1, 1);
        {
            NTL::ZZX poly;
            encodeOnDegree(&poly, 1, context);
            ASSERT_EQ(firt_term, poly);
        }

        NTL::ZZX minus_one;
        minus_one.SetLength(phi_N(M));
        NTL::SetCoeff(minus_one, phi_N(M) - 1, 1);
        {
            NTL::ZZX poly;
            encodeOnDegree(&poly, -1, context);
            ASSERT_EQ(minus_one, poly);
        }
    }

    TEST_F(PrivateGreaterThanTest, Arguments) {
        GreaterThanArgs gt_args;
        std::vector<long> primes = {23, 1031};
        std::vector<long> MUs = {12, 516};
        for (size_t i = 0; i < primes.size(); i++) {
            FHEcontext context(M, primes[i], 1);
            gt_args = create_greater_than_args(1L, 0L, context);
            ASSERT_EQ(gt_args.one_half, MUs[i]);
        }
    }

    TEST_F(PrivateGreaterThanTest, NegateDegree) {
        const long phiM = phi_N(M);
        long p = public_key->getPtxtSpace();
        for (long i = 0; i < TRIALS; i++) {
            long v = NTL::RandomBnd(phiM);
            Ctxt ctxt = encrypt_in_degree(v, *public_key);
            smart_negate_degree(&ctxt, context);
            NTL::ZZX dec;
            secret_key->Decrypt(dec, ctxt);
            if (v == 0)
                ASSERT_EQ(1L, NTL::coeff(dec, 0));
            else
                ASSERT_EQ(p - 1L, NTL::coeff(dec, phiM - v));
        }
    }

    TEST_F(PrivateGreaterThanTest, RandomGeneratedValues) {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, context);

        const long phiM = phi_N(M);
        for (long i = 0; i < TRIALS; i++) {
            const long A = NTL::RandomBnd(phiM);
            const long B = NTL::RandomBnd(phiM);

            NTL::ZZX encoded_A, encoded_B;
            encodeOnDegree(&encoded_A, A, context);
            encodeOnDegree(&encoded_B, B, context);

            Ctxt enc_A(*public_key), enc_B(*public_key);
            public_key->Encrypt(enc_A, encoded_A);
            public_key->Encrypt(enc_B, encoded_B);

            Ctxt result = greater_than(enc_A, enc_B, gt_args, context);
            ASSERT_TRUE(result.isCorrect());
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), A > B);
        }
    }

    TEST_F(PrivateGreaterThanTest, RandomGeneratedValues2) {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, context);

        const long phiM = phi_N(M);
        for (long i = 0; i < TRIALS; i++) {
            const long A = NTL::RandomBnd(phiM);
            const long B = NTL::RandomBnd(phiM);

            NTL::ZZX encoded_A;
            encodeOnDegree(&encoded_A, A, context);
            Ctxt enc_A(*public_key);
            public_key->Encrypt(enc_A, encoded_A);

            Ctxt result = greater_than(enc_A, B, gt_args, context);
            ASSERT_TRUE(result.isCorrect());
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), A > B);
        }
    }

    TEST_F(PrivateGreaterThanTest, BoundaryCondition) {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, context);
        long minimum = 0;
        long maximum = phi_N(M) - 1;
        long other;
        do {
            other = NTL::RandomBnd(maximum);
        } while (other == minimum or other == maximum);
        Ctxt enc_minimum = encrypt_in_degree(minimum, *public_key);
        Ctxt enc_maximum = encrypt_in_degree(maximum, *public_key);
        Ctxt enc_other = encrypt_in_degree(other, *public_key);

        std::vector<long> plains = {maximum, minimum, other};
        std::vector<Ctxt> ciphers = {enc_maximum, enc_minimum, enc_other};

        for (size_t i = 0; i < 3; i++) {
            Ctxt result = greater_than(enc_maximum, ciphers.at(i), gt_args, context);
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), maximum > plains.at(i));
        }

        for (size_t i = 0; i < 3; i++) {
            Ctxt result = greater_than(enc_minimum, ciphers.at(i), gt_args, context);
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), minimum > plains.at(i));
        }
    }

    TEST_F(PrivateGreaterThanTest, BoundaryCondition2) {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, context);
        long minimum = 0;
        long maximum = phi_N(M) - 1;
        long other;
        do {
            other = NTL::RandomBnd(maximum);
        } while (other == minimum or other == maximum);
        Ctxt enc_minimum = encrypt_in_degree(minimum, *public_key);
        Ctxt enc_maximum = encrypt_in_degree(maximum, *public_key);
        Ctxt enc_other = encrypt_in_degree(other, *public_key);

        std::vector<long> plains = {maximum, minimum, other};
        std::vector<Ctxt> ciphers = {enc_maximum, enc_minimum, enc_other};

        for (size_t i = 0; i < 3; i++) {
            Ctxt result = greater_than(enc_maximum, plains.at(i), gt_args, context);
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            EXPECT_EQ(dec[0] == gt_args.gt(), maximum > plains.at(i));
        }

        for (size_t i = 0; i < 3; i++) {
            Ctxt result = greater_than(enc_minimum, plains.at(i), gt_args, context);
            NTL::ZZX dec;
            secret_key->Decrypt(dec, result);
            EXPECT_EQ(dec[0] == gt_args.gt(), minimum > plains.at(i));
        }
    }

    TEST_F(PrivateGreaterThanTest, EqualityTest) {
        const long maximum = phi_N(M) - 1;
        for (size_t i = 0; i < TRIALS; i++) {
            long v = NTL::RandomBnd(maximum);
            long u = NTL::RandomBnd(maximum);
            if (i & 1)
                u = v;

            Ctxt enc_v = encrypt_in_degree(v, *public_key);
            Ctxt enc_u = encrypt_in_degree(u, *public_key);

            Ctxt result1 = equality_test(enc_v, enc_u, context, false);
            Ctxt result2 = equality_test(enc_u, enc_v, context, false);

            NTL::ZZX dec1, dec2;
            secret_key->Decrypt(dec1, result1);
            secret_key->Decrypt(dec2, result2);
            long coeff1 = NTL::to_long(NTL::coeff(dec1, 0));
            long coeff2 = NTL::to_long(NTL::coeff(dec2, 0));
            ASSERT_EQ(coeff1, coeff2);
            ASSERT_EQ(coeff1, v == u ? 0L : 1L);
        }
    }

    TEST_F(PrivateGreaterThanTest, CountLessThan) {
        const long maximum = phi_N(M) - 1;
        long a = NTL::RandomBnd(maximum);
        Ctxt ctx_a = encrypt_in_degree(a, *public_key);
        
        std::vector<long> b_vec(TRIALS * TRIALS);
        std::vector<Ctxt> ctx_b_vec;
        ctx_b_vec.reserve(b_vec.size());
        long ground_true = 0;
        for (size_t i = 0; i < b_vec.size(); i++) {
            b_vec[i] = NTL::RandomBnd(maximum);
            ctx_b_vec.emplace_back(encrypt_in_degree(b_vec[i], *public_key));
            ground_true += a > b_vec[i] ? 1 : 0;
        }

        Ctxt res = count_less_than(ctx_a, ctx_b_vec, context);
        NTL::ZZX dec;
        secret_key->Decrypt(dec, res);
        long coeff = NTL::to_long(NTL::coeff(dec, 0));
        ground_true %= context.alMod.getPPowR();
        EXPECT_EQ(ground_true, coeff);
    }
}
