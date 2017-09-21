#include <gtest/gtest.h>
#include <HElib/FHE.h>
#include <HElib/FHEContext.h>

#include "SymRLWE/Cipher.hpp"
#include "SymRLWE/PrivateKey.hpp"
#include "SymRLWE/types.hpp"
#include "SymRLWE/GreaterThan.hpp"

namespace {
    const long M = 32;
    FHEcontext context(M, 1031, 1);
    PrivateKey *key;

    class GreaterThanTest : public ::testing::Test {
    protected:
        static void SetUpTestCase() {
            buildModChain(context, 4);
            key = new PrivateKey(context);
        }
        static void TearDownTestCase() {
            delete key;
        }
    };

    TEST_F(GreaterThanTest, Encoding) {
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

    TEST_F(GreaterThanTest, Arguments) {
        GreaterThanArgs gt_args;
        std::vector<long> primes = {23, 1031};
        std::vector<long> MUs = {12, 516};
        for (size_t i = 0; i < primes.size(); i++) {
            FHEcontext context(M, primes[i], 1);
            create_greater_than_args(&gt_args, 1L, 0L, context);
            ASSERT_EQ(gt_args.one_half, MUs[i]);
        }
    }

    TEST_F(GreaterThanTest, RandomGeneratedValuesOnPlain) {
        const long numTrials = 100;
        std::vector<long> As(numTrials), Bs(numTrials);
        const long phiM = phi_N(M);
        for (long i = 0; i < numTrials; i++) {
            As[i] = NTL::RandomBnd(phiM);
            Bs[i] = NTL::RandomBnd(phiM);
        }

        GreaterThanArgs gt_args;
        create_greater_than_args(&gt_args, 1L, 0L, context);

        for (size_t i = 0; i < As.size(); i++) {
            NTL::ZZX poly_a;
            encodeOnDegree(&poly_a, As[i], context);
            NTL::ZZX result = greater_than(poly_a, Bs[i], gt_args, context);
            ASSERT_EQ(result[0] == gt_args.gt(), (As[i] > Bs[i]));
        }
    }

    TEST_F(GreaterThanTest, RandomGeneratedValues) {
        const long numTrials = 100;
        std::vector<long> As(numTrials), Bs(numTrials);
        const long phiM = phi_N(M);
        for (long i = 0; i < numTrials; i++) {
            As[i] = NTL::RandomBnd(phiM);
            Bs[i] = NTL::RandomBnd(phiM);
        }

        GreaterThanArgs gt_args;
        create_greater_than_args(&gt_args, 1L, 0L, context);

        for (size_t i = 0; i < As.size(); i++) {
            Cipher enc_a;
            key->EncryptOnDegree(&enc_a, As[i]);
            Cipher result = greater_than(enc_a, Bs[i], gt_args, context);
            NTL::ZZX dec;
            key->Decrypt(&dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), (As[i] > Bs[i]));
        }
    }

    TEST_F(GreaterThanTest, BoundaryCondition) {
        GreaterThanArgs gt_args;
        create_greater_than_args(&gt_args, 1L, 0L, context);
        long minimum = 0;
        long maximum = phi_N(M) - 1;
        Cipher enc_minimum;
        key->EncryptOnDegree(&enc_minimum, minimum);

        Cipher enc_maximum;
        key->EncryptOnDegree(&enc_maximum, maximum);

        long other; 
        do {
            other = NTL::RandomBnd(maximum);
        } while (other == minimum or other == maximum);
        Cipher enc_other;
        key->EncryptOnDegree(&enc_other, other);

        NTL::ZZX dec;
        for (long v : {minimum, other, maximum}) {
             Cipher result = greater_than(enc_minimum, v, gt_args, context);
             key->Decrypt(&dec, result);
             ASSERT_EQ(dec[0] == gt_args.gt(), minimum > v);
        }

        for (long v : {minimum, other, maximum}) {
             Cipher result = greater_than(enc_maximum, v, gt_args, context);
             key->Decrypt(&dec, result);
             ASSERT_EQ(dec[0] == gt_args.gt(), maximum > v);
        }

        for (long v : {other - 2, other + 2}) {
            Cipher result = greater_than(enc_other, v, gt_args, context);
            key->Decrypt(&dec, result);
            ASSERT_EQ(dec[0] == gt_args.gt(), other > v);
        }
    }
}
