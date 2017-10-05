//
// Created by riku on 10/5/17.
//
#include <gtest/gtest.h>
#include <HElib/FHE.h>

#include "PrivateGreaterThan/GreaterThan.hpp"
#include "SymRLWE/PrivateKey.hpp"

namespace {
    const long M = 1024;
    FHEcontext context(M, 1031, 1);
    FHESecKey *secret_key;
    FHEPubKey *public_key;

    class PrivateGreaterThanTest : public ::testing::Test {
    protected:
        static void SetUpTestCase() {
            buildModChain(context, 5);
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

    TEST_F(PrivateGreaterThanTest, RandomGeneratedValues) {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(0L, 1L, context);

        const long numTrials = 100;
        const long phiM = phi_N(M);
        for (long i = 0; i < numTrials; i++) {
            const long A = NTL::RandomBnd(phiM);
            const long B = NTL::RandomBnd(phiM);

            NTL::ZZX encoded_A, encoded_B;
            encodeOnDegree(&encoded_A, A, context);
            encodeOnDegree(&encoded_B, B, context);

            Ctxt enc_A(*public_key), enc_B(*public_key);
            public_key->Encrypt(enc_A, encoded_A);
            public_key->Encrypt(enc_B, encoded_B);

            Ctxt result = greater_than(enc_A, enc_B, gt_args, context);
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
}
