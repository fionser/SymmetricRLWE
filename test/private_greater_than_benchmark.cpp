//
// Created by riku on 10/5/17.
//
#include <gtest/gtest.h>
#include <HElib/FHE.h>
#include <HElib/Ctxt.h>

#include "PrivateGreaterThan/GreaterThan.hpp"
#include "SymRLWE/Timer.hpp"
#include <vector>
#include <iostream>
class PrivateGreaterThanBench {
public:
    const long M = 1024 << 4;
    const long TRIALS;
    const long prime = 1031;
    FHESecKey *secret_key;
    FHEPubKey *public_key;
    FHEcontext *context;
    std::vector<Ctxt> enc_a, enc_b, result;
    std::vector<long> plain_a, plain_b;

    PrivateGreaterThanBench(long TRIALS) : TRIALS(TRIALS) {
        context = new FHEcontext(M, prime, 1);
        if (M > 9000) // 120-bit security
            context->bitsPerLevel = 14 + std::ceil(std::log(M)/2 + std::log(prime));
        else // 80-bit security
            context->bitsPerLevel -= 5;
        buildModChain(*context, 5);
        printf("Security Level %f\n", context->securityLevel());
        secret_key = new FHESecKey(*context);
        secret_key->GenSecKey(64);
        setup_auxiliary_for_greater_than(secret_key);
        public_key = new FHEPubKey(*secret_key);
        enc_a.resize(TRIALS, *secret_key);
        enc_b.resize(TRIALS, *secret_key);
        result.resize(TRIALS, *secret_key);

        plain_a.resize(TRIALS);
        plain_b.resize(TRIALS);
    }

    ~PrivateGreaterThanBench() {
        delete secret_key;
        delete public_key;
        delete context;
    }

    void BenchEncryption() {
        const long phiM = phi_N(M);
        for (long i = 0; i < TRIALS; i++) {
            const long A = NTL::RandomBnd(phiM);
            const long B = NTL::RandomBnd(phiM);
            encrypt_in_degree(enc_a[i], A, *secret_key);
            encrypt_in_degree(enc_b[i], B, *secret_key);
            plain_a[i] = A;
            plain_b[i] = B;
        }
    }

    void BenchDecryption() {
        NTL::ZZX poly;
        auto gt_args = create_greater_than_args(1L, 0L, *context);
        for (long i = 0; i < TRIALS; i++) {
            secret_key->Decrypt(poly, result[i]);
            bool compute = poly[0] == gt_args.gt();
            bool ground = plain_a[i] > plain_b[i];
            if (compute != ground)
                std::cerr << "Error " << plain_a[i] << "," << plain_b[i] << std::endl;
        }
    }

    void ComparisonTwoCiphertexts() {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, *context);
        const long phiM = phi_N(M);
        for (long i = 0; i < TRIALS; i++) {
            result[i] = greater_than(enc_a[i], enc_b[i], gt_args, *context);
        }
    }

    void ComparisonOneCiphertext() {
        GreaterThanArgs gt_args;
        gt_args = create_greater_than_args(1L, 0L, *context);
        const long phiM = phi_N(M);
        for (long i = 0; i < TRIALS; i++) {
            result[i] = greater_than(enc_a[i], plain_b[i], gt_args, *context);
        }
    }

};

std::pair<double, double> mean_std(std::vector<double> const& times, long ignore) {
    long sze = times.size();
    double mean = 0.;
    for (long i = ignore; i < sze; i++) {
        mean += times[i];
    }
    mean /= (sze - ignore);
    double std_dev = 0.;
    for (long i = ignore; i < sze; i++) {
        std_dev += (times[i] - mean) * (times[i] - mean);
    }
    std_dev = std::sqrt(std_dev) / (sze - ignore - 1);
    return {mean, std_dev};
}

int main(int argc, char *argv[]) {
    PrivateGreaterThanBench bench(1);
    std::vector<double> times[4];
    long WARM_UP = 50;
    long TRAILS = 1000;
    for (long i = 0; i < WARM_UP + TRAILS; i++) {
        auto start = Clock::now();
        bench.BenchEncryption();
        auto end = Clock::now();
        double enc_time = time_as_millsecond(end - start);
        times[0].push_back(enc_time);

        start = Clock::now();
        bench.ComparisonTwoCiphertexts();
        end = Clock::now();
        double eval_time = time_as_millsecond(end - start);
        times[1].push_back(eval_time);

        start = Clock::now();
        bench.ComparisonOneCiphertext();
        end = Clock::now();
        double eval_one_cipher_time = time_as_millsecond(end - start);
        times[2].push_back(eval_one_cipher_time);

        start = Clock::now();
        bench.BenchDecryption();
        end = Clock::now();
        double dec_time = time_as_millsecond(end - start);
        times[3].push_back(dec_time);
    }

    for (auto &ts : times) {
        auto ms = mean_std(ts, WARM_UP);
        std::cout << ms.first << " " << ms.second << std::endl;
    }
    std::cout << std::endl;
    return 0;
}
