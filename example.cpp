//
// Created by riku on 10/5/17.
//
#include "PrivateGreaterThan/GreaterThan.hpp" // New private greater than
#include "SymRLWE/PrivateKey.hpp"
#include "SymRLWE/Timer.hpp"
#include <HElib/FHE.h>

std::vector<Ctxt> encrypt_group(std::vector<long> const& group,
                                FHEPubKey const& pk) {
    std::vector<Ctxt> ciphers;
    ciphers.reserve(group.size());
    for (long value : group) // i.e., for(size_t i = 0; i < group.size(); i++)
        ciphers.push_back(encrypt_in_degree(value, pk));
    return ciphers;
}

void xor_cipher(Ctxt *cipher) {
    if (!cipher)
        return;
    cipher->negate(); //ctxt = -ctxt;
    cipher->addConstant(NTL::to_ZZ(1)); // then add a 1.
}

std::vector<Ctxt> private_rank(std::vector<Ctxt> const& ciphers,
                               FHEPubKey const& pk) {
    auto context = pk.getContext();
    // return 0 if greater, else reutrn 1.
    GreaterThanArgs gt_args = create_greater_than_args(0L, 1L, context);
    size_t num_ctxts = ciphers.size();
    // Initialize the matrix with empty ciphertexts
    std::vector<std::vector<Ctxt>> cipher_matrix(num_ctxts, std::vector<Ctxt>(num_ctxts, pk));
    for (size_t i = 0; i < num_ctxts; i++) {
        for (size_t j = i + 1; j < num_ctxts; j++) {
            cipher_matrix[i][j] = greater_than(ciphers[i], ciphers[j], gt_args, context);
            // rank[j][i] = 1 - rank[i][j];
            auto copy(cipher_matrix[i][j]);
            xor_cipher(&copy);
            cipher_matrix[j][i] = copy;
        }
    }

    std::vector<Ctxt> sum_of_rows(num_ctxts, pk);
    for (size_t i = 0; i < num_ctxts; i++) {
        for (size_t j = 0; j < num_ctxts; j++) {
            if (i == j)
                continue;
            sum_of_rows[i] += cipher_matrix[i][j];
        }
    }
    return sum_of_rows;
}

int main() {
    const long m = 1024;
    const long p = 1031;
    const long r = 1;
    // plaintext space is p^r. `m` should be power of 2.
    FHEcontext context(m, p, r);
    const long L = 5; // Level. It should work with 5.
    buildModChain(context, L);
    FHESecKey sk(context);
    sk.GenSecKey(64); // Use the default value 64.
    setup_auxiliary_for_greater_than(&sk); // Should call this before doing the greater than.
    const FHEPubKey &pk = sk;
    // Values should not greater than m/2, since we encrypt it into degree of the polynomial.
    std::vector<long> group_a = {4, 5, 1, 3};
    std::vector<long> group_b = {0, 8, 7};

    std::vector<Ctxt> enc_group_a = encrypt_group(group_a, pk);
    std::vector<Ctxt> enc_group_b = encrypt_group(group_b, pk);

    std::vector<Ctxt> merged_group(enc_group_a);
    merged_group.insert(merged_group.end(), enc_group_b.begin(), enc_group_b.end());
    std::vector<Ctxt> rank = private_rank(merged_group, pk);

    Ctxt sum_of_group_a(pk);
    for (size_t i = 0; i < group_a.size(); i++)
        sum_of_group_a += rank[i];
    NTL::ZZX Ua;
    sk.Decrypt(Ua, sum_of_group_a);
    // To check the correctness.
    {
        long N = group_a.size() + group_b.size();
        auto expect_value = ((N - 1) * N) / 2 - Ua[0];
        Ctxt sum_of_group_b(pk);
        for (size_t i = group_a.size(); i < rank.size(); i++)
            sum_of_group_b += rank[i];
        NTL::ZZX Ub;
        sk.Decrypt(Ub, sum_of_group_b);
        if (Ub[0] != expect_value)
            std::cerr << "Warning! private rank might be wrong" << std::endl;
        else
            std::cerr << "private rank is passed" << std::endl;
    }

    return 0;
}
