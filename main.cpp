#include "SymRLWE/Cipher.hpp"
#include "SymRLWE/PrivateKey.hpp"
#include "SymRLWE/types.hpp"
#include <HElib/FHE.h>
#include <HElib/FHEContext.h>

void create_test_v(NTL::ZZX *test_v, const FHEcontext &context) {
    if (!test_v)
        return;
    long m = context.zMStar.getM();
    long phiM = phi_N(m);
    if (phiM != (m >> 1)) 
        std::cerr << "WARNING! m should be power of 2" << std::endl;
    test_v->SetLength(phiM);
    for (long i = 0; i < phiM; i++)
        NTL::SetCoeff(*test_v, i, 1);
}

void encrypt_features(std::vector<Cipher> *ciphers, 
                      const std::vector<long> &features,
                      const PrivateKey &key) {
    if (!ciphers)
        return;
    ciphers->resize(features.size());
    for (size_t i = 0; i < features.size(); i++)
        key.EncryptOnDegree(&(ciphers->at(i)), features.at(i));
}

struct GreaterThanArgs {
    long mu0;
    long mu1;
    long one_half; // (mu0 + mu1) / 2
};

/// if greater then returns mu0, else returns mu1
void create_greater_than_args(GreaterThanArgs *args, 
                              long mu0, long mu1, const FHEcontext &context) {
    if (!args)
        return;
    args->mu0 = mu0;
    args->mu1 = mu1;
    long ptxt_space = context.alMod.getPPowR();
    args->one_half = (NTL::InvMod(2L, ptxt_space) * (mu0 + mu1)) % ptxt_space;
}

Cipher greater_than(const Cipher &a, long b, 
                    const GreaterThanArgs& args,
                    const NTL::ZZX &test_v,
                    const FHEcontext &context) {
    NTL::ZZX poly_b;
    encodeOnDegree(&poly_b, -b, context); 
    //!< when b > 0, X^{-b} will bring negative coefficients, so just multiply it with -1
    if (b > 0)
        poly_b *= -1L;
    poly_b *= (args.mu1 - args.one_half);
    //!< poly_b = (mu1 - mu0)/2 * X^{-b} * test_v \mod X^N + 1
    NTL::MulMod(poly_b, poly_b, test_v, context.zMStar.getPhimX());
    
    Cipher result(a);
    result *= poly_b;
    //!< result = (mu1 + mu0)/2 + (mu1 - mu0)/2 * X^{a-b} * test_v 
    result += args.one_half;// TODO(riku) should blind other terms
    return result;
}

Cipher decision_tree(const std::vector<Cipher> &features,
                     const std::vector<long> &tree,
                     const FHEcontext &context) {
    assert(tree.size() == features.size());
    NTL::ZZX testv;
    create_test_v(&testv, context);
    GreaterThanArgs gt_args;
    //!< if greater return 1, else return 0
    create_greater_than_args(&gt_args, 1L, 0L, context);

    Cipher result = greater_than(features[0], tree[0], gt_args, testv, context);
    for (size_t i = 1; i < features.size(); i++) {
        Cipher tmp = greater_than(features[i], tree[i], gt_args, testv, context);
        result += tmp;
    }
    return result;
}

void test_decision_tree(const PrivateKey &key, const FHEcontext &context) {
    long N = 10;
    std::vector<long> features(N);
    for (long i = 0; i < N; i++)
        features[i] = i + 1;
    std::vector<Cipher> enc_features;
    encrypt_features(&enc_features, features, key);

    std::vector<long> tree(N);
    for (long i = 0; i < N; i++)
        tree[i] = i;

    NTL::ZZX dec;
    Cipher result = decision_tree(enc_features, tree, context);
    key.Decrypt(&dec, result);
    std::cout << dec[0] << "\n";
}

void any_power(Cipher *ctx, long k, const FHEcontext &context) {
    long m = context.zMStar.getM();
    k = mcMod(k, m);
    long g = context.zMStar.ZmStarGen(0);
    long val = PowerMod(g, k, m);
    std::cout << k << " " << val << " " << context.zMStar.inZmStar(val) << "\n";
}

void test_inner_product(const PrivateKey &key, const FHEcontext &context) {
    long N = 10;
    std::vector<long> features(N);
    for (long i = 0; i < N; i++)
        features[i] = i + 1;
    std::vector<Cipher> enc_features;
    encrypt_features(&enc_features, features, key);

    std::vector<long> vec(N);
    for (long i = 0; i < N; i++)
        any_power(nullptr, i, context);
        //vec[i] = i;
}

void test_power(const PrivateKey &key, const FHEcontext &context) {
    Cipher cipher;
    key.EncryptOnDegree(&cipher, 0);
    long m = context.zMStar.getM();
    long g = context.zMStar.ZmStarGen(0);
    for (long k = 0; k < m; k++) {
        long val = PowerMod(g, k, m);
        Cipher tmp(cipher);
        tmp.power(val);
        NTL::ZZX poly;
        key.Decrypt(&poly, tmp);
        std::cout << k << " " << val << " " << poly << "\n";
    }
}

int main() {
    FHEcontext context(32, 1031, 1);
    buildModChain(context, 4);
    std::cout << context.securityLevel() << "\n";
    PrivateKey sk(context);
    // test_power(sk, context); 
    test_decision_tree(sk, context);
    return 0;
}
