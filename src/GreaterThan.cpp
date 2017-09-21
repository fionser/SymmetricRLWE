#include "SymRLWE/GreaterThan.hpp"
#include "SymRLWE/Cipher.hpp"
#include "SymRLWE/PrivateKey.hpp"
#include <HElib/FHEContext.h>

static void create_test_v(NTL::ZZX *test_v, 
                          const FHEcontext &context) {

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

/// if greater then returns mu0, else returns mu1
void create_greater_than_args(GreaterThanArgs *args, 
                              long mu0, long mu1, 
                              const FHEcontext &context) {
    if (!args)
        return;
    args->mu0 = mu0;
    args->mu1 = mu1;
    long ptxt_space = context.alMod.getPPowR();
    args->one_half = (NTL::InvMod(2L, ptxt_space) 
                      * (mu0 + mu1)) % ptxt_space;
    create_test_v(&(args->test_v), context);
}

Cipher greater_than(const Cipher &a, long b, 
                    const GreaterThanArgs& args,
                    const FHEcontext &context) {
    NTL::ZZX poly_b;
    encodeOnDegree(&poly_b, -b, context); 
    //!< when b > 0, X^{-b} will bring negative coefficients, so just multiply it with -1
    if (b > 0)
        poly_b *= -1L;
    poly_b *= (args.ngt() - args.one_half);
    //!< poly_b = (mu1 - mu0)/2 * X^{-b} * test_v \mod X^N + 1
    NTL::MulMod(poly_b, poly_b, args.test_v, context.zMStar.getPhimX());

    Cipher result(a);
    result *= poly_b;
    //!< result = (mu1 + mu0)/2 + (mu1 - mu0)/2 * X^{a-b} * test_v 
    result += args.one_half;// TODO(riku) should blind other terms
    return result;
}

NTL::ZZX greater_than(const NTL::ZZX &poly_a, long b, 
                      const GreaterThanArgs& args,
                      const FHEcontext &context) {
    NTL::ZZX poly_b;
    encodeOnDegree(&poly_b, -b, context); 
    //!< when b > 0, X^{-b} will bring negative coefficients, so just multiply it with -1
    if (b > 0)
        poly_b *= -1L;
    poly_b *= (args.ngt() - args.one_half);
    //!< poly_b = (mu1 - mu0)/2 * X^{-b} * test_v \mod X^N + 1
    NTL::MulMod(poly_b, poly_b, args.test_v, context.zMStar.getPhimX());

    auto result(poly_a);
    NTL::MulMod(result, result, poly_b, context.zMStar.getPhimX());
    //!< result = (mu1 + mu0)/2 + (mu1 - mu0)/2 * X^{a-b} * test_v
    NTL::SetCoeff(result, 0, (result[0] + args.one_half) % context.alMod.getPPowR());
    return result;
}

