//
// Created by riku on 10/4/17.
//

#include "PrivateGreaterThan/GreaterThan.hpp"
#include <HElib/FHE.h>
// from SymRLWE
extern void encodeOnDegree(NTL::ZZX *poly, long degree, const FHEcontext &context);
/// F(X^a) --> F(X^{-a}) then apply the keyswtiching.
static void smart_negate_degree(Ctxt *ctx, FHEcontext const& context) {
    if (!ctx)
        return;
    long M = context.zMStar.getM();
    ctx->smartAutomorph(M - 1);
}
/// Create a testing vector: 1 + X + X^2 + ... + X^{N-1}.
/// N = phiN(M).
static NTL::ZZX create_test_v(FHEcontext const& context) {
    NTL::ZZX test_v;
    long m = context.zMStar.getM();
    long phiM = phi_N(m);
    if (phiM != (m >> 1))
        std::cerr << "WARNING! m should be power of 2" << std::endl;
    test_v.SetLength(phiM);
    for (long i = 0; i < phiM; i++)
        NTL::SetCoeff(test_v, i, 1);
    return test_v;
}

void setup_auxiliary_for_greater_than(FHESecKey *sk) {
    if (!sk)
        return;
    long m = sk->getContext().zMStar.getM();
    /// We use F(X) --> F(X^{m - 1}) automorph when doing the private greater than.
    sk->GenKeySWmatrix(1, m - 1, 0, 0);
    sk->setKeySwitchMap();
}
/// Privately comparing two encrypted values (in a proper form).
/// The return value is determined by GreaterThanArgs.
Ctxt greater_than(Ctxt const& ctx_a, Ctxt const& ctx_b,
                  GreaterThanArgs const& args,
                  FHEcontext const& context) {
    Ctxt b_copy(ctx_b);
    smart_negate_degree(&b_copy, context); // X^{-b}
    b_copy.multiplyBy(ctx_a); // X^a * X^{-b}

    b_copy.multByConstant((args.mu1 - args.one_half) * args.test_v);
    b_copy.addConstant(NTL::to_ZZ(args.one_half));
    return b_copy;
}
/// If greater then returns mu_0, else returns mu_1.
Ctxt greater_than(Ctxt const& ctx_a, Ctxt const& ctx_b, FHEcontext const& context) {
    GreaterThanArgs args = create_greater_than_args(0L, 1L, context);
    return greater_than(ctx_a, ctx_b, args, context);
}

GreaterThanArgs create_greater_than_args(long mu0, long mu1,
                                         FHEcontext const& context) {
    if (context.zMStar.getPhiM() != (context.zMStar.getM() >> 1))
        std::cerr << "Warning! the parameter m should be power of 2.";
    GreaterThanArgs args;
    args.mu0 = mu0;
    args.mu1 = mu1;
    long ptxt_space = context.alMod.getPPowR();
    args.one_half = (NTL::InvMod(2L, ptxt_space) * (mu0 + mu1)) % ptxt_space;
    args.test_v = create_test_v(context);
    return args;
}

Ctxt encrypt_in_degree(long value, FHEPubKey const& pk) {
    Ctxt cipher(pk);
    FHEcontext const& context = pk.getContext();
    NTL::ZZX poly;
    encodeOnDegree(&poly, value, context);
    pk.Encrypt(cipher, poly);
    return cipher;
}
