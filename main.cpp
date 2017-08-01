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

int main() {
    FHEcontext context(2048, 11, 1);
    buildModChain(context, 5);
    PrivateKey sk(context);
    const long a = 4;
    Cipher cipher;
    sk.EncryptOnDegree(&cipher, a);

    const long b = 5;
    NTL::ZZX Xb;
    encodeOnDegree(&Xb, -b, context);
    NTL::ZZX testv;
    create_test_v(&testv, context);    

    const long ptxtSpace = context.alMod.getPPowR();
    const long mu0 = 0, mu1 = 1;
    long one_half = NTL::InvMod(2L, ptxtSpace); 
    one_half *= (mu1 + mu0); // one_half = (mu0 + mu1) / 2
    long mu_dash = mu0 - one_half;
    testv *= mu_dash;

    //!< Xb = Xb * testv \mod PhiM(X)
    NTL::MulMod(Xb, Xb, testv, context.zMStar.getPhimX());
    //!< cipher = X^{a-b} * testv + one_half
    cipher *= Xb; 
    cipher += one_half;

    NTL::ZZX dec;
    sk.Decrypt(&dec, cipher);
    std::cout << dec << "\n";
    return 0;
}
