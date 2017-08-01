#include "SymRLWE/PrivateKey.hpp"
#include "SymRLWE/Cipher.hpp"
#include <HElib/FHEContext.h>
#include <HElib/NumbTh.h>
#include <HElib/DoubleCRT.h>
#include <HElib/FHE.h>
#include <NTL/ZZX.h>
PrivateKey::PrivateKey(const FHEcontext &context) 
    : context(context) {
        private_s = std::make_shared<DoubleCRT>(context);
        private_s->sampleHWt(64);
        ptxtSpace = context.alMod.getPPowR();
    }

PrivateKey::~PrivateKey() {}

const FHEcontext& PrivateKey::getContext() const {
    return context;
}

void PrivateKey::power(long k) {
    private_s->automorph(k);
}

void PrivateKey::Encrypt(Cipher *cipher, const NTL::ZZX &message) const {
    if (!cipher)
        return;
    auto a = std::make_shared<DoubleCRT>(context);
    auto b = std::make_shared<DoubleCRT>(context);
    RLWE(*a, *b, *private_s, NTL::to_long(ptxtSpace));
    (*a) += message;
    cipher->set_cipher(a, b); 
}

void PrivateKey::EncryptOnDegree(Cipher *cipher, long degree) const {
    if (!cipher)
        return;
    NTL::ZZX poly;
    encodeOnDegree(&poly, degree, context); 
    Encrypt(cipher, poly);
}

void PrivateKey::Decrypt(NTL::ZZX *message, const Cipher &cipher) const {
    if (!message)
        return;
    DoubleCRT b(*cipher.get_b()); 
    b *= (*private_s);
    b += (*cipher.get_a());

    b.toPoly(*message);
    PolyRed(*message, ptxtSpace, false/*reduce to [-p/2,p/2]*/);
}

void encodeOnDegree(NTL::ZZX *poly, long degree, const FHEcontext &context) {
    if (!poly)
        return;
    long m = context.zMStar.getM();
    long phiM = phi_N(m);
    poly->SetLength(phiM);
    while (degree < 0) 
        degree += phiM;
    degree %= phiM; 
    NTL::SetCoeff(*poly, degree, 1);
}

