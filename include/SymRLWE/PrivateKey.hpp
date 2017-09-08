#ifndef SYM_RLWE_PRIVATE_KEY_HPP
#define SYM_RLWE_PRIVATE_KEY_HPP
#include "SymRLWE/types.hpp"
#include <NTL/ZZ.h>
class FHEcontext;
class Cipher;
namespace NTL { class ZZX; }
void encodeOnDegree(NTL::ZZX *poly, long degree, const FHEcontext &context);

class PrivateKey {
public:
    PrivateKey(const FHEcontext &context);
    
    PrivateKey(const PrivateKey &oth);

    PrivateKey& operator=(const PrivateKey &oth) = delete;

    ~PrivateKey();

    const FHEcontext& getContext() const;
    /// Lift the s(X) to s^k(X).
    void power(long k);

    void Encrypt(Cipher *cipher, const NTL::ZZX &message) const;

    void EncryptOnDegree(Cipher *cipher, long degree) const;

    void Decrypt(NTL::ZZX *message, const Cipher &cipher) const;

private:
    const FHEcontext &context;
    NTL::ZZ ptxtSpace;
    Polynomial_ptr private_s;
};

#endif // SYM_RLWE_PRIVATE_KEY_HPP
