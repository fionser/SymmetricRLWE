#ifndef SYM_RLWE_CIPHER_HPP
#define SYM_RLWE_CIPHER_HPP
#include "SymRLWE/types.hpp"
namespace NTL { class ZZX; }
class PrivateKey;
class Cipher {
public:
    Cipher();
   
    Cipher(const Cipher &oth);

    Cipher& operator=(const Cipher &oth) const = delete;

    Cipher& operator*=(const NTL::ZZX &v);

    Cipher& operator+=(const long v);

    Cipher& operator+=(const Cipher &oth);

    Cipher& power(const long k);

    ~Cipher();
    /// PrivateKey instance get access set_cipher method for encryption.
    friend class PrivateKey;

protected:
    void set_cipher(Polynomial_ptr a, Polynomial_ptr b) {
        this->a = a;
        this->b = b;
    }

    Polynomial_ptr get_a() const {
        return a;
    }

    Polynomial_ptr get_b() const {
        return b;
    }
private:
    Polynomial_ptr a, b;
};

#endif // SYM_RLWE_CIPHER_HPP
