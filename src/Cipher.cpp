#include <NTL/ZZX.h>
#include <HElib/DoubleCRT.h>

#include "SymRLWE/Cipher.hpp"
Cipher::Cipher() {}

Cipher::Cipher(const Cipher &oth) {
    a = copy_ptr(oth.a);
    b = copy_ptr(oth.b);
}

Cipher& Cipher::operator*=(const NTL::ZZX &v) {
    (*a) *= v;
    (*b) *= v;
    return *this;
}

Cipher& Cipher::operator+=(const long v) {
    (*b) += v;
    return *this;
}

Cipher& Cipher::power(const long k) {
    a->automorph(k);
    b->automorph(k);
    return *this;
}

Cipher::~Cipher() {} 

