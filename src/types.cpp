#include "SymRLWE/types.hpp"
#include "HElib/DoubleCRT.h" 
Polynomial_ptr copy_ptr(const Polynomial_ptr a) {
    return std::make_shared<Polynomial>(*a);
}
