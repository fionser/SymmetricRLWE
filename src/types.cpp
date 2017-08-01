#include "SymRLWE/types.hpp"
#include "HElib/DoubleCRT.h" 
Polynomial_ptr copy_ptr(Polynomial_ptr a) {
    return std::make_shared<DoubleCRT>(*a);
}
