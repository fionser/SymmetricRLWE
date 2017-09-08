#ifndef SYM_RLWE_TYPES_HPP
#define SYM_RLWE_TYPES_HPP
#include <memory>
class DoubleCRT;
typedef DoubleCRT Polynomial;
typedef std::shared_ptr<Polynomial> Polynomial_ptr;
Polynomial_ptr copy_ptr(const Polynomial_ptr a);
#endif //SYM_RLWE_TYPES_HPP
