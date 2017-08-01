#ifndef SYM_RLWE_TYPES_HPP
#define SYM_RLWE_TYPES_HPP
#include <memory>
class DoubleCRT;
typedef std::shared_ptr<DoubleCRT> Polynomial_ptr;
Polynomial_ptr copy_ptr(Polynomial_ptr a);
#endif //SYM_RLWE_TYPES_HPP
