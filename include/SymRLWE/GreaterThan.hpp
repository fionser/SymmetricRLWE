#ifndef SYM_RLWE_GREATER_THAN_HPP
#define SYM_RLWE_GREATER_THAN_HPP
#include <NTL/ZZX.h>

struct GreaterThanArgs {
    long mu0;
    long mu1;
    long one_half; // (mu0 + mu1) / 2
    NTL::ZZX test_v;
    long gt() const {
        return mu0;
    }
    long ngt() const {
        return mu1;
    }
};

class FHEcontext;
class Cipher;
void create_greater_than_args(GreaterThanArgs *args, 
                              long mu0, long mu1, 
                              const FHEcontext &context);

Cipher greater_than(const Cipher &a, long b, 
                    const GreaterThanArgs& args,
                    const FHEcontext &context);

/// Use for debugging, same logic with the method above.
NTL::ZZX greater_than(const NTL::ZZX &poly_a, long b, 
                      const GreaterThanArgs& args,
                      const FHEcontext &context);
#endif // SYM_RLWE_GREATER_THAN_HPP
