#ifndef PRIVATE_GREATER_THAN_GREATER_THAN_HPP
#define PRIVATE_GREATER_THAN_GREATER_THAN_HPP
#include <NTL/ZZX.h>

/// Arguments for private greater than.
/// Return mu0 if greater, otherwise return mu1
struct GreaterThanArgs {
    long mu0;
    long mu1;
    long one_half; // (mu0 + mu1) / 2
    NTL::ZZX test_v; // a polynomial in the form of 1 + X + X^2 + ...
    long gt() const {
        return mu0;
    }
    long ngt() const {
        return mu1;
    }
};

class FHEcontext; // From HElib
class FHESecKey; // From HElib
class Ctxt; // From HElib
/// Create a GreaterThanArgs for the private greater than.
/// Return (a cipher of) mu0 if the A > B, otherwise return mu1.
GreaterThanArgs create_greater_than_args(long mu0, long mu1, FHEcontext const& context);
/// This method should be called before calling the private greater than.
void setup_auxiliary_for_greater_than(FHESecKey *sk);
/// Privately comparing two encrypted values (in a proper form).
/// The return value is determined by GreaterThanArgs.
Ctxt greater_than(Ctxt const&a, Ctxt const &b, GreaterThanArgs const& args, FHEcontext const& context);
/// Privately comparing two encrypted values (in a proper form).
/// Return a cipher that encrypts 0 if the value of ctx_a is greater than the value of ctx_b.
/// Otherwise, return a cipher that encrypts 1.
Ctxt greater_than(Ctxt const& ctx_a, Ctxt const& ctx_b, FHEcontext const& context);
#endif // PRIVATE_GREATER_THAN_GREATER_THAN_HPP
