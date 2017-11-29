#include <NTL/ZZ.h>
#include <vector>
#include <cassert>
#include <algorithm>
#include "SymRLWE/Timer.hpp"

struct PK {
    NTL::ZZ n, n2, g, half_n;
};

struct SK {
    NTL::ZZ lambda, lambda_inv;
};

void gen_key(SK *sk, PK *pk, uint32_t bitlen) {
    if (!sk || !pk)
        return;
    NTL::ZZ p, q;
    NTL::RandomPrime(p, bitlen);
    do {
            NTL::RandomPrime(q, bitlen);
        } while (p == q);

    pk->n = p * q;
    pk->half_n = pk->n >> 1;
    pk->n2 = pk->n * pk->n;
    pk->g = pk->n + 1;

    sk->lambda = (p - 1) * (q - 1) / GCD(p - 1, q - 1);
    sk->lambda_inv = NTL::InvMod(sk->lambda, pk->n);
}

NTL::ZZ& encrypt(NTL::ZZ& ret, PK const&pk, NTL::ZZ const& m) {
    NTL::ZZ r;
    NTL::RandomBnd(r, pk.n);
    NTL::PowerMod(r, r, pk.n, pk.n2);
    NTL::PowerMod(ret, pk.g, m, pk.n2);
    NTL::MulMod(ret, ret, r, pk.n2);
    return ret;
}

NTL::ZZ encrypt(PK const&pk, NTL::ZZ const& m) {
    NTL::ZZ c;
    encrypt(c, pk, m);
    return c;
}

NTL::ZZ decrypt(PK const& pk, SK const& sk, NTL::ZZ ctx) {
    NTL::PowerMod(ctx, ctx, sk.lambda, pk.n2);
    ctx -= 1;
    ctx /= pk.n;
    NTL::MulMod(ctx, ctx, sk.lambda_inv, pk.n);
    if (ctx >= pk.half_n)
        ctx -= pk.n;
    return ctx;
}

NTL::ZZ negate(PK const& pk, NTL::ZZ const& ctx) {
    return NTL::InvMod(ctx, pk.n2);
}

NTL::ZZ add(PK const&pk, NTL::ZZ const& c1, NTL::ZZ const& c2) {
    return NTL::MulMod(c1, c2, pk.n2);
}

NTL::ZZ& add(NTL::ZZ &ret, PK const&pk, NTL::ZZ const& c1, NTL::ZZ const& c2) {
    NTL::MulMod(ret, c1, c2, pk.n2);
    return ret;
}

NTL::ZZ sub(PK const&pk, NTL::ZZ const& c1, NTL::ZZ const& c2) {
    auto tmp = negate(pk, c2);
    return add(pk, c1, tmp);
}

NTL::ZZ add(PK const& pk, NTL::ZZ const& ctx, long plain) {
    auto tmp = encrypt(pk, NTL::to_ZZ(plain));
    return add(pk, ctx, tmp);
}

NTL::ZZ& add(NTL::ZZ &ret, PK const& pk, NTL::ZZ const& ctx, long plain) {
    encrypt(ret, pk, NTL::to_ZZ(plain));
    return add(ret, pk, ctx, ret);
}

NTL::ZZ sub(PK const&pk, NTL::ZZ const& ctx, long plain) {
    auto tmp = encrypt(pk, pk.n - plain);
    return add(pk, ctx, tmp);
}

NTL::ZZ& sub(NTL::ZZ &ret, PK const&pk, NTL::ZZ const& ctx, long plain) {
    encrypt(ret, pk, pk.n - plain);
    return add(ret, pk, ctx, ret);
}

NTL::ZZ multiply(PK const& pk, const NTL::ZZ &ctx, NTL::ZZ const& v) {
    return NTL::PowerMod(ctx, v, pk.n2);
}

NTL::ZZ& multiply(NTL::ZZ &ret, PK const& pk, const NTL::ZZ &ctx, NTL::ZZ const& v) {
    NTL::PowerMod(ret, ctx, v, pk.n2);
    return ret;
}

std::vector<NTL::ZZ> encrypt_bits(PK const& pk, uint32_t m, uint32_t bits) {
    std::vector<NTL::ZZ> ctxs;
    ctxs.reserve(bits);
    for (uint32_t i = 0; i < bits; i++) {
            long bit = m & 1;
            ctxs.emplace_back(encrypt(pk, NTL::to_ZZ(bit)));
            m >>= 1;
        }
    std::reverse(ctxs.begin(), ctxs.end());
    return ctxs;
}

NTL::ZZ XOR(PK const& pk, NTL::ZZ const& enc_x, long y) {
    if (y == 0)
        return add(pk, enc_x, 0);
    else
        return add(pk, negate(pk, enc_x), y);
}

long decrypt_cOT(PK const &pk, SK const& sk,
                                  std::vector<NTL::ZZ> const& mu,
                                                   long s0, long s1) {
    for (auto const&ctx : mu) {
            auto dec = decrypt(pk, sk, ctx);
            if (dec == 1 || dec == -1)
                return NTL::to_long(dec);
        }
    return 0;
}

std::vector<NTL::ZZ> cOT(PK const& pk,
                         std::vector<NTL::ZZ> const& enc_bits,
                         long s0, long s1,
                         uint32_t y,
                         uint32_t bits)
{
    assert(enc_bits.size() == bits);
    auto S0 = NTL::to_ZZ(s0 + s1);
    auto S1 = NTL::to_ZZ(s1 - s0);
    // NTL::ZZ half = NTL::InvMod(NTL::to_ZZ(2), pk.n);
    // auto S1 = NTL::MulMod(NTL::to_ZZ(s1 - s0), half, pk.n);
    // auto S0 = NTL::MulMod(NTL::to_ZZ(s1 + s0), half, pk.n);
    std::vector<NTL::ZZ> d, f, gamma, delta, mu;
    NTL::ZZ tmp;
    for (size_t i = 0; i < enc_bits.size(); i++) {
            long ybit = (y >> (bits - i - 1)) & 1;
            d.emplace_back(sub(pk, enc_bits[i], ybit));
            f.emplace_back(XOR(pk, enc_bits[i], ybit));
            if (i > 0) {
                        multiply(tmp, pk, gamma[i - 1], NTL::to_ZZ(2));
                        add(tmp, pk, tmp, f.at(i));
                        gamma.emplace_back(tmp);
                    } else {
                                gamma.emplace_back(f.at(i));
                            }

            NTL::ZZ r = NTL::RandomBnd(pk.n);
            sub(tmp, pk, gamma.at(i), 1);
            multiply(tmp, pk, tmp, r);
            delta.emplace_back(add(pk, d.at(i), tmp));

            multiply(tmp, pk, delta.at(i), S1);
            mu.emplace_back(add(pk, tmp, S0));
        }
    return mu;
}

long decrypt_GT(PK const &pk, SK const& sk,
                std::vector<NTL::ZZ> const& mu) {
    for (auto const&ctx : mu) {
        auto dec = decrypt(pk, sk, ctx);
        if (dec == 0)
            return 1;
    }
    return 0;
}

std::vector<NTL::ZZ> GT(PK const& pk,
                        std::vector<NTL::ZZ> const& enc_bits,
                        uint32_t y,
                        uint32_t bits)
{
    assert(enc_bits.size() == bits);
    std::vector<NTL::ZZ> z;
    NTL::ZZ tmp, tmp2;
    NTL::ZZ accum = encrypt(pk, NTL::to_ZZ(0));
    NTL::ZZ three = NTL::to_ZZ(3);
    for (size_t i = 0; i < enc_bits.size(); i++) {
        // most significant bit comes first
        long ybit = (y >> (bits - i - 1)) & 1;
        add(tmp, pk, enc_bits[i], 1 - ybit);
        auto xr = XOR(pk, enc_bits[i], ybit);
        multiply(xr, pk, xr, three);
        if (i > 0) {
            add(tmp, pk, tmp, accum);
        }
        add(accum, pk, xr, accum);
        auto r = NTL::RandomBnd(pk.n);
        multiply(tmp, pk, tmp, r);
        z.emplace_back(tmp);
    }
    return z;
}

std::pair<double, double> mean_std(std::vector<double> const& times, long ignore) {
    long sze = times.size();
    double mean = 0.;
    for (long i = ignore; i < sze; i++) {
        mean += times[i];
    }
    mean /= (sze - ignore);
    double std_dev = 0.;
    for (long i = ignore; i < sze; i++) {
        std_dev += (times[i] - mean) * (times[i] - mean);
    }
    std_dev = std::sqrt(std_dev) / (sze - ignore - 1);
    return {mean, std_dev};
}

int main(int argc, char *argv[]) {
    long bits = 512;
    if (argc > 1)
        bits = std::stol(argv[1]);
    SK sk;
    PK pk;
    gen_key(&sk, &pk, bits);
    long s0 = 0;
    long s1 = 1;

    std::vector<double> times[3];
    long WARM_UP = 10;
    long TRAILS = 10;
    long bits_len = 12;

    for (long i = 0; i < WARM_UP + TRAILS; i++) {
        auto start = Clock::now();
        auto enc_x = encrypt_bits(pk, 9, bits_len);
        auto end = Clock::now();
        times[0].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        //auto ret = cOT(pk, enc_x, s0, s1, 10, bits_len);
        auto ret = GT(pk, enc_x, 10, bits_len);
        end = Clock::now();
        times[1].push_back(time_as_millsecond(end - start));

        start = Clock::now();
        //long s = decrypt_cOT(pk, sk, ret, s0, s1);
        long s = decrypt_GT(pk, sk, ret);
        end = Clock::now();
        times[2].push_back(time_as_millsecond(end - start));
    }

    for (auto &ts : times) {
        auto ms = mean_std(ts, WARM_UP);
        std::cout << ms.first << " " << ms.second << std::endl;
    }
    std::cout << std::endl;
    return 1;
}
