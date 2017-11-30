#include <HElib/FHE.h>
#include <HElib/FHEContext.h>

#include "PrivateGreaterThan/GreaterThan.hpp"
#include "SymRLWE/PrivateKey.hpp"
#include <SymRLWE/Timer.hpp>
#include <set>
class TTP {
public:
    static std::vector<long> feature;
    static std::vector<long> DT;
    static std::vector<long> rnds;
    static std::vector<long> indices;
    static std::set<long> set;
    static long evaluate() {
        long r = 0;
        for (size_t i = 0; i < indices.size(); i++) {
            long idx = indices[i];
            if (feature.at(idx) > DT.at(i))
                r += rnds[i];
        }
        return r;
    }

    static void sum_randoms(long root, long weight, long p) {
        if (root > 1022) {
            if (set.find(weight) != set.end())
                std::cerr << weight << " duplicated\n";
            else
                set.insert(weight);
        } else {
            long next = (weight + rnds.at(root)) % p;
            sum_randoms(root * 2 + 1, next, p);
            sum_randoms(root * 2 + 2, weight, p);
        }
    }
};
std::vector<long> TTP::feature;
std::vector<long> TTP::DT;
std::vector<long> TTP::rnds;
std::vector<long> TTP::indices;
std::set<long> TTP::set;

void random(std::vector<long> &features, long p) {
    for (auto &f : features) {
        do {
             f = NTL::RandomBnd(p);
        } while (f == 0);
    }
}

std::vector<Ctxt> receive_from_client(FHESecKey const&sk, 
                                      FHEPubKey const&evk,
                                      long d) {
    FHEcontext const& context = sk.getContext();
    std::vector<long> feature(d);
    random(feature, context.zMStar.getPhiM());
    std::vector<Ctxt> ctxs(d, evk);
    for (long i = 0; i < d; i++) {
        encrypt_in_degree(ctxs[i], feature[i], sk);
    }
    TTP::feature = feature;
    return ctxs;
}

Ctxt perform_DT(std::vector<long> const& tree,
                std::vector<Ctxt> const& features,
                FHEPubKey const& evk) {
    long d = features.size();
    long M = tree.size();
    FHEcontext const& context = evk.getContext();
    long p = context.alMod.getPPowR();
    std::vector<long> rnds(M);
    random(rnds, p);
    Ctxt sum(evk);
    std::vector<long> indices(M);
    for (long i = 0; i < M; i++) {
        // Ctxt enc_b = encrypt_in_degree(tree[i], evk);
        /// randomly chose one index
        long idx = NTL::RandomBnd(d);
        auto gt_args = create_greater_than_args(rnds[i], 0, context);
        Ctxt gt = greater_than(features.at(idx), tree.at(i), gt_args, context);
        if (!gt.isCorrect())
            std::cout << "greater than might fail" << std::endl;
        sum += gt;
        indices.at(i) = idx;
    }
    TTP::rnds = rnds;
    TTP::DT = tree;
    TTP::indices = indices;
    return sum;
}

std::pair<double, double> mean_std(const std::vector<double> &times, long ignore_first) {
    double sum = 0.;
    long cnt = 0;
    for (size_t i = ignore_first; i < times.size(); i++) {
        sum += times[i];
        cnt += 1;
    }
    double mean = sum / cnt;

    double sd = 0.;
    for (size_t i = ignore_first; i < times.size(); i++) {
        sd += (times[i] - mean) * (times[i] - mean);
    }
    sd = std::sqrt(sd) / (cnt - 1);
    return {mean, sd};
}

int main(int argc, char *argv[]) {
    long m = 1024 << 3;
    long p = NTL::RandomPrime_long(14, 20);
    long r = 1;
    FHEcontext context(m, p, r);
    // context.bitsPerLevel = 14 + std::ceil(std::log(m)/2 + r* std::log(p));
    // std::cout << context.bitsPerLevel << std::endl;
    context.bitsPerLevel += 1;
    buildModChain(context, 3);
    std::cout << context.securityLevel() << std::endl;
    
    FHESecKey sk(context);
    sk.GenSecKey(64);
    setup_auxiliary_for_greater_than(&sk);
    const FHEPubKey& evk(sk);
    /// TODO(riku): symmetric version
    //evk.makeSymmetric();
    std::vector<double> encryption;
    std::vector<double> evaluation;
    std::vector<double> decryption;
    // for (long M : {100, 200, 300, 400, 500, 600, 700, 800, 900}) {
        long M = 1023; // number of internal nodes
        long d = 16;
        // for (long _i = 0; _i < 60; _i++) {
            auto start = Clock::now();
            std::vector<Ctxt> feature = receive_from_client(sk, evk, d);
            auto end = Clock::now();
            encryption.push_back(time_as_millsecond(end - start));

            start = Clock::now();
            std::vector<long> DT(M);
            random(DT, context.zMStar.getPhiM());
            Ctxt result = perform_DT(DT, feature, evk);
            result.modDownToLevel(1);
            end = Clock::now();
            evaluation.push_back(time_as_millsecond(end - start));

            start = Clock::now();
            NTL::ZZX dec;
            if (!result.isCorrect())
                std::cout << "decryption might fail" << std::endl;
            sk.Decrypt(dec, result);
            auto ground = TTP::evaluate() % context.alMod.getPPowR();
            if (NTL::coeff(dec, 0) != ground) {
                std::cerr << "seem wrong! add more levels" << std::endl;
                std::cerr << NTL::coeff(dec, 0)  << "!=" << ground << std::endl;
            }
            end = Clock::now();
            decryption.push_back(time_as_millsecond(end - start));
        // }
        // std::cout << M << " " << d << " ";
        // auto ms = mean_std(encryption, 10);
        // std::cout << ms.first << " \\pm " << ms.second << " ";
        // ms = mean_std(evaluation, 10);
        // std::cout << ms.first << " \\pm " << ms.second << " ";
        // ms = mean_std(decryption, 10);
        // std::cout << ms.first << " \\pm " << ms.second << "\n";
    // }
    TTP::sum_randoms(0, 0, context.alMod.getPPowR());
    return 0;
}


