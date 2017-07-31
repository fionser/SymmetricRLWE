#include <HElib/FHE.h>
#include <HElib/DoubleCRT.h>
#include <HElib/FHEContext.h>

#include <memory>
typedef std::shared_ptr<DoubleCRT> Polynomial_ptr;

Polynomial_ptr copy_poly_ptr(Polynomial_ptr a) {
    return std::make_shared<DoubleCRT>(*a);
}

class SymmetricPrivateKey;
class Cipher {
public:
    Cipher() {}
   
    Cipher(const Cipher &oth) {
        a = copy_poly_ptr(oth.a);
        b = copy_poly_ptr(oth.b);
    }

    Cipher& operator=(const Cipher &oth) const = delete;

    ~Cipher() {} 
    
    friend class SymmetricPrivateKey;

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

class SymmetricPrivateKey {
public:
    SymmetricPrivateKey(const FHEcontext &context) : context(context) {
        private_s = std::make_shared<DoubleCRT>(context);
        private_s->sampleHWt(64);
        ptxtSpace = context.alMod.getPPowR();
    }
    
    ~SymmetricPrivateKey() {
    }

    void Encrypt(Cipher *cipher, const NTL::ZZX &message) const {
        if (!cipher)
            return;
        auto a = std::make_shared<DoubleCRT>(context);
        auto b = std::make_shared<DoubleCRT>(context);
        RLWE(*a, *b, *private_s, NTL::to_long(ptxtSpace));
        (*a) += message;
        cipher->set_cipher(a, b); 
    }

    void Decrypt(NTL::ZZX *message, const Cipher &cipher) const {
        if (!message)
            return;
        DoubleCRT b(*cipher.get_b()); 
        b *= (*private_s);
        b += (*cipher.get_a());

        b.toPoly(*message);
        PolyRed(*message, ptxtSpace, true/*reduce to [0,p-1]*/);
    }
private:
    const FHEcontext &context;
    NTL::ZZ ptxtSpace;
    Polynomial_ptr private_s;
};


int main() {
    FHEcontext context(2048, 11, 1);
    buildModChain(context, 5);
    SymmetricPrivateKey sk(context);
    Cipher cipher;
    NTL::ZZX poly;
    poly.SetLength(10);
    for (long i = 0; i < 10; i++)
        poly[i] = i + 1;
    sk.Encrypt(&cipher, poly);
    NTL::ZZX dec;
    sk.Decrypt(&dec, cipher);
    std::cout << dec << "\n";
    return 0;
}
