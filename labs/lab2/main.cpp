#include <windows.h>
#include <iostream>
#include <array>
#include <vector>
#include <cstring>
#include <stdexcept>
#include <gmpxx.h>
#include <random>
#include <chrono>

using BigInt = mpz_class;

// =====================================================================
// УПРОЩЕННАЯ ХЕШ-ФУНКЦИЯ (вместо SHA-256 для демонстрации)
// =====================================================================
namespace SimpleHash {
    // Простая хеш-функция для демонстрации (не криптографическая!)
    void hash(const uint8_t* data, size_t len, uint8_t* out, size_t out_len) {
        uint32_t h = 0x12345678;
        for (size_t i = 0; i < len; ++i) {
            h = h * 31 + data[i];
        }
        for (size_t i = 0; i < out_len; ++i) {
            out[i] = (uint8_t)((h >> (i % 4) * 8) & 0xFF);
        }
    }
}

// =====================================================================
// МОДУЛЬ 1: Теория чисел
// =====================================================================
namespace MathModule {

    BigInt ext_gcd(const BigInt &a, const BigInt &b, BigInt &x, BigInt &y) {
        if (b == 0) { x = 1; y = 0; return a; }
        BigInt x1, y1;
        BigInt d = ext_gcd(b, a % b, x1, y1);
        x = y1;
        y = x1 - (a / b) * y1;
        return d;
    }

    BigInt mod_inverse(const BigInt &a, const BigInt &m) {
        BigInt x, y;
        BigInt g = ext_gcd(a, m, x, y);
        if (g != 1) throw std::runtime_error("Inverse doesn't exist");
        BigInt result = x % m;
        if (result < 0) result = result + m;
        return result;
    }

    BigInt mod_pow(const BigInt &base, const BigInt &exp, const BigInt &mod) {
        BigInt result;
        mpz_powm(result.get_mpz_t(), base.get_mpz_t(), exp.get_mpz_t(), mod.get_mpz_t());
        return result;
    }

    BigInt gcd_func(const BigInt &a, const BigInt &b) {
        BigInt result;
        mpz_gcd(result.get_mpz_t(), a.get_mpz_t(), b.get_mpz_t());
        return result;
    }

    BigInt lcm_func(const BigInt &a, const BigInt &b) {
        BigInt g = gcd_func(a, b);
        BigInt a_div_g = a / g;
        return a_div_g * b;
    }

    struct PublicKey { BigInt n, e; };
    struct PrivateKey { BigInt d, p, q, dp, dq, qinv; };

    std::pair<PublicKey, PrivateKey> generate_keys() {
        BigInt p = 61;
        BigInt q = 53;
        BigInt n = p * q;
        BigInt e = 17;

        BigInt p1 = p - 1;
        BigInt q1 = q - 1;
        BigInt lambda_n = lcm_func(p1, q1);
        BigInt d = mod_inverse(e, lambda_n);

        BigInt dp = d % p1;
        BigInt dq = d % q1;
        BigInt qinv = mod_inverse(q, p);

        return {{n, e}, {d, p, q, dp, dq, qinv}};
    }
}

// =====================================================================
// МОДУЛЬ 2: RSA с CRT
// =====================================================================
namespace RSACore {
    using namespace MathModule;

    BigInt encrypt(const BigInt &m, const PublicKey &pk) {
        return mod_pow(m, pk.e, pk.n);
    }

    BigInt decrypt_crt(const BigInt &c, const PrivateKey &sk) {
        BigInt m1 = mod_pow(c, sk.dp, sk.p);
        BigInt m2 = mod_pow(c, sk.dq, sk.q);

        BigInt diff = m1 - m2;
        if (diff < 0) diff = diff + sk.p;
        BigInt h = (sk.qinv * diff) % sk.p;

        return m2 + h * sk.q;
    }
}

// =====================================================================
// МОДУЛЬ 3: УПРОЩЕННЫЙ OAEP с Constant-Time защитой (Вариант 5)
// =====================================================================
namespace OAEPScheme {
    const size_t K = 8;           // длина модуля в байтах (для N=3233 нужно 2, но для демо берем 8)
    const size_t HLEN = 2;        // длина хеша в байтах
    const size_t MAX_MSG_LEN = K - 2 * HLEN - 2;  // 8 - 4 - 2 = 2 байта

    void mgf1(const uint8_t* seed, size_t seed_len, uint8_t* mask, size_t mask_len) {
        size_t counter = 0;
        size_t out_idx = 0;
        
        while (out_idx < mask_len) {
            uint8_t buffer[64];
            size_t buf_len = seed_len;
            std::memcpy(buffer, seed, seed_len);
            buffer[buf_len++] = (uint8_t)((counter >> 24) & 0xFF);
            buffer[buf_len++] = (uint8_t)((counter >> 16) & 0xFF);
            buffer[buf_len++] = (uint8_t)((counter >> 8) & 0xFF);
            buffer[buf_len++] = (uint8_t)(counter & 0xFF);
            
            uint8_t hash[HLEN];
            SimpleHash::hash(buffer, buf_len, hash, HLEN);
            
            size_t to_copy = (HLEN < (mask_len - out_idx)) ? HLEN : (mask_len - out_idx);
            std::memcpy(mask + out_idx, hash, to_copy);
            
            out_idx += to_copy;
            counter++;
        }
    }

    void rand_bytes(uint8_t* buf, size_t len) {
        static std::mt19937_64 rng(
            std::chrono::steady_clock::now().time_since_epoch().count());
        for (size_t i = 0; i < len; ++i)
            buf[i] = (uint8_t)(rng() & 0xFF);
    }

    void pad(const uint8_t* msg, size_t msg_len, uint8_t* em) {
        std::cout << "  [pad] Начало padding, msg_len=" << msg_len << "\n"; std::cout.flush();
        
        if (msg_len > MAX_MSG_LEN) throw std::runtime_error("Message too long");

        uint8_t lHash[HLEN];
        SimpleHash::hash(nullptr, 0, lHash, HLEN);
        std::cout << "  [pad] lHash вычислен\n"; std::cout.flush();

        uint8_t db[K - HLEN - 1];
        std::memset(db, 0, sizeof(db));
        std::memcpy(db, lHash, HLEN);

        size_t ps_len = (K - HLEN - 1) - HLEN - msg_len - 1;
        size_t sep_pos = HLEN + ps_len;
        db[sep_pos] = 0x01;
        std::memcpy(db + sep_pos + 1, msg, msg_len);
        std::cout << "  [pad] DB сформирован\n"; std::cout.flush();

        uint8_t seed[HLEN];
        rand_bytes(seed, HLEN);
        std::cout << "  [pad] Seed сгенерирован\n"; std::cout.flush();

        uint8_t dbMask[K - HLEN - 1];
        mgf1(seed, HLEN, dbMask, K - HLEN - 1);
        std::cout << "  [pad] dbMask вычислен\n"; std::cout.flush();

        uint8_t maskedDB[K - HLEN - 1];
        for (size_t i = 0; i < K - HLEN - 1; ++i)
            maskedDB[i] = db[i] ^ dbMask[i];
        std::cout << "  [pad] maskedDB вычислен\n"; std::cout.flush();

        uint8_t seedMask[HLEN];
        mgf1(maskedDB, K - HLEN - 1, seedMask, HLEN);
        std::cout << "  [pad] seedMask вычислен\n"; std::cout.flush();

        uint8_t maskedSeed[HLEN];
        for (size_t i = 0; i < HLEN; ++i)
            maskedSeed[i] = seed[i] ^ seedMask[i];
        std::cout << "  [pad] maskedSeed вычислен\n"; std::cout.flush();

        em[0] = 0x00;
        std::memcpy(em + 1, maskedSeed, HLEN);
        std::memcpy(em + 1 + HLEN, maskedDB, K - HLEN - 1);
        std::cout << "  [pad] EM сформирован\n"; std::cout.flush();
    }

    bool unpad(const uint8_t* em, const uint8_t* expected_lhash, uint8_t* msg, size_t &msg_len) {
        uint8_t error_mask = 0;
        error_mask |= (em[0] != 0x00);

        uint8_t maskedSeed[HLEN];
        std::memcpy(maskedSeed, em + 1, HLEN);

        uint8_t maskedDB[K - HLEN - 1];
        std::memcpy(maskedDB, em + 1 + HLEN, K - HLEN - 1);

        uint8_t seedMask[HLEN];
        mgf1(maskedDB, K - HLEN - 1, seedMask, HLEN);

        uint8_t seed[HLEN];
        for (size_t i = 0; i < HLEN; ++i)
            seed[i] = maskedSeed[i] ^ seedMask[i];

        uint8_t dbMask[K - HLEN - 1];
        mgf1(seed, HLEN, dbMask, K - HLEN - 1);

        uint8_t db[K - HLEN - 1];
        for (size_t i = 0; i < K - HLEN - 1; ++i)
            db[i] = maskedDB[i] ^ dbMask[i];

        // ЗАДАНИЕ ВАРИАНТА 5: XOR-аккумулятор для безусловного сравнения lHash
        uint8_t lhash_diff = 0;
        for (size_t i = 0; i < HLEN; ++i)
            lhash_diff |= (db[i] ^ expected_lhash[i]);
        if (lhash_diff != 0) error_mask |= 1;

        size_t sep_idx = 0;
        uint8_t found_sep = 0;
        for (size_t i = HLEN; i < K - HLEN - 1; ++i) {
            uint8_t is_sep = (db[i] == 0x01) ? 1 : 0;
            uint8_t is_zero = (db[i] == 0x00) ? 1 : 0;
            if (!found_sep && is_sep) sep_idx = i;
            found_sep |= is_sep;
            if (!found_sep && !is_zero && !is_sep) error_mask |= 1;
        }
        if (!found_sep) error_mask |= 1;

        size_t extracted_len = (K - HLEN - 1) - sep_idx - 1;
        if (extracted_len > MAX_MSG_LEN) { error_mask |= 1; extracted_len = 0; }

        uint8_t success = (error_mask == 0) ? 0xFF : 0x00;
        for (size_t i = 0; i < MAX_MSG_LEN; ++i) {
            if (i < extracted_len) msg[i] = db[sep_idx + 1 + i] & success;
            else msg[i] = 0x00;
        }
        msg_len = (error_mask == 0) ? extracted_len : 0;

        return (error_mask == 0);
    }
}

// =====================================================================
// Утилиты
// =====================================================================
void bytes_to_bigint(const uint8_t* bytes, size_t len, BigInt &out) {
    out = 0;
    for (size_t i = 0; i < len; ++i)
        out = (out << 8) + bytes[i];
}

void bigint_to_bytes(const BigInt &in, uint8_t* bytes, size_t len) {
    BigInt temp = in;
    for (int i = (int)len - 1; i >= 0; --i) {
        BigInt masked = temp & 0xFF;
        long val = masked.get_si();
        bytes[i] = (uint8_t)val;
        temp >>= 8;
    }
}

// =====================================================================
// MAIN
// =====================================================================
int main() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    try {
        std::cout << "--- RSA OAEP (Variant 5: XOR lHash) ---\n";
        std::cout.flush();

        std::cout << "[1/6] Генерация ключей...\n"; std::cout.flush();
        auto keys = MathModule::generate_keys();
        MathModule::PublicKey pk = keys.first;
        MathModule::PrivateKey sk = keys.second;
        std::cout << "  Ключи сгенерированы: N=" << pk.n << ", e=" << pk.e << "\n"; std::cout.flush();

        std::string plaintext_str = "Hi";
        std::vector<uint8_t> msg(plaintext_str.begin(), plaintext_str.end());
        std::cout << "[2/6] Сообщение: \"" << plaintext_str << "\" (" << msg.size() << " байт)\n"; std::cout.flush();

        std::cout << "[3/6] OAEP padding...\n"; std::cout.flush();
        uint8_t em[OAEPScheme::K];
        OAEPScheme::pad(msg.data(), msg.size(), em);
        std::cout << "  Padding завершен\n"; std::cout.flush();

        BigInt m_int, c_int;
        bytes_to_bigint(em, OAEPScheme::K, m_int);
        std::cout << "[4/6] Шифрование... m=" << m_int << "\n"; std::cout.flush();
        c_int = RSACore::encrypt(m_int, pk);
        std::cout << "  Шифротекст c=" << c_int << "\n"; std::cout.flush();

        std::cout << "[5/6] Расшифрование CRT...\n"; std::cout.flush();
        BigInt m_dec_int = RSACore::decrypt_crt(c_int, sk);
        std::cout << "  Расшифровано m'=" << m_dec_int << "\n"; std::cout.flush();

        uint8_t em_dec[OAEPScheme::K];
        bigint_to_bytes(m_dec_int, em_dec, OAEPScheme::K);

        uint8_t expected_lhash[OAEPScheme::HLEN];
        SimpleHash::hash(nullptr, 0, expected_lhash, OAEPScheme::HLEN);

        uint8_t recovered_msg[OAEPScheme::MAX_MSG_LEN];
        size_t recovered_len = 0;

        std::cout << "[6/6] Деинкапсуляция OAEP (XOR lHash)...\n"; std::cout.flush();
        bool success = OAEPScheme::unpad(em_dec, expected_lhash, recovered_msg, recovered_len);

        if (success) {
            std::string recovered(recovered_msg, recovered_msg + recovered_len);
            std::cout << "Decrypted: \"" << recovered << "\"\n";
        } else {
            std::cout << "Decryption failed (Padding error).\n";
        }

    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << "\n";
    }
    return 0;
}