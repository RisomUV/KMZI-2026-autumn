#include <iostream>
#include <string>
#include <gmpxx.h>
#include <ctime>
#include <iomanip>
#include <windows.h>

// ============================================================================
// Вспомогательные функции для работы с Hex и GMP
// ============================================================================
mpz_class hex_to_mpi(const std::string& hex) {
    mpz_class res;
    mpz_set_str(res.get_mpz_t(), hex.c_str(), 16);
    return res;
}

std::string mpi_to_hex(const mpz_class& num) {
    if (num == 0) return "0";
    char* str = mpz_get_str(nullptr, 16, num.get_mpz_t());
    std::string res(str);
    free(str);
    return res;
}

// Безопасный модуль (всегда возвращает положительное число)
mpz_class safe_mod(const mpz_class& a, const mpz_class& m) {
    mpz_class res = a % m;
    if (res < 0) res += m;
    return res;
}

// Модульная инверсия
mpz_class mod_inv(const mpz_class& a, const mpz_class& m) {
    mpz_class res;
    if (mpz_invert(res.get_mpz_t(), a.get_mpz_t(), m.get_mpz_t()) == 0) {
        throw std::runtime_error("Inverse does not exist");
    }
    return res;
}

// ============================================================================
// МОДУЛЬ 1: Алгебра эллиптических кривых (Аффинные координаты)
// ============================================================================
namespace EC_Algebra {
    struct CurveParams {
        mpz_class p, a, b, q;
        struct Point {
            mpz_class x, y;
            bool infinity;
            Point() : infinity(true) {}
            Point(mpz_class _x, mpz_class _y) : x(_x), y(_y), infinity(false) {}
        } G;
    };

    // Сложение двух точек в аффинных координатах
    CurveParams::Point point_add(const CurveParams::Point& P, const CurveParams::Point& Q, const CurveParams& curve) {
        if (P.infinity) return Q;
        if (Q.infinity) return P;

        if (P.x == Q.x) {
            if (safe_mod(P.y + Q.y, curve.p) == 0) {
                return CurveParams::Point(); // Точка на бесконечности
            }
            // Удвоение точки (P == Q)
            mpz_class s = safe_mod((3 * P.x * P.x + curve.a) * mod_inv(2 * P.y, curve.p), curve.p);
            mpz_class x3 = safe_mod(s * s - 2 * P.x, curve.p);
            mpz_class y3 = safe_mod(s * (P.x - x3) - P.y, curve.p);
            return CurveParams::Point(x3, y3);
        } else {
            // Сложение различных точек
            mpz_class s = safe_mod((Q.y - P.y) * mod_inv(Q.x - P.x, curve.p), curve.p);
            mpz_class x3 = safe_mod(s * s - P.x - Q.x, curve.p);
            mpz_class y3 = safe_mod(s * (P.x - x3) - P.y, curve.p);
            return CurveParams::Point(x3, y3);
        }
    }

    // Базовое скалярное умножение (Double-and-Add)
    CurveParams::Point basic_multiply(const mpz_class& k, const CurveParams::Point& P, const CurveParams& curve) {
        CurveParams::Point R; // Infinity
        CurveParams::Point addend = P;

        for (size_t i = 0; i < mpz_sizeinbase(k.get_mpz_t(), 2); ++i) {
            if (mpz_tstbit(k.get_mpz_t(), i)) {
                R = point_add(R, addend, curve);
            }
            addend = point_add(addend, addend, curve);
        }
        return R;
    }
}

// ============================================================================
// МОДУЛЬ 3: Constant-Time защита и Оптимизация (Ослепление точки)
// ============================================================================
namespace Security_Module {
    using namespace EC_Algebra;

    // Глобальное состояние ГПСЧ для GMP (инициализируется один раз)
    gmp_randstate_t r_state;
    bool rng_initialized = false;

    void init_rng() {
        if (!rng_initialized) {
            gmp_randinit_default(r_state);
            gmp_randseed_ui(r_state, time(nullptr));
            rng_initialized = true;
        }
    }

    mpz_class generate_random_scalar(const mpz_class& max_val) {
        init_rng();
        mpz_class res;
        mpz_urandomm(res.get_mpz_t(), r_state, max_val.get_mpz_t());
        return res;
    }

    /*
     * ЗАДАНИЕ ВАРИАНТА 5: Ослепление точки (Point Blinding)
     * Формула: Q = d * (G + R) - d * R, где R - случайная точка.
     * Это защищает от DPA-атак, так как скалярное умножение выполняется 
     * не от базовой точки G, а от рандомизированной (G+R).
     */
    CurveParams::Point secure_multiply(const mpz_class& d, const CurveParams::Point& G, const CurveParams& curve) {
        // 1. Генерируем случайный скаляр r_rand и вычисляем случайную точку R
        mpz_class r_rand = generate_random_scalar(curve.q);
        CurveParams::Point R = basic_multiply(r_rand, G, curve);

        // 2. Вычисляем P1 = G + R
        CurveParams::Point P1 = point_add(G, R, curve);

        // 3. Вычисляем Q1 = d * P1
        CurveParams::Point Q1 = basic_multiply(d, P1, curve);

        // 4. Вычисляем Q2 = d * R
        CurveParams::Point Q2 = basic_multiply(d, R, curve);

        // 5. Вычисляем итоговую точку Q = Q1 - Q2 (что эквивалентно Q1 + (-Q2))
        CurveParams::Point neg_Q2(Q2.x, safe_mod(-Q2.y, curve.p));
        CurveParams::Point Q = point_add(Q1, neg_Q2, curve);

        return Q;
    }
}

// ============================================================================
// МОДУЛЬ 2: Криптографические протоколы (ECDH и ЭЦП СТБ 34.101.45)
// ============================================================================
namespace Crypto_Protocols {
    using namespace EC_Algebra;
    using namespace Security_Module;

    // --- ECDH ---
    mpz_class ecdh_shared_secret(const mpz_class& d_private, const CurveParams::Point& Q_public, const CurveParams& curve) {
        CurveParams::Point K = secure_multiply(d_private, Q_public, curve);
        return K.x; // В качестве ключа берем x-координату
    }

    // --- ЭЦП СТБ 34.101.45 ---
    struct Signature {
        mpz_class r, s;
    };

    Signature sign(const mpz_class& hash_e, const mpz_class& d, const CurveParams& curve) {
        while (true) {
            // Генерация эфемерного ключа k
            mpz_class k = generate_random_scalar(curve.q);
            if (k == 0) continue;

            // C = k * G
            CurveParams::Point C = basic_multiply(k, curve.G, curve);
            if (C.infinity) continue;

            // r = x_c (mod q)
            mpz_class r = safe_mod(C.x, curve.q);
            if (r == 0) continue;

            // s = (r * d + k * e) (mod q)
            mpz_class s = safe_mod(r * d + k * hash_e, curve.q);
            if (s == 0) continue;

            return {r, s};
        }
    }

    bool verify(const Signature& sig, const mpz_class& hash_e, const CurveParams::Point& Q, const CurveParams& curve) {
        // Проверка границ
        if (sig.r <= 0 || sig.r >= curve.q || sig.s <= 0 || sig.s >= curve.q) return false;

        // v = e^{-1} (mod q)
        mpz_class v = mod_inv(hash_e, curve.q);
        
        // z1 = (s * v) (mod q), z2 = (-r * v) (mod q)
        mpz_class z1 = safe_mod(sig.s * v, curve.q);
        mpz_class z2 = safe_mod(-sig.r * v, curve.q);

        // C' = z1 * G + z2 * Q
        CurveParams::Point C1 = basic_multiply(z1, curve.G, curve);
        CurveParams::Point C2 = basic_multiply(z2, Q, curve);
        CurveParams::Point C_prime = point_add(C1, C2, curve);

        if (C_prime.infinity) return false;

        // R = x_{c'} (mod q)
        mpz_class R = safe_mod(C_prime.x, curve.q);
        
        return R == sig.r;
    }
}

// ============================================================================
// MAIN: Демонстрация работы и тестирование
// ============================================================================
int main() {
    SetConsoleOutputCP(65001);
    SetConsoleCP(65001);
    // Параметры кривой secp256k1 (задаются в Hex, как требуется в задании)
    EC_Algebra::CurveParams curve;
    curve.p = hex_to_mpi("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F");
    curve.a = hex_to_mpi("0");
    curve.b = hex_to_mpi("7");
    curve.q = hex_to_mpi("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    
    curve.G.x = hex_to_mpi("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798");
    curve.G.y = hex_to_mpi("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8");
    curve.G.infinity = false;

    std::cout << "=== Лабораторная работа №3. Вариант 5 ===\n";
    std::cout << "Алгоритм: СТБ 34.101.45 | Кривая: Вейерштрасс (Аффинная) | Защита: Ослепление точки\n\n";

    // 1. Генерация ключей Алисы и Боба
    mpz_class d_A = Security_Module::generate_random_scalar(curve.q);
    EC_Algebra::CurveParams::Point Q_A = Security_Module::secure_multiply(d_A, curve.G, curve);

    mpz_class d_B = Security_Module::generate_random_scalar(curve.q);
    EC_Algebra::CurveParams::Point Q_B = Security_Module::secure_multiply(d_B, curve.G, curve);

    // 2. Протокол ECDH
    mpz_class K_A = Crypto_Protocols::ecdh_shared_secret(d_A, Q_B, curve);
    mpz_class K_B = Crypto_Protocols::ecdh_shared_secret(d_B, Q_A, curve);

    std::cout << "[ECDH] Shared Secret (Alice): " << mpi_to_hex(K_A) << "\n";
    std::cout << "[ECDH] Shared Secret (Bob):   " << mpi_to_hex(K_B) << "\n";
    std::cout << "[ECDH] Status: " << (K_A == K_B ? "SUCCESS (Keys match)" : "FAILED") << "\n\n";

    // 3. ЭЦП (СТБ 34.101.45)
    // Имитация хэша сообщения (сырой Hex)
    mpz_class hash_e = hex_to_mpi("A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90");
    
    std::cout << "[ЭЦП] Подписание сообщения хэша: " << mpi_to_hex(hash_e) << "\n";
    Crypto_Protocols::Signature sig = Crypto_Protocols::sign(hash_e, d_A, curve);
    std::cout << "[ЭЦП] Подпись (r): " << mpi_to_hex(sig.r) << "\n";
    std::cout << "[ЭЦП] Подпись (s): " << mpi_to_hex(sig.s) << "\n";

    bool is_valid = Crypto_Protocols::verify(sig, hash_e, Q_A, curve);
    std::cout << "[ЭЦП] Верификация оригинальной подписи: " << (is_valid ? "VALID" : "INVALID") << "\n";

    // 4. Тест на устойчивость к искажениям (Fault Injection / Tampering)
    Crypto_Protocols::Signature fake_sig = sig;
    fake_sig.s += 1; // Намеренно искажаем параметр s
    bool is_fake_valid = Crypto_Protocols::verify(fake_sig, hash_e, Q_A, curve);
    std::cout << "[ЭЦП] Верификация искаженной подписи (s+1): " << (is_fake_valid ? "VALID" : "INVALID (Correctly rejected)") << "\n";

    return 0;
}