#include <algorithm>
#include <array>
#include <cstdint>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>

using u8 = std::uint8_t;
using u16 = std::uint16_t;
using u32 = std::uint32_t;
using u64 = std::uint64_t;
using DataBlock = std::array<u8, 16>;


// Арифметика в конечном поле Галуа GF(2^8)

class FiniteField {
public:
    // Вариант 5: x^8 + x^5 + x^3 + x^2 + 1
    static constexpr u16 IRREDUCIBLE_POLY = 0x12D;

    static constexpr u8 xor_add(u8 a, u8 b) noexcept { 
        return static_cast<u8>(a ^ b); 
    }

    // Умножение в поле Галуа (алгоритм сдвига и сложения)
    static u8 gal_mul(u8 val_a, u8 val_b) noexcept {
        u8 accumulator = 0;
        for (int step = 0; step < 8; ++step) {
            u8 selector = static_cast<u8>(0u - (val_b & 1u));
            accumulator ^= (val_a & selector);
            
            u8 overflow_mask = static_cast<u8>(0u - (val_a >> 7));
            val_a = static_cast<u8>((val_a << 1) ^ (IRREDUCIBLE_POLY & overflow_mask));
            val_b >>= 1;
        }
        return accumulator;
    }

    static u8 sq(u8 val) noexcept { 
        return gal_mul(val, val); 
    }

    // Вычисление обратного элемента через a^254 (малая теорема Ферма)
    static u8 get_inverse(u8 val) noexcept {
        if (val == 0) return 0;
        u8 p2 = sq(val);
        u8 p4 = sq(p2);
        u8 p8 = sq(p4);
        u8 p16 = sq(p8);
        u8 p32 = sq(p16);
        u8 p64 = sq(p32);
        u8 p128 = sq(p64);

        u8 res = p128;
        res = gal_mul(res, p64);
        res = gal_mul(res, p32);
        res = gal_mul(res, p16);
        res = gal_mul(res, p8);
        res = gal_mul(res, p4);
        res = gal_mul(res, p2);
        return res;
    }

    static u8 multiply_by_x(u8 val) noexcept {
        u8 overflow = static_cast<u8>(0u - (val >> 7));
        return static_cast<u8>((val << 1) ^ (IRREDUCIBLE_POLY & overflow));
    }

    static bool verify_inverse(u8 original, u8 inv) noexcept {
        return gal_mul(original, inv) == 1;
    }
};



// Блочный шифр AES-128

class BlockCipher128 {
public:
    BlockCipher128() = default;
    static constexpr std::size_t NUM_ROUNDS = 10;

    static constexpr std::array<u8, 16> MIX_MATRIX = {
        0x02, 0x03, 0x01, 0x01,
        0x01, 0x02, 0x03, 0x01,
        0x01, 0x01, 0x02, 0x03,
        0x03, 0x01, 0x01, 0x02
    };

    static constexpr std::array<u8, 16> INV_MIX_MATRIX = {
        0x0E, 0x0B, 0x0D, 0x09,
        0x09, 0x0E, 0x0B, 0x0D,
        0x0D, 0x09, 0x0E, 0x0B,
        0x0B, 0x0D, 0x09, 0x0E
    };

    void expand_key(const DataBlock& master_key) {
        for (std::size_t i = 0; i < 16; ++i) {
            expanded_key_schedule[i] = master_key[i];
        }

        std::size_t current_bytes = 16;
        u8 rcon_val = 0x01;

        while (current_bytes < 176) {
            std::array<u8, 4> temp_word = {
                expanded_key_schedule[current_bytes - 4],
                expanded_key_schedule[current_bytes - 3],
                expanded_key_schedule[current_bytes - 2],
                expanded_key_schedule[current_bytes - 1]
            };

            if ((current_bytes % 16) == 0) {
                u8 first_byte = temp_word[0];
                temp_word[0] = substitute_byte(temp_word[1]);
                temp_word[1] = substitute_byte(temp_word[2]);
                temp_word[2] = substitute_byte(temp_word[3]);
                temp_word[3] = substitute_byte(first_byte);
                temp_word[0] ^= rcon_val;
                rcon_val = FiniteField::multiply_by_x(rcon_val);
            }

            for (std::size_t j = 0; j < 4; ++j) {
                expanded_key_schedule[current_bytes] = 
                    static_cast<u8>(expanded_key_schedule[current_bytes - 16] ^ temp_word[j]);
                ++current_bytes;
            }
        }
    }

    void process_encrypt(const DataBlock& input, DataBlock& output) const noexcept {
        DataBlock state = input;
        xor_round_key(state, 0);

        for (std::size_t rnd = 1; rnd <= 9; ++rnd) {
            apply_sbox(state);
            permute_rows(state);
            diffuse_columns(state);
            xor_round_key(state, rnd);
        }

        apply_sbox(state);
        permute_rows(state);
        xor_round_key(state, 10);
        output = state;
    }

    void process_decrypt(const DataBlock& input, DataBlock& output) const noexcept {
        DataBlock state = input;
        xor_round_key(state, 10);

        for (int rnd = 9; rnd >= 1; --rnd) {
            inv_permute_rows(state);
            inv_apply_sbox(state);
            xor_round_key(state, static_cast<std::size_t>(rnd));
            inv_diffuse_columns(state);
        }

        inv_permute_rows(state);
        inv_apply_sbox(state);
        xor_round_key(state, 0);
        output = state;
    }

    static u8 substitute_byte(u8 x) noexcept {
        u8 y = FiniteField::get_inverse(x);
        return static_cast<u8>(y ^ rotate_left(y, 1) ^ rotate_left(y, 2) ^ 
                               rotate_left(y, 3) ^ rotate_left(y, 4) ^ 0x63);
    }

    static u8 inv_substitute_byte(u8 x) noexcept {
        u8 y = static_cast<u8>(rotate_left(x, 1) ^ rotate_left(x, 3) ^ rotate_left(x, 6) ^ 0x05);
        return FiniteField::get_inverse(y);
    }

    static bool check_mix_matrices() noexcept {
        for (std::size_t r = 0; r < 4; ++r) {
            for (std::size_t c = 0; c < 4; ++c) {
                u8 acc = 0;
                for (std::size_t k = 0; k < 4; ++k) {
                    acc ^= FiniteField::gal_mul(INV_MIX_MATRIX[4 * r + k], MIX_MATRIX[4 * k + c]);
                }
                if (acc != static_cast<u8>(r == c ? 1 : 0)) return false;
            }
        }
        return true;
    }

private:
    std::array<u8, 176> expanded_key_schedule{};

    static u8 rotate_left(u8 x, unsigned n) noexcept {
        return static_cast<u8>((x << n) | (x >> (8u - n)));
    }

    static void xor_round_key(DataBlock& state, std::size_t rnd, const std::array<u8, 176>& keys) noexcept {
        std::size_t offset = rnd * 16;
        for (std::size_t i = 0; i < 16; ++i) {
            state[i] ^= keys[offset + i];
        }
    }

    void xor_round_key(DataBlock& state, std::size_t rnd) const noexcept {
        xor_round_key(state, rnd, expanded_key_schedule);
    }

    static void apply_sbox(DataBlock& state) noexcept {
        for (u8& byte_val : state) {
            byte_val = substitute_byte(byte_val);
        }
    }

    static void inv_apply_sbox(DataBlock& state) noexcept {
        for (u8& byte_val : state) {
            byte_val = inv_substitute_byte(byte_val);
        }
    }

    static void permute_rows(DataBlock& state) noexcept {
        DataBlock temp = state;
        state[1] = temp[5];  state[5] = temp[9];  state[9] = temp[13]; state[13] = temp[1];
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        state[3] = temp[15]; state[7] = temp[3];  state[11] = temp[7]; state[15] = temp[11];
    }

    static void inv_permute_rows(DataBlock& state) noexcept {
        DataBlock temp = state;
        state[1] = temp[13]; state[5] = temp[1];  state[9] = temp[5];  state[13] = temp[9];
        state[2] = temp[10]; state[6] = temp[14]; state[10] = temp[2]; state[14] = temp[6];
        state[3] = temp[7];  state[7] = temp[11]; state[11] = temp[15];state[15] = temp[3];
    }

    static void diffuse_columns(DataBlock& state) noexcept {
        for (int col = 0; col < 4; ++col) {
            int idx = col * 4;
            u8 c0 = state[idx], c1 = state[idx+1], c2 = state[idx+2], c3 = state[idx+3];
            state[idx]   = FiniteField::gal_mul(0x02, c0) ^ FiniteField::gal_mul(0x03, c1) ^ c2 ^ c3;
            state[idx+1] = c0 ^ FiniteField::gal_mul(0x02, c1) ^ FiniteField::gal_mul(0x03, c2) ^ c3;
            state[idx+2] = c0 ^ c1 ^ FiniteField::gal_mul(0x02, c2) ^ FiniteField::gal_mul(0x03, c3);
            state[idx+3] = FiniteField::gal_mul(0x03, c0) ^ c1 ^ c2 ^ FiniteField::gal_mul(0x02, c3);
        }
    }

    static void inv_diffuse_columns(DataBlock& state) noexcept {
        for (int col = 0; col < 4; ++col) {
            int idx = col * 4;
            u8 c0 = state[idx], c1 = state[idx+1], c2 = state[idx+2], c3 = state[idx+3];
            state[idx]   = FiniteField::gal_mul(0x0E, c0) ^ FiniteField::gal_mul(0x0B, c1) ^ FiniteField::gal_mul(0x0D, c2) ^ FiniteField::gal_mul(0x09, c3);
            state[idx+1] = FiniteField::gal_mul(0x09, c0) ^ FiniteField::gal_mul(0x0E, c1) ^ FiniteField::gal_mul(0x0B, c2) ^ FiniteField::gal_mul(0x0D, c3);
            state[idx+2] = FiniteField::gal_mul(0x0D, c0) ^ FiniteField::gal_mul(0x09, c1) ^ FiniteField::gal_mul(0x0E, c2) ^ FiniteField::gal_mul(0x0B, c3);
            state[idx+3] = FiniteField::gal_mul(0x0B, c0) ^ FiniteField::gal_mul(0x0D, c1) ^ FiniteField::gal_mul(0x09, c2) ^ FiniteField::gal_mul(0x0E, c3);
        }
    }
};


// Режим шифрования GCM (Galois/Counter Mode)

class AuthenticatedCipher {
public:
    static constexpr std::size_t BUFFER_LIMIT = 4096;

    struct EncryptionOutcome {
        std::array<u8, BUFFER_LIMIT> cipher_data{};
        std::size_t data_length = 0;
        DataBlock auth_tag{};
    };

    explicit AuthenticatedCipher(const BlockCipher128& cipher_ref) : cipher_engine(cipher_ref) {
        DataBlock zero_block{};
        cipher_engine.process_encrypt(zero_block, hash_subkey_H);
    }

    EncryptionOutcome seal(const std::array<u8, BUFFER_LIMIT>& plain, std::size_t plain_len,
                           const std::array<u8, BUFFER_LIMIT>& associated_data, std::size_t aad_len,
                           const std::array<u8, 12>& nonce) const {
        EncryptionOutcome outcome;
        outcome.data_length = plain_len;

        DataBlock j0{};
        for (std::size_t i = 0; i < 12; ++i) j0[i] = nonce[i];
        j0[15] = 1;

        DataBlock counter = j0;
        bump_counter(counter);

        std::size_t processed = 0;
        while (processed < plain_len) {
            DataBlock key_stream{};
            cipher_engine.process_encrypt(counter, key_stream);
            
            std::size_t chunk = std::min<std::size_t>(16, plain_len - processed);
            for (std::size_t i = 0; i < chunk; ++i) {
                outcome.cipher_data[processed + i] = plain[processed + i] ^ key_stream[i];
            }
            processed += chunk;
            bump_counter(counter);
        }

        DataBlock ghash_result = compute_ghash(associated_data, aad_len, outcome.cipher_data, plain_len);
        
        DataBlock encrypted_j0{};
        cipher_engine.process_encrypt(j0, encrypted_j0);
        for (std::size_t i = 0; i < 16; ++i) {
            outcome.auth_tag[i] = encrypted_j0[i] ^ ghash_result[i];
        }

        return outcome;
    }

    static bool secure_compare(const DataBlock& a, const DataBlock& b) noexcept {
        u8 diff_accumulator = 0;
        for (std::size_t i = 0; i < 16; ++i) {
            diff_accumulator |= static_cast<u8>(a[i] ^ b[i]);
        }
        return diff_accumulator == 0;
    }

private:
    const BlockCipher128& cipher_engine;
    DataBlock hash_subkey_H{};

    static void bump_counter(DataBlock& blk) noexcept {
        for (int i = 15; i >= 12; --i) {
            if (++blk[i] != 0) {
                break;
            }
        }
    }

    static DataBlock multiply_gf128(const DataBlock& op1, const DataBlock& op2) noexcept {
        DataBlock product{};
        DataBlock current = op2;
        
        for (int bit_idx = 0; bit_idx < 128; ++bit_idx) {
            int byte_pos = bit_idx / 8;
            int bit_pos = 7 - (bit_idx % 8);
            
            if ((op1[byte_pos] >> bit_pos) & 1) {
                for (int j = 0; j < 16; ++j) {
                    product[j] ^= current[j];
                }
            }
            
            u8 lsb = current[15] & 1;
            u8 carry = 0;
            for (int j = 15; j >= 0; --j) {
                u8 next_carry = current[j] & 1;
                current[j] = static_cast<u8>((current[j] >> 1) | (carry << 7));
                carry = next_carry;
            }
            if (lsb) {
                current[0] ^= 0xE1;
            }
        }
        return product;
    }

    static DataBlock block_xor(const DataBlock& a, const DataBlock& b) noexcept {
        DataBlock res{};
        for (std::size_t i = 0; i < 16; ++i) res[i] = a[i] ^ b[i];
        return res;
    }

    DataBlock compute_ghash(const std::array<u8, BUFFER_LIMIT>& aad, std::size_t aad_len,
                            const std::array<u8, BUFFER_LIMIT>& cipher, std::size_t cipher_len) const noexcept {
        DataBlock y{};

        auto process_chunk = [&](const std::array<u8, BUFFER_LIMIT>& src, std::size_t len) {
            std::size_t offset = 0;
            while (offset < len) {
                DataBlock x{};
                std::size_t take = std::min<std::size_t>(16, len - offset);
                for (std::size_t i = 0; i < take; ++i) {
                    x[i] = src[offset + i];
                }
                y = multiply_gf128(block_xor(y, x), hash_subkey_H);
                offset += take;
            }
        };

        process_chunk(aad, aad_len);
        process_chunk(cipher, cipher_len);

        DataBlock length_block{};
        u64 aad_bits = static_cast<u64>(aad_len) * 8u;
        u64 cipher_bits = static_cast<u64>(cipher_len) * 8u;
        
        for (int i = 0; i < 8; ++i) {
            length_block[7 - i] = static_cast<u8>(aad_bits >> (8 * i));
            length_block[15 - i] = static_cast<u8>(cipher_bits >> (8 * i));
        }
        
        y = multiply_gf128(block_xor(y, length_block), hash_subkey_H);
        return y;
    }
};


// Вспомогательные функции ввода-вывода

static int hex_char_to_val(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static DataBlock hex_to_block(const std::string& hex_str) {
    if (hex_str.size() != 32) throw std::invalid_argument("Hex string must be 32 chars");
    DataBlock result{};
    for (std::size_t i = 0; i < 16; ++i) {
        int high = hex_char_to_val(hex_str[2 * i]);
        int low = hex_char_to_val(hex_str[2 * i + 1]);
        if (high < 0 || low < 0) throw std::invalid_argument("Invalid hex character");
        result[i] = static_cast<u8>((high << 4) | low);
    }
    return result;
}

static std::array<u8, 12> hex_to_nonce(const std::string& hex_str) {
    if (hex_str.size() != 24) throw std::invalid_argument("Nonce hex string must be 24 chars");
    std::array<u8, 12> result{};
    for (std::size_t i = 0; i < 12; ++i) {
        int high = hex_char_to_val(hex_str[2 * i]);
        int low = hex_char_to_val(hex_str[2 * i + 1]);
        if (high < 0 || low < 0) throw std::invalid_argument("Invalid hex character");
        result[i] = static_cast<u8>((high << 4) | low);
    }
    return result;
}

static std::string to_hex_string(const u8* data, std::size_t length) {
    std::ostringstream builder;
    builder << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < length; ++i) {
        builder << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return builder.str();
}

int main() {
    try {
        const DataBlock master_key = hex_to_block("000102030405060708090a0b0c0d0e0f");
        const DataBlock plain_block = hex_to_block("00112233445566778899aabbccddeeff");

        BlockCipher128 cipher;
        cipher.expand_key(master_key);

        DataBlock encrypted_block{}, decrypted_block{};
        cipher.process_encrypt(plain_block, encrypted_block);
        cipher.process_decrypt(encrypted_block, decrypted_block);

        std::cout << "Irreducible polynomial: 0x12D\n";
        std::cout << "S-box[00]: " << std::setw(2) << std::setfill('0') << std::hex
                  << static_cast<unsigned>(BlockCipher128::substitute_byte(0x00)) << "\n";
        std::cout << "S-box[53]: " << std::setw(2) << static_cast<unsigned>(BlockCipher128::substitute_byte(0x53)) << "\n";

        bool bijection_valid = true;
        for (int x = 0; x < 256; ++x) {
            if (BlockCipher128::inv_substitute_byte(BlockCipher128::substitute_byte(static_cast<u8>(x))) != static_cast<u8>(x)) {
                bijection_valid = false;
            }
        }

        bool field_valid = (FiniteField::get_inverse(0x00) == 0x00);
        for (int x = 1; x < 256; ++x) {
            field_valid = field_valid && FiniteField::verify_inverse(
                static_cast<u8>(x), FiniteField::get_inverse(static_cast<u8>(x))
            );
        }

        std::cout << "S-box bijection OK: " << (bijection_valid ? "YES" : "NO") << "\n";
        std::cout << "GF(2^8) inverse tests OK (including 0x00): " << (field_valid ? "YES" : "NO") << "\n";
        std::cout << "AES-like CT: " << to_hex_string(encrypted_block.data(), 16) << "\n";
        std::cout << "Decrypt OK: " << (decrypted_block == plain_block ? "YES" : "NO") << "\n";
        std::cout << "Inverse MixColumns OK: " << (BlockCipher128::check_mix_matrices() ? "YES" : "NO") << "\n";

        // Тестирование GCM
        std::array<u8, AuthenticatedCipher::BUFFER_LIMIT> msg_buffer{};
        std::array<u8, AuthenticatedCipher::BUFFER_LIMIT> aad_buffer{};
        
        const std::string test_payload = "Testing";
        const std::string test_aad = "test text";
        
        std::copy(test_payload.begin(), test_payload.end(), msg_buffer.begin());
        std::copy(test_aad.begin(), test_aad.end(), aad_buffer.begin());

        std::array<u8, 12> initialization_vector = hex_to_nonce("000102030405060708090a0b");

        AuthenticatedCipher gcm_instance(cipher);
        auto encryption_result = gcm_instance.seal(msg_buffer, test_payload.size(), 
                                                   aad_buffer, test_aad.size(), initialization_vector);

        std::cout << "GCM ciphertext: " << to_hex_string(encryption_result.cipher_data.data(), encryption_result.data_length) << "\n";
        std::cout << "GCM tag: " << to_hex_string(encryption_result.auth_tag.data(), 16) << "\n";
        std::cout << "Tag valid: " << (AuthenticatedCipher::secure_compare(encryption_result.auth_tag, encryption_result.auth_tag) ? "YES" : "NO") << "\n";

        DataBlock tampered_tag = encryption_result.auth_tag;
        tampered_tag[0] ^= 1;
        std::cout << "Modified tag rejected: " << (!AuthenticatedCipher::secure_compare(encryption_result.auth_tag, tampered_tag) ? "YES" : "NO") << "\n";

    } catch (const std::exception& ex) {
        std::cerr << "Critical Error: " << ex.what() << std::endl;
        return 1;
    }

    return 0;
}