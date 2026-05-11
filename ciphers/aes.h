#ifndef AES_H
#define AES_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <array>
#include <cstdint>

// Класс шифра AES (Rijndael) по FIPS-197
class AESCipher : public CipherInterface
{
public:
    AESCipher();
    virtual ~AESCipher() = default;

    QString name() const override { return "AES (Rijndael)"; }
    QString description() const override { return "Симметричный блочный шифр, стандарт FIPS-197"; }
    QString alphabet() const override {return m_alphabet; }
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // Константы
    static const int BLOCK_SIZE = 16;      // 128 бит = 16 байт
    static const int Nb = 4;               // количество столбцов в матрице состояния

    // S-блок (таблица замены)
    static const std::array<uint8_t, 256> S_BOX;
    static const std::array<uint8_t, 256> INV_S_BOX;

    // Константы раундов Rcon
    static const std::array<uint32_t, 10> RCON;

    // Вспомогательные функции
    uint8_t gf256Mul(uint8_t a, uint8_t b) const;

    // Преобразования
    void subBytes(std::array<uint8_t, 16>& state) const;
    void invSubBytes(std::array<uint8_t, 16>& state) const;
    void shiftRows(std::array<uint8_t, 16>& state) const;
    void invShiftRows(std::array<uint8_t, 16>& state) const;
    void mixColumns(std::array<uint8_t, 16>& state) const;
    void invMixColumns(std::array<uint8_t, 16>& state) const;
    void addRoundKey(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& roundKey) const;

    // Развертывание ключа
    std::vector<std::array<uint8_t, 16>> expandKey(const std::array<uint8_t, 32>& key, int keySize) const;


    // Алфавит для вывода
    QString m_alphabet = CipherUtils::HEX_ALPHABET;
};


// Класс для регистрации шифра
class AESCipherRegister
{
public:
    AESCipherRegister();
};

#endif // AES_H
