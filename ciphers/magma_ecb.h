#ifndef MAGMA_ECB_H
#define MAGMA_ECB_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <array>
#include <cstdint>

// Класс шифра Магма в режиме простой замены (ECB)
class MagmaECBCipher : public CipherInterface
{
public:
    MagmaECBCipher();
    virtual ~MagmaECBCipher() = default;

    QString name() const override { return "Магма (ГОСТ Р 34.12-2015) - ECB"; }
    QString description() const override { return "Блочный шифр с длиной блока 64 бит, режим простой замены (ГОСТ Р 34.13-2015)"; }
    QString alphabet() const override {return m_alphabet; }
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // S-блоки ГОСТ Р 34.12-2015 (раздел 5.1.1)
    static const std::array<uint8_t, 16> PI0;
    static const std::array<uint8_t, 16> PI1;
    static const std::array<uint8_t, 16> PI2;
    static const std::array<uint8_t, 16> PI3;
    static const std::array<uint8_t, 16> PI4;
    static const std::array<uint8_t, 16> PI5;
    static const std::array<uint8_t, 16> PI6;
    static const std::array<uint8_t, 16> PI7;

    // Базовые преобразования
    uint32_t tTransform(uint32_t x) const;
    uint32_t leftShift11(uint32_t x) const;
    uint32_t g(uint32_t a, uint32_t k) const;

    // Шифрование одного 64-битного блока
    uint64_t encryptBlock(uint64_t block, const std::array<uint32_t, 32>& roundKeys) const;
    CipherResult process(const QString& text, const QVariantMap& params, bool encrypt);

    // Развертывание ключа (key schedule) по ГОСТ Р 34.12-2015
    std::array<uint32_t, 32> keySchedule(const QString& keyHex) const;

    // Алфавит для вывода
    QString m_alphabet = CipherUtils::HEX_ALPHABET;
};


// Класс для регистрации шифра
class MagmaECBCipherRegister
{
public:
    MagmaECBCipherRegister();
};

#endif // MAGMA_ECB_H
