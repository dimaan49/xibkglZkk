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

    virtual QString name() const override { return "Магма (ГОСТ Р 34.12-2015) - ECB"; }
    virtual QString description() const override { return "Блочный шифр с длиной блока 64 бит, режим простой замены (ГОСТ Р 34.13-2015)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

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

    // Развертывание ключа (key schedule) по ГОСТ Р 34.12-2015
    std::array<uint32_t, 32> keySchedule(const QString& keyHex) const;

    // Вспомогательные функции
    QString prepareHexInput(const QString& text) const;
    QString bytesToHex(const uint8_t* data, int len) const;
    void hexToBytes(const QString& hex, uint8_t* out, int len) const;
    uint32_t hexToUint32(const QString& hex) const;
    QString uint32ToHex(uint32_t value) const;
    uint64_t hexToUint64(const QString& hex) const;
    QString uint64ToHex(uint64_t value) const;

    // Алфавит для вывода
    QString m_alphabet = "HEX";
};

// Виджет для ввода HEX
class MagmaECBHexEdit : public QLineEdit
{
    Q_OBJECT

public:
    MagmaECBHexEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }
    void setExpectedLength(int bytes);
    QString getHex() const;
    void setHex(const QString& hex);

protected:
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    int m_expectedBytes = 0;
    QString m_originalStyle;
};

// Класс для регистрации шифра
class MagmaECBCipherRegister
{
public:
    MagmaECBCipherRegister();
};

#endif // MAGMA_ECB_H
