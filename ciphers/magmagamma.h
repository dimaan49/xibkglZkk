#ifndef MAGMAGAMMA_H
#define MAGMAGAMMA_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <array>
#include <cstdint>

// Класс шифра ГОСТ Магма в режиме CTR
class MagmaGammaCipher : public CipherInterface
{
public:
    MagmaGammaCipher();
    virtual ~MagmaGammaCipher() = default;

    // CipherInterface interface
    virtual QString name() const override { return "Магма (ГОСТ Р 34.12-2015) - CTR"; }
    virtual QString description() const override { return "Блочный шифр ГОСТ Р 34.12-2015 (Магма) в режиме гаммирования CTR (ГОСТ Р 34.13-2015)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // S-блоки из ГОСТ Р 34.12-2015 (раздел 5.1.1)
    static const std::array<uint8_t, 16> PI0;
    static const std::array<uint8_t, 16> PI1;
    static const std::array<uint8_t, 16> PI2;
    static const std::array<uint8_t, 16> PI3;
    static const std::array<uint8_t, 16> PI4;
    static const std::array<uint8_t, 16> PI5;
    static const std::array<uint8_t, 16> PI6;
    static const std::array<uint8_t, 16> PI7;

    // Вспомогательные функции
    QString prepareHexInput(const QString& text) const;
    bool isValidHex(const QString& text) const;
    uint32_t hexToUint32(const QString& hex) const;
    QString uint32ToHex(uint32_t value) const;
    uint64_t hexToUint64(const QString& hex) const;
    QString uint64ToHex(uint64_t value) const;

    // Базовые преобразования ГОСТ
    uint32_t tTransform(uint32_t x) const;           // Нелинейное преобразование t
    uint32_t leftShift11(uint32_t x) const;          // Циклический сдвиг влево на 11
    uint32_t g(uint32_t a, uint32_t k) const;        // Функция g[k](a)

    // Шифрование одного 64-битного блока
    uint64_t encryptBlock(uint64_t block, const std::array<uint32_t, 32>& roundKeys) const;

    // Развертывание ключа (key schedule)
    std::array<uint32_t, 32> keySchedule(const QString& keyHex) const;

    // Режим CTR для данных произвольной длины
    QByteArray ctrProcess(const QByteArray& data, const QString& keyHex, const QString& ivHex) const;
};

// Класс для регистрации шифра в фабриках
class MagmaGammaCipherRegister
{
public:
    MagmaGammaCipherRegister();
};

// Валидатор для HEX-полей
class HexLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    HexLineEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }
    void setExpectedLength(int bytes) { m_expectedBytes = bytes; }

protected:
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    int m_expectedBytes = 0; // 0 = любая четная длина
    QString m_originalStyle;
};

#endif // MAGMAGAMMA_H
