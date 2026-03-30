#ifndef KUZNECHIK_H
#define KUZNECHIK_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <array>
#include <cstdint>
#include <QLineEdit>

// Класс шифра Кузнечик (ГОСТ Р 34.12-2015)
class KuznechikCipher : public CipherInterface
{
public:
    KuznechikCipher();
    virtual ~KuznechikCipher() = default;

    virtual QString name() const override { return "Кузнечик (ГОСТ Р 34.12-2015)"; }
    virtual QString description() const override { return "Блочный шифр с длиной блока 128 бит (SP-сеть)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

private:
    // S-блок из ГОСТ Р 34.12-2015 (раздел 4.1.1)
    static const std::array<uint8_t, 256> PI;
    static const std::array<uint8_t, 256> PI_INV;

    // Коэффициенты для линейного преобразования L (раздел 4.1.2)
    static const std::array<uint8_t, 16> L_VEC;

    // Вспомогательные функции
    uint8_t gf256Mul(uint8_t a, uint8_t b) const;

    // Базовые преобразования (раздел 4.2)
    void X(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const;
    void S(std::array<uint8_t, 16>& state) const;
    void invS(std::array<uint8_t, 16>& state) const;
    void R(std::array<uint8_t, 16>& state) const;
    void invR(std::array<uint8_t, 16>& state) const;
    void L(std::array<uint8_t, 16>& state) const;
    void invL(std::array<uint8_t, 16>& state) const;
    void LSX(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const;
    void invLSX(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const;
    void F(std::array<uint8_t, 16>& out1, std::array<uint8_t, 16>& out2,
           const std::array<uint8_t, 16>& in1, const std::array<uint8_t, 16>& in2,
           const std::array<uint8_t, 16>& iterConst) const;

    // Развертывание ключа (раздел 4.3)
    std::array<std::array<uint8_t, 16>, 10> expandKey(const std::array<uint8_t, 32>& masterKey) const;

    // Итерационные константы C_i (раздел 4.3, формула 10)
    std::array<std::array<uint8_t, 16>, 32> generateIterConstants() const;

    // Вспомогательные функции для работы с HEX
    QString prepareHexInput(const QString& text) const;
    QString bytesToHex(const uint8_t* data, int len) const;
    void hexToBytes(const QString& hex, uint8_t* out, int len) const;

    // Алфавит для вывода
    QString m_alphabet = "HEX";
};

// Виджет для ввода HEX
class KuznechikHexEdit : public QLineEdit
{
    Q_OBJECT

public:
    KuznechikHexEdit(QWidget* parent = nullptr);
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

// Регистратор
class KuznechikCipherRegister
{
public:
    KuznechikCipherRegister();
};

#endif // KUZNECHIK_H
