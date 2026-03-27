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

    virtual QString name() const override { return "AES (Rijndael)"; }
    virtual QString description() const override { return "Симметричный блочный шифр, стандарт FIPS-197"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

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

    // Вспомогательные функции для работы с HEX
    QString prepareHexInput(const QString& text) const;
    QString bytesToHex(const uint8_t* data, int len) const;
    void hexToBytes(const QString& hex, uint8_t* out, int len) const;

    // Алфавит для вывода
    QString m_alphabet = "HEX";
};

// Виджет для ввода HEX с проверкой
class AESHexEdit : public QLineEdit
{
    Q_OBJECT

public:
    AESHexEdit(QWidget* parent = nullptr);
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
class AESCipherRegister
{
public:
    AESCipherRegister();
};

#endif // AES_H
