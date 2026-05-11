#ifndef RSA_H
#define RSA_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <QPair>
#include <vector>
#include <cstdint>
#include <QRegularExpression>

// Класс шифра RSA
class RSACipher : public CipherInterface
{
public:
    RSACipher();
    virtual ~RSACipher() = default;

    // CipherInterface interface
    QString name() const override { return "RSA"; }
    QString description() const override { return "Асимметричный шифр RSA (Rivest-Shamir-Adleman)"; }
    QString alphabet() const override {return m_alphabet; }
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    // Статические методы для генерации ключей
    static uint64_t generateEStatic(uint64_t phi);

private:
    // Алфавит для преобразования текста в числа
    QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    // Проверка параметров RSA
    bool validateParameters(uint64_t p, uint64_t q, uint64_t e, QString& errorMessage) const;

    // Основные операции RSA
    uint64_t encryptNumber(uint64_t m, uint64_t e, uint64_t n) const;
    uint64_t decryptNumber(uint64_t c, uint64_t d, uint64_t n) const;
};

// Класс для регистрации шифра
class RSACipherRegister
{
public:
    RSACipherRegister();
};

#endif // RSA_H
