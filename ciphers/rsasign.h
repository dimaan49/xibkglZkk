#ifndef RSASIGN_H
#define RSASIGN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <array>
#include <cstdint>

// ==================== RSASignCipher ====================
class RSASignCipher : public CipherInterface
{
public:
    RSASignCipher();

    // Основные методы шифрования/расшифрования
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "RSA с цифровой подписью"; }
    QString description() const override {
        return "Алгоритм RSA с цифровой подписью. "
               "При шифровании создается подпись хеша сообщения, "
               "при расшифровании подпись проверяется.";
    }

    static uint64_t generateEStatic(uint64_t phi);

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    // Проверка параметров (с учетом p_hash)
    bool validateParameters(uint64_t p, uint64_t q, uint64_t e, uint64_t p_hash, QString& errorMessage) const;


    // Основные криптографические операции
    uint64_t encryptNumber(uint64_t m, uint64_t e, uint64_t n) const;
    uint64_t decryptNumber(uint64_t c, uint64_t d, uint64_t n) const;

};

// ==================== Регистратор ====================
class RSASignCipherRegister
{
public:
    RSASignCipherRegister();
};

#endif // RSASIGN_H
