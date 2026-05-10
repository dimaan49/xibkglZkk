#ifndef ELGAMALSIGN_H
#define ELGAMALSIGN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

// ==================== ElGamalSignCipher ====================
class ElGamalSignCipher : public CipherInterface
{
public:
    ElGamalSignCipher();

    // Основные методы шифрования/расшифрования
    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ElGamal с цифровой подписью"; }
    QString description() const override {
        return "Алгоритм ElGamal с цифровой подписью. "
               "При шифровании создается подпись сообщения (a,b), "
               "при расшифровании подпись проверяется.";
    }

    static uint64_t generateRandomKStatic(uint64_t p);

    bool isPrimitiveRoot(uint64_t g, uint64_t p) const;

    // Хеш-функция квадратичной свертки
    uint64_t computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int stepOffset) const;

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    // Проверка параметров
    bool validateParameters(uint64_t p, uint64_t g, uint64_t x, uint64_t p_hash, QString& errorMessage) const;
};

// ==================== Регистратор ====================
class ElGamalSignCipherRegister
{
public:
    ElGamalSignCipherRegister();
};

#endif // ELGAMALSIGN_H
