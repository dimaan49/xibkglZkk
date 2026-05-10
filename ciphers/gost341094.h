#ifndef GOST341094_H
#define GOST341094_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

class GOST341094Cipher : public CipherInterface
{
public:
    GOST341094Cipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "ГОСТ Р 34.10-94 (ЭЦП)"; }
    QString description() const override {
        return "ГОСТ Р 34.10-94 — алгоритм электронной цифровой подписи "
               "на основе дискретного логарифмирования.";
    }

    bool isAvailable() const{ return true; }

    // Статические методы для генерации ключей
    static uint64_t generatePrimeStatic(int bits);
    static uint64_t generateRandomStatic(uint64_t max);


    // Хеш-функция квадратичной свертки
    uint64_t computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int& stepCounter) const;

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    // Проверка параметров
    bool validateParameters(uint64_t p, uint64_t q, uint64_t a, uint64_t x, uint64_t k, uint64_t p_hash, QString& errorMessage) const;
};

// ==================== Регистратор ====================
class GOST341094CipherRegister
{
public:
    GOST341094CipherRegister();
};

#endif // GOST341094_H
