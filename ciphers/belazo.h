#ifndef BELAZO_H
#define BELAZO_H

#include "cipherinterface.h"

class BelazoCipher : public CipherInterface
{
public:
    BelazoCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Шифр Белазо"; }
    QString description() const override {
        return "Полиалфавитный шифр с ключевым словом";
    }
    QString alphabet() const override {return m_alphabet; }

private:
    QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    QString generateKey(const QString& text, const QString& key) const;
};

class BelazoCipherRegister {
public:
    BelazoCipherRegister();
};

static BelazoCipherRegister belazoRegister;

#endif // BELAZO_H
