#ifndef TRITHEMIUS_H
#define TRITHEMIUS_H

#include "cipherinterface.h"

class TrithemiusCipher : public CipherInterface
{
public:
    TrithemiusCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Шифр Тритемия"; }
    QString description() const override {
        return "Полиалфавитный шифр с прогрессирующим сдвигом. Каждая следующая буква сдвигается на 1 больше предыдущей.";
    }
    QString alphabet() const override {return m_alphabet; }

private:
    QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;
    int normalizeShift(int shift) const;
};

class TrithemiusCipherRegister {
public:
    TrithemiusCipherRegister();
};

static TrithemiusCipherRegister trithemiusRegister;

#endif // TRITHEMIUS_H
