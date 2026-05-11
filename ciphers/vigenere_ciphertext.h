#ifndef VIGENERE_CIPHERTEXT_H
#define VIGENERE_CIPHERTEXT_H

#include "cipherinterface.h"

class VigenereCiphertextCipher : public CipherInterface
{
public:
    VigenereCiphertextCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Виженер (шифротекст)"; }
    QString description() const override {
        return "Автоключевой шифр: ключ[i] = шифротекст[i-1] (для i>0)";
    }
    QString alphabet() const override {return m_alphabet; }

private:
    QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;

    CipherResult process(const QString& text, QChar keyLetter, bool encrypt);
};

class VigenereCiphertextCipherRegister {
public:
    VigenereCiphertextCipherRegister();
};

static VigenereCiphertextCipherRegister vigenereCiphertextRegister;

#endif // VIGENERE_CIPHERTEXT_H
