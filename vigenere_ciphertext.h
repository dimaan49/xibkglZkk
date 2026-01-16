#ifndef VIGENERE_CIPHERTEXT_H
#define VIGENERE_CIPHERTEXT_H

#include "ciphercore.h"

class VigenereCiphertextCipher {
private:
    QString alphabet;

public:
    VigenereCiphertextCipher();

    // Шифрование: ключ-шифротекст
    CipherResult encrypt(const QString& text, QChar keyLetter) const;

    // Дешифрование: ключ-шифротекст
    CipherResult decrypt(const QString& text, QChar keyLetter) const;

    QString name() const;
    QString description() const;

private:
    int getLetterIndex(QChar letter) const;
};

#endif // VIGENERE_CIPHERTEXT_H
