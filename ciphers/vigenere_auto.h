#ifndef VIGENERE_AUTO_H
#define VIGENERE_AUTO_H

#include "ciphercore.h"

class VigenereAutoCipher {
private:
    QString alphabet;

public:
    VigenereAutoCipher();

    // Шифрование Виженера с самоключом (первая буква ключа + открытый текст)
    CipherResult encrypt(const QString& text, QChar keyLetter) const;

    // Дешифрование Виженера с самоключом
    CipherResult decrypt(const QString& text, QChar keyLetter) const;

    QString name() const;
    QString description() const;

private:
    // Получение индекса буквы
    int getLetterIndex(QChar letter) const;

    // Генерация ключа для шифрования (keyLetter + текст без последней буквы)
    QString generateEncryptionKey(const QString& text, QChar keyLetter) const;

    // Генерация ключа для дешифрования
    QString generateDecryptionKey(const QString& text, QChar keyLetter) const;
};

#endif // VIGENERE_AUTO_H
