#ifndef VIGENERE_AUTO_H
#define VIGENERE_AUTO_H

#include "cipherinterface.h"

class VigenereAutoCipher : public CipherInterface
{
public:
    VigenereAutoCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Виженер (самоключ)"; }
    QString description() const override {
        return "Автоключевой шифр: ключ = начальная буква + открытый текст";
    }

private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    QString generateEncryptionKey(const QString& text, QChar keyLetter) const;
};

class VigenereAutoCipherRegister {
public:
    VigenereAutoCipherRegister();
};

static VigenereAutoCipherRegister vigenereAutoRegister;

#endif // VIGENERE_AUTO_H
