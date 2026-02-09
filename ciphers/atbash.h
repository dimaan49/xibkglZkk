#ifndef ATBASH_H
#define ATBASH_H

#include "cipherinterface.h"

class AtbashCipher : public CipherInterface
{
public:
    AtbashCipher();
    ~AtbashCipher() override = default;

    // Decrypt просто вызывает encrypt
    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override {
        // Для Atbash шифрование и дешифрование идентичны
        return encrypt(text, params);
    }

    QString name() const override { return "Атбаш"; }
    QString description() const override {
        return "Зеркальный шифр. Каждая буква заменяется на симметричную относительно центра алфавита.";
    }

private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
};

class AtbashCipherRegister {
public:
    AtbashCipherRegister();
};

static AtbashCipherRegister atbashRegister;

#endif // ATBASH_H
