#ifndef CAESARCIPHER_H
#define CAESARCIPHER_H

#include "cipherinterface.h"

class CaesarCipher : public CipherInterface
{
public:
    CaesarCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override { return "Шифр Цезаря"; }
    QString description() const override {
        return "Шифр сдвига. Каждая буква сдвигается на фиксированное количество позиций в алфавите.";
    }


private:
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");

    CipherResult shiftText(const QString& text, int shift, const QString& operation);
    int getShift(const QVariantMap& params) const;
};

class CaesarCipherRegister {
public:
    CaesarCipherRegister();
};

static CaesarCipherRegister caesarRegister;

#endif // CAESARCIPHER_H
