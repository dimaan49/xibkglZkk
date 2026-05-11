#ifndef DIFFIEHELLMAN_H
#define DIFFIEHELLMAN_H

#include "cipherinterface.h"
#include <QObject>
#include <QWidget>
#include <QVariantMap>
#include <QVector>
#include <cstdint>

class DiffieHellmanCipher : public CipherInterface
{
public:
    DiffieHellmanCipher();

    CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    QString name() const override { return "Диффи-Хеллман (обмен ключами)"; }
    QString description() const override {
        return "Протокол обмена ключами Диффи-Хеллмана. "
               "Позволяет двум сторонам выработать общий секретный ключ "
               "через незащищенный канал связи.";
    }
    QString alphabet() const override {return m_alphabet; }

private:
    const QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;
};

// ==================== Регистратор ====================
class DiffieHellmanCipherRegister
{
public:
    DiffieHellmanCipherRegister();
};

#endif // DIFFIEHELLMAN_H
