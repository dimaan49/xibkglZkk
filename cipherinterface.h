#ifndef CIPHERINTERFACE_H
#define CIPHERINTERFACE_H

#include <QString>
#include <QVariant>
#include "ciphercore.h"
#include "cipherparameters.h"  // Добавляем

class CipherInterface
{
public:
    virtual ~CipherInterface() = default;

    virtual CipherResult encrypt(const QString& text, const QVariantMap& params = {}) = 0;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params = {}) = 0;

    virtual QString name() const = 0;
    virtual QString description() const = 0;

};

#endif // CIPHERINTERFACE_H
