#ifndef CIPHERINTERFACE_H
#define CIPHERINTERFACE_H

#include <QString>
#include <QMap>
#include <QVariant>
#include "ciphercore.h"

class CipherInterface
{
public:
    virtual ~CipherInterface() = default;

    virtual CipherResult encrypt(const QString& text, const QVariantMap& params = {}) = 0;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params = {}) = 0;

    virtual QString name() const = 0;
    virtual QString description() const = 0;

    // Проверка параметров (опционально)
    virtual bool validateParameters(const QVariantMap& params, QString& error) const {
        Q_UNUSED(params);
        error.clear();
        return true;
    }
};

#endif // CIPHERINTERFACE_H
