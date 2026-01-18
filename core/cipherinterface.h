#ifndef CIPHERINTERFACE_H
#define CIPHERINTERFACE_H

#include <QString>
#include <QVariant>
#include <QVector>
#include "ciphercore.h"

class CipherInterface {
public:
    virtual ~CipherInterface() = default;

    // Основные методы
    virtual CipherResult encrypt(const QString& text, const QVariant& key = QVariant()) = 0;
    virtual CipherResult decrypt(const QString& text, const QVariant& key = QVariant()) = 0;

    // Информационные методы
    virtual QString name() const = 0;
    virtual QString description() const = 0;

    // Параметры шифра
    virtual QVector<QString> parameterNames() const = 0;
    virtual QVector<QString> parameterDescriptions() const = 0;
    virtual QVector<QVariant::Type> parameterTypes() const = 0;

    // Проверка ключа
    virtual bool validateKey(const QVariant& key) const = 0;
};

#endif // CIPHERINTERFACE_H
