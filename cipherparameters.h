#ifndef CIPHERPARAMETERS_H
#define CIPHERPARAMETERS_H

#include <QString>
#include <QList>
#include <QVariant>

enum ParameterType {
    PARAM_INT,
    PARAM_STRING,
    PARAM_CHAR
};

struct CipherParameter {
    QString id;            // "shift", "key", "startChar"
    QString displayName;   // "Сдвиг", "Ключ", "Начальный символ"
    ParameterType type;
    QVariant defaultValue;
    QVariant minValue;
    QVariant maxValue;
    QString toolTip;

    CipherParameter(const QString& id, const QString& name, ParameterType type,
                   const QVariant& def = QVariant())
        : id(id), displayName(name), type(type), defaultValue(def) {}
};

#endif // CIPHERPARAMETERS_H
