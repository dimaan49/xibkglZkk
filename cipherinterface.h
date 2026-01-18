// cipherinterface.h
#ifndef CIPHERINTERFACE_H
#define CIPHERINTERFACE_H

#include <QWidget>
#include <QString>
#include "ciphercore.h"

class CipherInterface : public QObject {
    Q_OBJECT

public:
    virtual ~CipherInterface() = default;

    // Основные методы
    virtual CipherResult encrypt(const QString& text) const = 0;
    virtual CipherResult decrypt(const QString& text) const = 0;

    // Информация о шифре
    virtual QString name() const = 0;
    virtual QString description() const = 0;

    // GUI элементы для параметров
    virtual QWidget* createParametersWidget(QWidget* parent) = 0;
    virtual void getParametersFromUI() = 0;

    // Поддерживаемые операции
    virtual bool supportsEncryption() const { return true; }
    virtual bool supportsDecryption() const { return true; }
};

#endif // CIPHERINTERFACE_H
