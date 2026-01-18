#ifndef CIPHERFACTORY_H
#define CIPHERFACTORY_H

#include <QMap>
#include <QString>
#include <functional>
#include "cipherinterface.h"

class CipherFactory {
private:
    // Singleton
    static CipherFactory* instance;
    CipherFactory();

    // Реестр создателей
    QMap<QString, std::function<CipherInterface*()>> creators;

public:
    // Singleton instance
    static CipherFactory* getInstance();

    // Запрет копирования
    CipherFactory(const CipherFactory&) = delete;
    CipherFactory& operator=(const CipherFactory&) = delete;

    // Регистрация шифра
    void registerCipher(const QString& name,
                       std::function<CipherInterface*()> creator);

    // Создание шифра
    CipherInterface* createCipher(const QString& name);

    // Список доступных шифров
    QStringList availableCiphers() const;
};

#endif // CIPHERFACTORY_H
