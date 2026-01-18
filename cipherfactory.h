#ifndef CIPHERFACTORY_H
#define CIPHERFACTORY_H

#include <QObject>
#include <QMap>
#include <QString>
#include <functional>
#include <memory>
#include "cipherinterface.h"

class CipherFactory : public QObject
{
    Q_OBJECT

public:
    static CipherFactory& instance();

    // Регистрация шифра
    void registerCipher(const QString& id,
                       const QString& displayName,
                       std::function<CipherInterface*()> creator);

    // Получение списка доступных шифров
    QStringList availableCiphers() const;

    // Получение отображаемых имен
    QStringList displayNames() const;

    // Создание экземпляра шифра
    std::unique_ptr<CipherInterface> createCipher(const QString& id);

    // Получение ID по отображаемому имени
    QString idFromDisplayName(const QString& displayName) const;

    // Получение информации о шифре
    QString cipherDescription(const QString& id) const;

private:
    CipherFactory() = default;
    ~CipherFactory() = default;

    CipherFactory(const CipherFactory&) = delete;
    CipherFactory& operator=(const CipherFactory&) = delete;

    struct CipherInfo {
        QString displayName;
        std::function<CipherInterface*()> creator;
        QString description;
    };

    QMap<QString, CipherInfo> m_ciphers; // id -> CipherInfo
    QMap<QString, QString> m_displayNameToId; // displayName -> id
};

#endif // CIPHERFACTORY_H
