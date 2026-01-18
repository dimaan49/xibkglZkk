#include "cipherfactory.h"

CipherFactory& CipherFactory::instance()
{
    static CipherFactory instance;
    return instance;
}

void CipherFactory::registerCipher(const QString& id,
                                  const QString& displayName,
                                  std::function<CipherInterface*()> creator)
{
    if (m_ciphers.contains(id)) {
        qWarning() << "Шифр с ID" << id << "уже зарегистрирован";
        return;
    }

    // Создаем временный экземпляр для получения описания
    std::unique_ptr<CipherInterface> cipher(creator());
    CipherInfo info;
    info.displayName = displayName;
    info.creator = creator;
    info.description = cipher ? cipher->description() : "";

    m_ciphers.insert(id, info);
    m_displayNameToId.insert(displayName, id);

    qDebug() << "Зарегистрирован шифр:" << displayName << "(" << id << ")";
}

QStringList CipherFactory::availableCiphers() const
{
    return m_ciphers.keys();
}

QStringList CipherFactory::displayNames() const
{
    QStringList names;
    for (const auto& info : m_ciphers) {
        names.append(info.displayName);
    }
    std::sort(names.begin(), names.end());
    return names;
}

std::unique_ptr<CipherInterface> CipherFactory::createCipher(const QString& id)
{
    if (!m_ciphers.contains(id)) {
        qWarning() << "Шифр с ID" << id << "не найден";
        return nullptr;
    }

    return std::unique_ptr<CipherInterface>(m_ciphers[id].creator());
}

QString CipherFactory::idFromDisplayName(const QString& displayName) const
{
    return m_displayNameToId.value(displayName, "");
}

QString CipherFactory::cipherDescription(const QString& id) const
{
    if (m_ciphers.contains(id)) {
        return m_ciphers[id].description;
    }
    return "";
}
