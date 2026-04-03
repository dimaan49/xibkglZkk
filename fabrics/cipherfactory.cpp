// cipherfactory.cpp
#include "cipherfactory.h"

CipherFactory& CipherFactory::instance()
{
    static CipherFactory instance;
    return instance;
}

void CipherFactory::registerCipher(int id,
                                  const QString& displayName,
                                  std::function<CipherInterface*()> creator,
                                  CipherCategory category)
{
    if (m_ciphers.contains(id)) {
        qWarning() << "Шифр с ID" << id << "уже зарегистрирован";
        return;
    }

    if (m_displayNameToId.contains(displayName)) {
        qWarning() << "Шифр с именем" << displayName << "уже зарегистрирован";
        return;
    }

    // Создаем временный экземпляр для получения описания
    std::unique_ptr<CipherInterface> cipher(creator());
    CipherInfo info;
    info.id = id;
    info.displayName = displayName;
    info.creator = creator;
    info.description = cipher ? cipher->description() : "";
    info.category = category;

    m_ciphers.insert(id, info);
    m_displayNameToId.insert(displayName, id);

    qDebug() << "Зарегистрирован шифр:" << displayName << "(ID:" << id
             << ") - категория:" << info.categoryName();
}

QStringList CipherFactory::displayNames() const
{
    QStringList names;

    // Сортируем по числовому ID
    QList<int> ids = m_ciphers.keys();
    std::sort(ids.begin(), ids.end());

    for (int id : ids) {
        names.append(m_ciphers[id].displayName);
    }

    return names;
}

QStringList CipherFactory::displayNames(const QList<CipherCategory>& categories) const
{
    QStringList names;

    // Если фильтр пуст, возвращаем все
    if (categories.isEmpty()) {
        return displayNames();
    }

    // Собираем ID шифров, категории которых есть в фильтре
    QList<int> filteredIds;
    for (auto it = m_ciphers.begin(); it != m_ciphers.end(); ++it) {
        if (categories.contains(it.value().category)) {
            filteredIds.append(it.key());
        }
    }

    // Сортируем по ID
    std::sort(filteredIds.begin(), filteredIds.end());

    for (int id : filteredIds) {
        names.append(m_ciphers[id].displayName);
    }

    return names;
}

QList<int> CipherFactory::availableCipherIds() const
{
    QList<int> ids = m_ciphers.keys();
    std::sort(ids.begin(), ids.end());
    return ids;
}

int CipherFactory::idFromDisplayName(const QString& displayName) const
{
    return m_displayNameToId.value(displayName, -1);
}

QString CipherFactory::displayNameFromId(int id) const
{
    if (m_ciphers.contains(id)) {
        return m_ciphers[id].displayName;
    }
    return QString();
}

std::unique_ptr<CipherInterface> CipherFactory::createCipher(int id)
{
    if (!m_ciphers.contains(id)) {
        qWarning() << "Шифр с ID" << id << "не найден";
        return nullptr;
    }

    return std::unique_ptr<CipherInterface>(m_ciphers[id].creator());
}

std::unique_ptr<CipherInterface> CipherFactory::createCipher(const QString& displayName)
{
    int id = idFromDisplayName(displayName);
    if (id == -1) {
        qWarning() << "Шифр с именем" << displayName << "не найден";
        return nullptr;
    }
    return createCipher(id);
}

QString CipherFactory::cipherDescription(int id) const
{
    if (m_ciphers.contains(id)) {
        return m_ciphers[id].description;
    }
    return QString();
}

CipherCategory CipherFactory::cipherCategory(int id) const
{
    if (m_ciphers.contains(id)) {
        return m_ciphers[id].category;
    }
    return CipherCategory::Asymmetric;
}

QMap<CipherCategory, QList<int>> CipherFactory::getCiphersByCategory() const
{
    QMap<CipherCategory, QList<int>> result;

    for (auto it = m_ciphers.begin(); it != m_ciphers.end(); ++it) {
        result[it.value().category].append(it.key());
    }

    // Сортируем ID в каждой категории
    for (auto& list : result) {
        std::sort(list.begin(), list.end());
    }

    return result;
}

QList<CipherCategory> CipherFactory::getAllCategories() const
{
    QList<CipherCategory> categories;
    for (auto it = m_ciphers.begin(); it != m_ciphers.end(); ++it) {
        if (!categories.contains(it.value().category)) {
            categories.append(it.value().category);
        }
    }
    return categories;
}

QString CipherFactory::getCategoryName(CipherCategory category)
{
    switch(category) {
        case CipherCategory::KeyExchange: return "Алгоритмы обмена ключами";
        case CipherCategory::DigitalSignature: return "Алгоритмы цифровой подписи";
        case CipherCategory::Asymmetric: return "Асимметричные";
        case CipherCategory::Combinatorial: return "Комбинационные";
        case CipherCategory::Stream: return "Поточные";
        case CipherCategory::Gamma: return "Шифры гаммирования";
        case CipherCategory::Permutation: return "Шифры перестановки";
        case CipherCategory::BlockSubstitution: return "Шифры блочной замены";
        case CipherCategory::Polyalphabetic: return "Шифры многозначной замены";
        case CipherCategory::Monoalphabetic: return "Шифры однозначной замены";
        default: return "Прочие";
    }
}

QString CipherFactory::getCategoryIcon(CipherCategory category)
{
    switch(category) {
        case CipherCategory::KeyExchange: return "🔑";
        case CipherCategory::DigitalSignature: return "✍️";
        case CipherCategory::Asymmetric: return "🔐";
        case CipherCategory::Combinatorial: return "🧩";
        case CipherCategory::Stream: return "🌊";
        case CipherCategory::Gamma: return "🎲";
        case CipherCategory::Permutation: return "🔄";
        case CipherCategory::BlockSubstitution: return "🧱";
        case CipherCategory::Polyalphabetic: return "📚";
        case CipherCategory::Monoalphabetic: return "🔡";
        default: return "📦";
    }
}

bool CipherFactory::hasCipher(int id) const
{
    return m_ciphers.contains(id);
}

bool CipherFactory::hasCipher(const QString& displayName) const
{
    return m_displayNameToId.contains(displayName);
}
