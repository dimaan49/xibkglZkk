#ifndef CIPHERFACTORY_H
#define CIPHERFACTORY_H

#include <QMap>
#include <QString>
#include <QStringList>
#include <functional>
#include <memory>
#include <QDebug>
#include "cipherinterface.h"
#include <QLabel>
#include <QTextEdit>
#include <QSpinBox>

// Категории шифров
enum class CipherCategory {
    Stream,           // Поточные
    Block,            // Блочные
    Transposition,    // Перестановочные (комбинационные)
    Substitution,     // Подстановочные
    Asymmetric,       // Асимметричные
    Signature,        // Цифровые подписи
    Hash,             // Хеш-функции
    Other             // Прочие
};

// Структура информации о шифре
struct CipherInfo {
    int id;                          // Числовой ID для сортировки
    QString displayName;             // Отображаемое имя
    std::function<CipherInterface*()> creator;
    QString description;
    CipherCategory category;

    QString categoryName() const {
        switch(category) {
            case CipherCategory::Stream: return "Поточные";
            case CipherCategory::Block: return "Блочные";
            case CipherCategory::Transposition: return "Перестановочные";
            case CipherCategory::Substitution: return "Подстановочные";
            case CipherCategory::Asymmetric: return "Асимметричные";
            case CipherCategory::Signature: return "Цифровые подписи";
            case CipherCategory::Hash: return "Хеш-функции";
            default: return "Прочие";
        }
    }
};

class CipherFactory
{
public:
    static CipherFactory& instance();

    // Регистрация шифра с числовым ID
    void registerCipher(int id,
                       const QString& displayName,
                       std::function<CipherInterface*()> creator,
                       CipherCategory category = CipherCategory::Other);

    // Получение списка displayName в порядке возрастания ID
    QStringList displayNames() const;

    // Получение списка всех ID (отсортированных)
    QList<int> availableCipherIds() const;

    // Получение ID по отображаемому имени
    int idFromDisplayName(const QString& displayName) const;

    // Получение отображаемого имени по ID
    QString displayNameFromId(int id) const;

    // Создание шифра по ID
    std::unique_ptr<CipherInterface> createCipher(int id);

    // Создание шифра по отображаемому имени (для обратной совместимости)
    std::unique_ptr<CipherInterface> createCipher(const QString& displayName);

    // Получение описания шифра по ID
    QString cipherDescription(int id) const;

    // Получение категории шифра по ID
    CipherCategory cipherCategory(int id) const;

    // Получение всех зарегистрированных шифров
    const QMap<int, CipherInfo>& getAllCiphers() const { return m_ciphers; }

    // Группировка шифров по категориям
    QMap<CipherCategory, QList<int>> getCiphersByCategory() const;

    // Проверка существования шифра
    bool hasCipher(int id) const;
    bool hasCipher(const QString& displayName) const;

private:
    CipherFactory() = default;
    CipherFactory(const CipherFactory&) = delete;
    CipherFactory& operator=(const CipherFactory&) = delete;

    QMap<int, CipherInfo> m_ciphers;              // id -> CipherInfo
    QMap<QString, int> m_displayNameToId;         // displayName -> id
};

#endif // CIPHERFACTORY_H
