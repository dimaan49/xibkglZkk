// cipherfactory.h
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

// Категории шифров (обновленные)
enum class CipherCategory {
    KeyExchange,        // Алгоритмы обмена ключами
    DigitalSignature,   // Алгоритмы цифровой подписи
    Asymmetric,         // Асимметричные
    Combinatorial,      // Комбинационные
    Stream,             // Поточные
    Gamma,              // Шифры гаммирования
    Permutation,        // Шифры перестановки
    BlockSubstitution,  // Шифры блочной замены
    Polyalphabetic,     // Шифры многозначной замены
    Monoalphabetic      // Шифры однозначной замены
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

    // Для получения иконки категории (опционально)
    QString categoryIcon() const {
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
};

class CipherFactory
{
public:
    static CipherFactory& instance();

    // Регистрация шифра с числовым ID
    void registerCipher(int id,
                       const QString& displayName,
                       std::function<CipherInterface*()> creator,
                       CipherCategory category = CipherCategory::Asymmetric);

    // Получение списка displayName в порядке возрастания ID
    QStringList displayNames() const;

    // Получение списка displayName с фильтром по категориям
    QStringList displayNames(const QList<CipherCategory>& categories) const;

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

    // Получение всех категорий с их названиями
    QList<CipherCategory> getAllCategories() const;

    // Получение названия категории
    static QString getCategoryName(CipherCategory category);

    // Получение иконки категории
    static QString getCategoryIcon(CipherCategory category);

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
