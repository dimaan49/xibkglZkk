// cipherwidgetfactory.h
#ifndef CIPHERWIDGETFACTORY_H
#define CIPHERWIDGETFACTORY_H

#include <QWidget>
#include <QVBoxLayout>
#include <QMap>
#include <functional>

class CipherWidgetFactory
{
public:
    static CipherWidgetFactory& instance();

    // Регистрация только основных виджетов - ID теперь int
    void registerCipherWidgets(int cipherId,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> creator);

    // Регистрация основных + расширенных виджетов - ID теперь int
    void registerCipherWidgets(int cipherId,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> mainCreator,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> advancedCreator);

    // Создание основных виджетов
    void createMainWidgets(int cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets);

    // Создание расширенных виджетов
    void createAdvancedWidgets(int cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets);

    // Проверка наличия расширенных виджетов
    bool hasAdvancedWidgets(int cipherId) const;

    // Сбор значений из виджетов
    static QVariantMap collectValues(const QMap<QString, QWidget*>& widgets);

    // Обновление значений в виджетах
    static void updateWidgets(const QMap<QString, QWidget*>& widgets, const QVariantMap& values);

private:
    CipherWidgetFactory() = default;

    struct CipherWidgetSet {
        std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> mainCreator;
        std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> advancedCreator;
    };

    QMap<int, CipherWidgetSet> m_widgets;  // ← ключ теперь int
};

#endif // CIPHERWIDGETFACTORY_H
