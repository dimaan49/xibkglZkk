// cipherwidgetfactory.h
#ifndef CIPHERWIDGETFACTORY_H
#define CIPHERWIDGETFACTORY_H

#include <QWidget>
#include <QVBoxLayout>
#include <QMap>
#include <functional>
#include <QListWidget>
#include <QListwidgetItem>
#include <QTableWidget>
#include <QTableWidgetItem>
#include <QPushButton>


class CipherWidgetFactory
{
public:
    static CipherWidgetFactory& instance();

    // Регистрация только основных виджетов
    void registerCipherWidgets(const QString& cipherId,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> creator);

    // Регистрация основных + расширенных виджетов
    void registerCipherWidgets(const QString& cipherId,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> mainCreator,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> advancedCreator);

    // Создание основных виджетов
    void createMainWidgets(const QString& cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets);

    // Создание расширенных виджетов
    void createAdvancedWidgets(const QString& cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets);

    // Проверка наличия расширенных виджетов
    bool hasAdvancedWidgets(const QString& cipherId) const;

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

    QMap<QString, CipherWidgetSet> m_widgets;
};

#endif // CIPHERWIDGETFACTORY_H
