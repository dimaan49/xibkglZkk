#ifndef CIPHERWIDGETFACTORY_H
#define CIPHERWIDGETFACTORY_H

#include <QWidget>
#include <QMap>
#include <QVariant>
#include <QVBoxLayout>

class CipherWidgetFactory
{
public:
    static CipherWidgetFactory& instance();

    // Регистрация виджетов для шифра
    void registerCipherWidgets(const QString& cipherId,
                              std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> creator);

    // Создание виджетов для шифра
    void createWidgets(const QString& cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets);

    // Получение значений из виджетов
    static QVariantMap collectValues(const QMap<QString, QWidget*>& widgets);

private:
    CipherWidgetFactory() = default;

    QMap<QString, std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)>> m_creators;
};

#endif // CIPHERWIDGETFACTORY_H
