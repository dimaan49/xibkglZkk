#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QSpinBox>
#include <QLineEdit>
#include <QVBoxLayout>
#include <QDebug>

CipherWidgetFactory& CipherWidgetFactory::instance()
{
    static CipherWidgetFactory instance;
    return instance;
}

void CipherWidgetFactory::registerCipherWidgets(const QString& cipherId,
                                               std::function<void(QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)> creator)
{
    m_creators[cipherId] = creator;
}

void CipherWidgetFactory::createWidgets(const QString& cipherId, QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)
{
    if (m_creators.contains(cipherId)) {
        m_creators[cipherId](parent, layout, widgets);
    }
}

QVariantMap CipherWidgetFactory::collectValues(const QMap<QString, QWidget*>& widgets)
{
    QVariantMap params;

    for (auto it = widgets.constBegin(); it != widgets.constEnd(); ++it) {
        QString paramId = it.key();
        QWidget* widget = it.value();

        if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(widget)) {
            params[paramId] = spinBox->value();
        }
        else if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(widget)) {
            QString text = lineEdit->text();
            if (paramId == "keyLetter" && !text.isEmpty()) {
                    params[paramId] = text[0].toUpper();
                } else {
                    params[paramId] = text;
            }
        }
        // Добавьте другие типы виджетов
    }

    return params;
}
