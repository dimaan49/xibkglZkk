// cipherwidgetfactory.cpp
#include "cipherwidgetfactory.h"
#include <QSpinBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QComboBox>
#include <QCheckBox>

CipherWidgetFactory& CipherWidgetFactory::instance()
{
    static CipherWidgetFactory instance;
    return instance;
}

void CipherWidgetFactory::registerCipherWidgets(const QString& cipherId,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> creator)
{
    registerCipherWidgets(cipherId, creator, nullptr);
}

void CipherWidgetFactory::registerCipherWidgets(const QString& cipherId,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> mainCreator,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> advancedCreator)
{
    CipherWidgetSet set;
    set.mainCreator = mainCreator;
    set.advancedCreator = advancedCreator;
    m_widgets[cipherId] = set;
}

void CipherWidgetFactory::createMainWidgets(const QString& cipherId, QWidget* parent,
                                           QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)
{
    if (m_widgets.contains(cipherId) && m_widgets[cipherId].mainCreator) {
        m_widgets[cipherId].mainCreator(parent, layout, widgets);
    }
}

void CipherWidgetFactory::createAdvancedWidgets(const QString& cipherId, QWidget* parent,
                                               QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)
{
    if (m_widgets.contains(cipherId) && m_widgets[cipherId].advancedCreator) {
        m_widgets[cipherId].advancedCreator(parent, layout, widgets);
    }
}

bool CipherWidgetFactory::hasAdvancedWidgets(const QString& cipherId) const
{
    return m_widgets.contains(cipherId) && m_widgets[cipherId].advancedCreator != nullptr;
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
        else if (QTextEdit* textEdit = qobject_cast<QTextEdit*>(widget)) {
            params[paramId] = textEdit->toPlainText();
        }
        else if (QComboBox* comboBox = qobject_cast<QComboBox*>(widget)) {
            params[paramId] = comboBox->currentText();
        }
        else if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(widget)) {
            params[paramId] = checkBox->isChecked();
        }
    }

    return params;
}

void CipherWidgetFactory::updateWidgets(const QMap<QString, QWidget*>& widgets, const QVariantMap& values)
{
    for (auto it = widgets.constBegin(); it != widgets.constEnd(); ++it) {
        QString paramId = it.key();
        QWidget* widget = it.value();

        if (!values.contains(paramId)) continue;

        QVariant value = values[paramId];

        if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(widget)) {
            spinBox->setValue(value.toInt());
        }
        else if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(widget)) {
            lineEdit->setText(value.toString());
        }
        else if (QTextEdit* textEdit = qobject_cast<QTextEdit*>(widget)) {
            textEdit->setPlainText(value.toString());
        }
        else if (QComboBox* comboBox = qobject_cast<QComboBox*>(widget)) {
            int index = comboBox->findText(value.toString());
            if (index >= 0) comboBox->setCurrentIndex(index);
        }
        else if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(widget)) {
            checkBox->setChecked(value.toBool());
        }
    }
}
