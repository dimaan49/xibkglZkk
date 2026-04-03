// cipherwidgetfactory.cpp
#include "cipherwidgetfactory.h"
#include "routecipherwidget.h"
#include "ecc.h"
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

void CipherWidgetFactory::registerCipherWidgets(int cipherId,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> creator)
{
    registerCipherWidgets(cipherId, creator, nullptr);
}

void CipherWidgetFactory::registerCipherWidgets(int cipherId,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> mainCreator,
                                               std::function<void(QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&)> advancedCreator)
{
    CipherWidgetSet set;
    set.mainCreator = mainCreator;
    set.advancedCreator = advancedCreator;
    m_widgets[cipherId] = set;
}

void CipherWidgetFactory::createMainWidgets(int cipherId, QWidget* parent,
                                           QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)
{
    if (m_widgets.contains(cipherId) && m_widgets[cipherId].mainCreator) {
        m_widgets[cipherId].mainCreator(parent, layout, widgets);
    }
}

void CipherWidgetFactory::createAdvancedWidgets(int cipherId, QWidget* parent,
                                               QVBoxLayout* layout, QMap<QString, QWidget*>& widgets)
{
    if (m_widgets.contains(cipherId) && m_widgets[cipherId].advancedCreator) {
        m_widgets[cipherId].advancedCreator(parent, layout, widgets);
    }
}

bool CipherWidgetFactory::hasAdvancedWidgets(int cipherId) const
{
    return m_widgets.contains(cipherId) && m_widgets[cipherId].advancedCreator != nullptr;
}


QVariantMap CipherWidgetFactory::collectValues(const QMap<QString, QWidget*>& widgets)
{
    QVariantMap params;

    for (auto it = widgets.constBegin(); it != widgets.constEnd(); ++it) {
        QString paramId = it.key();
        QWidget* widget = it.value();

        // Добавьте эту проверку ПЕРЕД стандартными виджетами
        if (RouteCipherAdvancedWidget* advancedWidget = qobject_cast<RouteCipherAdvancedWidget*>(widget)) {
            // Получаем все параметры из расширенного виджета
            QVariantMap advancedParams = advancedWidget->getParameters();

            // Добавляем каждый параметр в общую карту
            for (auto advIt = advancedParams.constBegin(); advIt != advancedParams.constEnd(); ++advIt) {
                params[advIt.key()] = advIt.value();
                qDebug() << "CipherWidgetFactory: добавил параметр" << advIt.key() << "=" << advIt.value();
            }
        }
        else if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(widget)) {
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
            params[paramId] = comboBox->currentData();
        }
        else if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(widget)) {
            params[paramId] = checkBox->isChecked();
        }
        else if (ECCPointEdit* pointEdit = qobject_cast<ECCPointEdit*>(widget)) {
            ECPoint point = pointEdit->getPoint();
            if (!point.isInfinity) {
                params[paramId] = QString("(%1,%2)").arg(point.x).arg(point.y);
            } else {
                params[paramId] = "inf";
            }
        }
    }

    return params;
}

void CipherWidgetFactory::updateWidgets(const QMap<QString, QWidget*>& widgets, const QVariantMap& values)
{
    for (auto it = widgets.constBegin(); it != widgets.constEnd(); ++it) {
        QString paramId = it.key();
        QWidget* widget = it.value();

        // Для RouteCipherAdvancedWidget
        if (RouteCipherAdvancedWidget* advancedWidget = qobject_cast<RouteCipherAdvancedWidget*>(widget)) {
            if (values.contains("rows")) {
                advancedWidget->setRows(values["rows"].toInt());
            }
            if (values.contains("cols")) {
                advancedWidget->setCols(values["cols"].toInt());
            }
            // ... остальные параметры
        }
        else if (QSpinBox* spinBox = qobject_cast<QSpinBox*>(widget)) {
            if (values.contains(paramId)) {
                spinBox->setValue(values[paramId].toInt());
            }
        }
        // ============ ДОБАВИТЬ ЭТУ ВЕТКУ ============
        else if (QLineEdit* lineEdit = qobject_cast<QLineEdit*>(widget)) {
            if (values.contains(paramId)) {
                lineEdit->setText(values[paramId].toString());
            }
        }
        // ==========================================
        else if (QTextEdit* textEdit = qobject_cast<QTextEdit*>(widget)) {
            if (values.contains(paramId)) {
                textEdit->setPlainText(values[paramId].toString());
            }
        }
        else if (QComboBox* comboBox = qobject_cast<QComboBox*>(widget)) {
            if (values.contains(paramId)) {
                int idx = comboBox->findData(values[paramId]);
                if (idx >= 0) comboBox->setCurrentIndex(idx);
            }
        }
        else if (QCheckBox* checkBox = qobject_cast<QCheckBox*>(widget)) {
            if (values.contains(paramId)) {
                checkBox->setChecked(values[paramId].toBool());
            }
        }
        else if (ECCPointEdit* pointEdit = qobject_cast<ECCPointEdit*>(widget)) {
            if (values.contains(paramId)) {
                // Разбираем строку вида "(x,y)"
                QString str = values[paramId].toString();
                if (str == "inf") {
                    pointEdit->setPoint(ECPoint());
                } else {
                    QRegularExpression regex("\\((\\d+),(\\d+)\\)");
                    QRegularExpressionMatch match = regex.match(str);
                    if (match.hasMatch()) {
                        ECPoint point(match.captured(1).toULongLong(),
                                      match.captured(2).toULongLong());
                        pointEdit->setPoint(point);
                    }
                }
            }
        }
    }
}
