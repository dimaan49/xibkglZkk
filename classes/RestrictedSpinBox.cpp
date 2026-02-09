// restrictedspinbox.cpp
#include "restrictedspinbox.h"

RestrictedSpinBox::RestrictedSpinBox(QWidget* parent)
    : QSpinBox(parent)
{
}

void RestrictedSpinBox::keyPressEvent(QKeyEvent* event)
{
    // Обрабатываем только цифровые клавиши, Backspace и Delete
    if (event->key() >= Qt::Key_0 && event->key() <= Qt::Key_9) {
        QString currentText = text();
        int cursorPos = lineEdit()->cursorPosition();

        QString testText = currentText;
        testText.insert(cursorPos, event->text());

        bool ok;
        int testValue = testText.toInt(&ok);

        // Проверяем, что значение в допустимом диапазоне
        if (ok && (testValue < minimum() || testValue > maximum())) {
            // Значение вне диапазона - игнорируем ввод
            return;
        }
    }

    QSpinBox::keyPressEvent(event);
}
