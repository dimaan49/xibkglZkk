#include "numberlineedit.h"

NumberLineEdit::NumberLineEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression numRegex("^[0-9]{0,20}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(numRegex, this);
    setValidator(validator);

    setPlaceholderText("Введите число");
}

void NumberLineEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("NumberLineEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void NumberLineEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

uint64_t NumberLineEdit::getValue() const
{
    QString text = this->text();
    if (text.isEmpty()) return 0;
    bool ok;
    uint64_t value = text.toULongLong(&ok);
    return ok ? value : 0;
}

void NumberLineEdit::setValue(uint64_t value)
{
    setText(QString::number(value));
}
