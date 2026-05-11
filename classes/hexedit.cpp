#include "hexedit.h"

HexEdit::HexEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(hexRegex, this);
    setValidator(validator);

    setPlaceholderText("HEX (0-9, A-F)");
}

void HexEdit::updateStyle()
{
    if (!m_valid) {
        setStyleSheet("HexEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void HexEdit::setValid(bool valid)
{
    m_valid = valid;
    updateStyle();
}

void HexEdit::setExpectedLength(int bytes)
{
    m_expectedBytes = bytes;
    if (bytes > 0) {
        setPlaceholderText(QString("HEX (%1 байт, %2 символа)").arg(bytes).arg(bytes * 2));
        setMaxLength(bytes * 2);
    }
}

void HexEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

void HexEdit::focusOutEvent(QFocusEvent* event)
{
    QString txt = text().trimmed();
    if (!txt.isEmpty() && m_expectedBytes > 0 && txt.length() != m_expectedBytes * 2) {
        setValid(false);
        setToolTip(QString("Требуется %1 HEX-символов (%2 байт)").arg(m_expectedBytes * 2).arg(m_expectedBytes));
    } else {
        setValid(true);
    }
    QLineEdit::focusOutEvent(event);
}

QString HexEdit::getHex() const
{
    return text().trimmed().toUpper();
}

void HexEdit::setHex(const QString& hex)
{
    setText(hex.toUpper());
}

bool HexEdit::isValidHex(const QString& hex)
{
    static QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    return hexRegex.match(hex).hasMatch();
}

QString HexEdit::normalizeHex(const QString& hex)
{
    QString result;
    for (QChar ch : hex) {
        if ((ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') || (ch >= 'a' && ch <= 'f')) {
            result.append(ch.toUpper());
        }
    }
    return result;
}
