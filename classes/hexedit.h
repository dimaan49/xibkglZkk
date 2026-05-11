#ifndef HEXEDIT_H
#define HEXEDIT_H

#include <QLineEdit>
#include <QRegularExpression>
#include <QRegularExpressionValidator>

class HexEdit : public QLineEdit
{
    Q_OBJECT

public:
    explicit HexEdit(QWidget* parent = nullptr);

    void setValid(bool valid);
    bool isValid() const { return m_valid; }

    void setExpectedLength(int bytes);
    int expectedLength() const { return m_expectedBytes; }

    QString getHex() const;
    void setHex(const QString& hex);

    // Проверка HEX-строки (статическая, для использования без создания объекта)
    static bool isValidHex(const QString& hex);
    static QString normalizeHex(const QString& hex);

protected:
    void focusInEvent(QFocusEvent* event) override;
    void focusOutEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    int m_expectedBytes = 0;
    QString m_originalStyle;

    void updateStyle();
};

#endif // HEXEDIT_H
