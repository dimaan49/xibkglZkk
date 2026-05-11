#ifndef NUMBERLINEEDIT_H
#define NUMBERLINEEDIT_H

#include <QLineEdit>
#include <QRegularExpression>
#include <QRegularExpressionValidator>

class NumberLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    explicit NumberLineEdit(QWidget* parent = nullptr);

    void setValid(bool valid);
    bool isValid() const { return m_valid; }

    uint64_t getValue() const;
    void setValue(uint64_t value);

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

#endif // NUMBERLINEEDIT_H
