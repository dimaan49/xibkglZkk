#ifndef SHANNONPAD_H
#define SHANNONPAD_H

#include "cipherinterface.h"
#include "ciphercore.h"
#include <QVector>
#include <QRegularExpression>

// Класс шифра Одноразовый блокнот Шеннона (НЕ наследник QObject)
class ShannonPadCipher : public CipherInterface
{
public:
    ShannonPadCipher();
    virtual ~ShannonPadCipher() = default;

    // CipherInterface interface
    virtual QString name() const override { return "Одноразовый блокнот Шеннона"; }
    virtual QString description() const override { return "Потоковый шифр с линейным конгруэнтным генератором (гаммирование)"; }
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;

    // Константы
    static const int ALPHABET_SIZE = 32; // Размер русского алфавита (А-Я без Ё)

private:
    CipherResult process(const QString& text, const QVariantMap& params, bool encrypt);
    bool validateParameters(int t0, int a, int c, QString& errorMessage);
    QVector<int> generateGamma(int length, int t0, int a, int c);
    QString m_alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
};

// Класс для регистрации шифра в фабриках
class ShannonPadCipherRegister
{
public:
    ShannonPadCipherRegister();
};

// Валидатор для полей ввода (подсвечивает красным при ошибке)
class ValidatedLineEdit : public QLineEdit
{
    Q_OBJECT

public:
    ValidatedLineEdit(QWidget* parent = nullptr);
    void setValid(bool valid);
    bool isValid() const { return m_valid; }

protected:
    void focusInEvent(QFocusEvent* event) override;

private:
    bool m_valid = true;
    QString m_originalStyle;
};

#endif // SHANNONPAD_H
