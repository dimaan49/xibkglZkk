#ifndef MATRIXCIPHER_H
#define MATRIXCIPHER_H

#include "cipherinterface.h"
#include <QVector>

class MatrixCipher : public CipherInterface
{
public:
    MatrixCipher();

    // CipherInterface interface
    virtual CipherResult encrypt(const QString& text, const QVariantMap& params) override;
    virtual CipherResult decrypt(const QString& text, const QVariantMap& params) override;
    virtual QString name() const override;
    virtual QString description() const override;
    QString alphabet() const override {return m_alphabet; }

    // Константы
    QString m_alphabet = CipherUtils::RUSSIAN_ALPHABET_32;
    static const int ALPHABET_SIZE = 32;

    // Вспомогательные методы (публичные для доступа из регистратора)
    static bool checkMatrix(const QString& matrixStr, QString& resultMessage, int& det, int& size);

private:

    CipherResult process(const QString& text, const QVariantMap& params, bool encrypt);
    QString formatMatrix(const QVector<QVector<int>>& matrix);
    QString formatMatrixDouble(const QVector<QVector<double>>& matrix);
    QString formatVector(const QVector<int>& vec);
    // Вспомогательные методы
    static bool parseMatrix(const QString& matrixStr, QVector<QVector<int>>& matrix);
    static bool isInvertible(const QVector<QVector<int>>& matrix, int& det);
    static int calculateDeterminant(const QVector<QVector<int>>& matrix);
    static int calculateMinor(const QVector<QVector<int>>& matrix, int row, int col);
    static bool calculateInverse(const QVector<QVector<int>>& matrix, QVector<QVector<double>>& inverse, int det);

    static QVector<int> multiplyMatrixVector(const QVector<QVector<int>>& matrix, const QVector<int>& vector);
    static QVector<double> multiplyMatrixVectorDouble(const QVector<QVector<double>>& matrix, const QVector<int>& vector);
    static QVector<int> roundToInt(const QVector<double>& numbers);
    static QString formatNumbers(const QVector<int>& numbers);
    static QVector<int> parseNumbers(const QString& text);
};

// Регистратор
class MatrixCipherRegister
{
public:
    MatrixCipherRegister();
};

#endif // MATRIXCIPHER_H
