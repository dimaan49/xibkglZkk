#ifndef MATRIXCIPHER_H
#define MATRIXCIPHER_H

#include "cipherinterface.h"
#include <QVector>
#include <QString>

class MatrixCipher : public CipherInterface
{
public:
    MatrixCipher();
    ~MatrixCipher() override = default;

    // CipherInterface implementation
    CipherResult encrypt(const QString& text, const QVariantMap& params = {}) override;
    CipherResult decrypt(const QString& text, const QVariantMap& params = {}) override;

    QString name() const override;
    QString description() const override;

private:
    // Алфавит (А-Я без Ё)
    static const QString ALPHABET;
    static const int ALPHABET_SIZE = 32;

    // Вспомогательные методы
    bool parseMatrix(const QString& matrixStr, QVector<QVector<int>>& matrix);
    bool isInvertible(const QVector<QVector<int>>& matrix, int& det);
    bool calculateInverse(const QVector<QVector<int>>& matrix, QVector<QVector<double>>& inverse, int det);

    // Математические операции
    int calculateDeterminant(const QVector<QVector<int>>& matrix);
    int calculateMinor(const QVector<QVector<int>>& matrix, int row, int col);
    QVector<int> multiplyMatrixVector(const QVector<QVector<int>>& matrix, const QVector<int>& vector);
    QVector<double> multiplyMatrixVectorDouble(const QVector<QVector<double>>& matrix, const QVector<int>& vector);
    QVector<int> roundToInt(const QVector<double>& numbers);

    // Преобразования текста
    QVector<int> textToNumbers(const QString& text);
    QString numbersToText(const QVector<int>& numbers);

    // Форматирование
    QString formatNumbers(const QVector<int>& numbers);
    QVector<int> parseNumbers(const QString& text);
};

// Класс для регистрации шифра
class MatrixCipherRegister
{
public:
    MatrixCipherRegister();
};

#endif // MATRIXCIPHER_H
