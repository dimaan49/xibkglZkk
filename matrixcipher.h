#ifndef MATRIXCIPHER_H
#define MATRIXCIPHER_H

#include "ciphercore.h"
#include <QVector>
#include <QString>

class MatrixCipher {
private:
    QVector<QVector<int>> keyMatrix;      // Ключевая матрица
    QVector<QVector<int>> inverseMatrix;  // Обратная матрица (для дешифрования)
    int blockSize;                        // Размер блока = размер матрицы
    bool hasValidInverse;                 // Есть ли обратная матрица

    // Вспомогательные методы
    QVector<int> textToNumbers(const QString& text) const;
    QString numbersToText(const QVector<int>& numbers) const;
    QVector<QVector<int>> splitIntoBlocks(const QVector<int>& numbers) const;
    QVector<int> combineBlocks(const QVector<QVector<int>>& blocks) const;
    void calculateInverseMatrix();
    QString formatNumber(int num) const;

public:
    // Конструктор с ключевой матрицей
    MatrixCipher(const QVector<QVector<int>>& matrix);

    // Шифрование
    CipherResult encrypt(const QString& text);

    // Дешифрование
    CipherResult decrypt(const QString& text);

    // Информация о матрице
    QString getKeyMatrixString() const;
    QString getInverseMatrixString() const;
    bool hasValidKey() const;

    QString name() const;
    QString description() const;
};

#endif // MATRIXCIPHER_H
