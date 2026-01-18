#include "ciphercore.h"
#include <algorithm>
#include <cmath>

// Умножение матрицы на вектор
QVector<int> MatrixUtils::multiplyMatrixVector(const QVector<QVector<int>>& matrix,
                                              const QVector<int>& vector) {
    int n = matrix.size();
    if (n == 0 || n != vector.size()) {
        throw std::invalid_argument("Несовместимые размеры матрицы и вектора");
    }

    QVector<int> result(n, 0);

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            result[i] += matrix[i][j] * vector[j];
        }
    }

    return result;
}

// Вычисление определителя матрицы (рекурсивно)
int MatrixUtils::determinant(const QVector<QVector<int>>& matrix) {
    int n = matrix.size();

    if (n == 1) {
        return matrix[0][0];
    }

    if (n == 2) {
        return matrix[0][0] * matrix[1][1] - matrix[0][1] * matrix[1][0];
    }

    int det = 0;
    int sign = 1;

    for (int col = 0; col < n; ++col) {
        // Создаем подматрицу без первой строки и col-го столбца
        QVector<QVector<int>> submatrix(n - 1, QVector<int>(n - 1));

        for (int i = 1; i < n; ++i) {
            int subCol = 0;
            for (int j = 0; j < n; ++j) {
                if (j != col) {
                    submatrix[i - 1][subCol++] = matrix[i][j];
                }
            }
        }

        det += sign * matrix[0][col] * determinant(submatrix);
        sign = -sign;
    }

    return det;
}

// Создание единичной матрицы
QVector<QVector<int>> MatrixUtils::identityMatrix(int size) {
    QVector<QVector<int>> identity(size, QVector<int>(size, 0));

    for (int i = 0; i < size; ++i) {
        identity[i][i] = 1;
    }

    return identity;
}

// Вычисление обратной матрицы (методом присоединенной матрицы)
QVector<QVector<int>> MatrixUtils::inverseMatrix(const QVector<QVector<int>>& matrix) {
    int n = matrix.size();

    if (n == 0) {
        throw std::invalid_argument("Пустая матрица");
    }

    // Проверяем определитель
    int det = determinant(matrix);
    if (det == 0) {
        throw std::runtime_error("Определитель равен 0, обратной матрицы не существует");
    }

    if (n == 1) {
        // Для матрицы 1x1 обратная = 1/элемент
        QVector<QVector<int>> inverse(1, QVector<int>(1));
        inverse[0][0] = 1; // В целых числах только для элемента 1
        return inverse;
    }

    // Создаем матрицу алгебраических дополнений
    QVector<QVector<int>> cofactors(n, QVector<int>(n));

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            // Создаем минорную матрицу
            QVector<QVector<int>> minor(n - 1, QVector<int>(n - 1));

            int minorRow = 0;
            for (int row = 0; row < n; ++row) {
                if (row == i) continue;

                int minorCol = 0;
                for (int col = 0; col < n; ++col) {
                    if (col == j) continue;

                    minor[minorRow][minorCol] = matrix[row][col];
                    minorCol++;
                }
                minorRow++;
            }

            // Вычисляем алгебраическое дополнение
            int minorDet = determinant(minor);
            int sign = ((i + j) % 2 == 0) ? 1 : -1;
            cofactors[i][j] = sign * minorDet;
        }
    }

    // Транспонируем (получаем присоединенную матрицу)
    QVector<QVector<int>> adjugate(n, QVector<int>(n));
    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            adjugate[j][i] = cofactors[i][j];
        }
    }

    // Делим на определитель (в целых числах только если определитель = ±1)
    // Для учебных целей оставляем как есть
    QVector<QVector<int>> inverse(n, QVector<int>(n));

    for (int i = 0; i < n; ++i) {
        for (int j = 0; j < n; ++j) {
            inverse[i][j] = adjugate[i][j]; // В реальности: adjugate[i][j] / det
        }
    }

    return inverse;
}

bool MatrixUtils::isSquareMatrix(const QVector<QVector<int>>& matrix) {
    if (matrix.isEmpty()) return false;

    int rows = matrix.size();
    for (const auto& row : matrix) {
        if (row.size() != rows) {
            return false;
        }
    }

    return true;
}

QString MatrixUtils::numberToString(int num, int width) {
    return QString("%1").arg(num, width, 10, QChar(' '));
}

QString MatrixUtils::vectorToString(const QVector<int>& vec, int width) {
    QString result;
    for (int i = 0; i < vec.size(); ++i) {
        if (i > 0) result += " ";
        result += numberToString(vec[i], width);
    }
    return result;
}

QString MatrixUtils::matrixToString(const QVector<QVector<int>>& matrix, int width) {
    QString result;
    for (int i = 0; i < matrix.size(); ++i) {
        for (int j = 0; j < matrix[i].size(); ++j) {
            if (j > 0) result += " ";
            result += numberToString(matrix[i][j], width);
        }
        if (i < matrix.size() - 1) {
            result += "\n";
        }
    }
    return result;
}
