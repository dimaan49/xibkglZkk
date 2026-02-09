#ifndef CIPHERCORE_H
#define CIPHERCORE_H

#include <QString>
#include <QVector>
#include <QChar>
#include <QLineEdit>
#include <QKeyEvent>

// БАЗА
// Шаг преобразования одного символа
struct CipherStep {
    int index;
    QChar originalChar;
    QString resultValue;
    QString description;

    CipherStep(int idx = -1,
               QChar orig = QChar(),
               const QString& result = QString(),
               const QString& desc = QString())
        : index(idx),
          originalChar(orig),
          resultValue(result),
          description(desc)
    {}
};

// Полный результат шифрования
struct CipherResult {
    QString result;
    QVector<CipherStep> steps;
    QString alphabet;
    QString cipherName;
    bool isNumeric;

    CipherResult(const QString& res = QString(),
                 const QVector<CipherStep>& st = QVector<CipherStep>(),
                 const QString& alph = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"),
                 const QString& name = QStringLiteral(u"Атбаш"),
                 bool numeric = false)
        : result(res),
          steps(st),
          alphabet(alph),
          cipherName(name),
          isNumeric(numeric)
    {}
};

namespace CipherUtils {
    // Убирает все неалфавитные символы (только русские буквы)
    static QString filterAlphabetOnly(const QString& text, const QString& alphabet) {
        QString result;
        for (QChar ch : text.toUpper()) {
            if (alphabet.contains(ch)) {
                result.append(ch);
            }
        }
        return result;
    }
}


// КАРДАНО
struct GridRotationStep {
    int rotationNumber;
    std::vector<std::vector<bool>> grid;
    QString placedChars;
    QString description;

    GridRotationStep(int num = 0,
                    const std::vector<std::vector<bool>>& g = {},
                    const QString& chars = QString(),
                    const QString& desc = QString())
        : rotationNumber(num), grid(g), placedChars(chars), description(desc) {}
};


enum Direction {
    LEFT_TO_RIGHT,    // Слева направо
    RIGHT_TO_LEFT,    // Справа налево
    TOP_TO_BOTTOM,    // Сверху вниз
    BOTTOM_TO_TOP     // Снизу вверх
};

// Шаг маршрутной перестановки
struct RouteStep {
    int stepNumber;
    QString action;  // "Запись" или "Чтение"
    QString route;   // Описание маршрута
    QString placed;  // Размещенные символы
    QString matrix;  // Состояние матрицы

    RouteStep(int num = 0,
             const QString& act = QString(),
             const QString& rt = QString(),
             const QString& pl = QString(),
             const QString& mat = QString())
        : stepNumber(num), action(act), route(rt), placed(pl), matrix(mat) {}
};

// Структура конфигурации для RouteCipher
struct RouteCipherConfig {
    int rows = 0;
    int cols = 0;
    QVector<Direction> writeDirections;  // Направления записи по строкам
    QVector<Direction> readDirections;   // Направления чтения по столбцам
    QVector<int> columnOrder;            // Порядок столбцов (пусто = обычный порядок)
    QVector<int> rowOrder;               // Порядок строк (пусто = обычный порядок)

    RouteCipherConfig() = default;

    // Вспомогательные конструкторы
    static RouteCipherConfig createSimple(int r, int c,
                                         Direction writeDir = LEFT_TO_RIGHT,
                                         Direction readDir = TOP_TO_BOTTOM) {
        RouteCipherConfig config;
        config.rows = r;
        config.cols = c;
        for (int i = 0; i < r; ++i) {
            config.writeDirections.append(writeDir);
        }
        for (int i = 0; i < c; ++i) {
            config.readDirections.append(readDir);
        }
        return config;
    }

    static RouteCipherConfig createSnake(int r, int c,
                                        Direction readDir = TOP_TO_BOTTOM) {
        RouteCipherConfig config;
        config.rows = r;
        config.cols = c;
        for (int i = 0; i < r; ++i) {
            config.writeDirections.append((i % 2 == 0) ? LEFT_TO_RIGHT : RIGHT_TO_LEFT);
        }
        for (int i = 0; i < c; ++i) {
            config.readDirections.append(readDir);
        }
        return config;
    }
};



// Матричные операции (inline реализации)
namespace MatrixUtils {
    // Преобразование числа в строку фиксированной длины
    inline QString numberToString(int num, int width = 3) {
        return QString("%1").arg(num, width, 10, QChar(' '));
    }

    // Преобразование вектора чисел в строку
    inline QString vectorToString(const QVector<int>& vec, int width = 3) {
        QString result;
        for (int i = 0; i < vec.size(); ++i) {
            if (i > 0) result += " ";
            result += numberToString(vec[i], width);
        }
        return result;
    }

    // Преобразование матрицы в строку
    inline QString matrixToString(const QVector<QVector<int>>& matrix, int width = 3) {
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

    // Проверка, является ли матрица квадратной
    inline bool isSquareMatrix(const QVector<QVector<int>>& matrix) {
        if (matrix.isEmpty()) return false;

        int rows = matrix.size();
        for (const auto& row : matrix) {
            if (row.size() != rows) {
                return false;
            }
        }

        return true;
    }

    // Умножение матрицы на вектор
    inline QVector<int> multiplyMatrixVector(const QVector<QVector<int>>& matrix,
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
    inline int determinant(const QVector<QVector<int>>& matrix) {
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
    inline QVector<QVector<int>> identityMatrix(int size) {
        QVector<QVector<int>> identity(size, QVector<int>(size, 0));

        for (int i = 0; i < size; ++i) {
            identity[i][i] = 1;
        }

        return identity;
    }

    // Вычисление обратной матрицы
    inline QVector<QVector<int>> inverseMatrix(const QVector<QVector<int>>& matrix) {
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
            // Для матрицы 1x1
            QVector<QVector<int>> inverse(1, QVector<int>(1));
            inverse[0][0] = 1; // В целых числах
            return inverse;
        }

        // Матрица алгебраических дополнений
        QVector<QVector<int>> cofactors(n, QVector<int>(n));

        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                // Создаем минор
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

                // Алгебраическое дополнение
                int minorDet = determinant(minor);
                int sign = ((i + j) % 2 == 0) ? 1 : -1;
                cofactors[i][j] = sign * minorDet;
            }
        }

        // Транспонируем (присоединенная матрица)
        QVector<QVector<int>> adjugate(n, QVector<int>(n));
        for (int i = 0; i < n; ++i) {
            for (int j = 0; j < n; ++j) {
                adjugate[j][i] = cofactors[i][j];
            }
        }

        // Для целых чисел просто возвращаем присоединенную матрицу
        // (деление на определитель не выполняется)
        return adjugate;
    }
};




#endif // CIPHERCORE_H
