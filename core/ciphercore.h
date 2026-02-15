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











#endif // CIPHERCORE_H
