#include "routecipher.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <algorithm>
#include <cmath>
#include <QDebug>

RouteCipher::RouteCipher()
{
}


// Внутренний основной метод
CipherResult RouteCipher::encryptImpl(const QString& text,
                                     int rows, int cols,
                                     const QVector<Direction>& writeDirections,
                                     const QVector<Direction>& readDirections,
                                     const QVector<int>& rowOrder,
                                     const QVector<int>& columnOrder) {
    QVector<CipherStep> steps;

    // Шаг 1: Очистка текста
    QString cleanText = CipherUtils::filterAlphabetOnly(text,
        QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));

    steps.append(CipherStep(1, QChar(), cleanText, QStringLiteral(u"Очищенный текст")));

    // Шаг 2: Определение размера таблицы
    int actualRows = rows, actualCols = cols;
    calculateOptimalSize(cleanText.length(), actualRows, actualCols);

    steps.append(CipherStep(2, QChar(),
        QString("%1×%2").arg(actualRows).arg(actualCols),
        QStringLiteral(u"Размер таблицы")));

    rows = actualRows;
    cols = actualCols;

    // Нормализуем порядки
    QVector<int> normalizedRowOrder = normalizeOrder(rowOrder, rows, "строк");
    QVector<int> normalizedColumnOrder = normalizeOrder(columnOrder, cols, "столбцов");

    // Шаг 3: Заполнение таблицы
    QVector<CipherStep> fillSteps;
    std::vector<std::vector<QChar>> table = fillTable(cleanText, writeDirections,
                                                     normalizedRowOrder, fillSteps);

    // Добавляем шаги заполнения
    for (const auto& step : fillSteps) {
        steps.append(step);
    }

    // Шаг 4: Отображение таблицы
    steps.append(CipherStep(steps.size() + 1, QChar(),
        tableToString(table), QStringLiteral(u"Заполненная таблица")));

    // Шаг 5: Чтение таблицы
    QVector<CipherStep> readSteps;
    QString encrypted = readTable(table, readDirections, normalizedColumnOrder, readSteps);

    // Добавляем шаги чтения
    for (const auto& step : readSteps) {
        steps.append(step);
    }

    // Шаг 6: Итоговый результат
    steps.append(CipherStep(steps.size() + 1, QChar(),
        encrypted, QStringLiteral(u"Итоговый шифртекст")));

    // Перенумеровываем шаги
    for (int i = 0; i < steps.size(); ++i) {
        steps[i].index = i + 1;
    }

    // Формируем описание
    QString description = QStringLiteral(u"RouteCipher - Маршрутная перестановка\n")
                        + QStringLiteral(u"Размер таблицы: %1×%2\n").arg(rows).arg(cols);

    if (!normalizedRowOrder.isEmpty() && normalizedRowOrder != QVector<int>()) {
        description += QStringLiteral(u"Порядок строк: ");
        for (int i = 0; i < normalizedRowOrder.size(); ++i) {
            if (i > 0) description += ", ";
            description += QString::number(normalizedRowOrder[i]);
        }
        description += "\n";
    }

    if (!normalizedColumnOrder.isEmpty() && normalizedColumnOrder != QVector<int>()) {
        description += QStringLiteral(u"Порядок столбцов: ");
        for (int i = 0; i < normalizedColumnOrder.size(); ++i) {
            if (i > 0) description += ", ";
            description += QString::number(normalizedColumnOrder[i]);
        }
        description += "\n";
    }

    return CipherResult(encrypted, steps, description, name(), false);
}

QVector<Direction> RouteCipher::getDefaultWriteDirections(int rows) const
{
    QVector<Direction> directions;
    // Змейка: чередование направлений
    for (int i = 0; i < rows; ++i) {
        directions.append((i % 2 == 0) ? LEFT_TO_RIGHT : RIGHT_TO_LEFT);
    }
    return directions;
}

QVector<Direction> RouteCipher::getDefaultReadDirections(int cols) const
{
    QVector<Direction> directions(cols, TOP_TO_BOTTOM);
    return directions;
}

CipherResult RouteCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params); // Параметры не используются

    // Автоматически определяем размер таблицы
    QString cleanText = CipherUtils::filterAlphabetOnly(text,
        QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));

    int rows = 0, cols = 0;
    calculateOptimalSize(cleanText.length(), rows, cols);

    // Получаем направления по умолчанию
    QVector<Direction> writeDirections = getDefaultWriteDirections(rows);
    QVector<Direction> readDirections = getDefaultReadDirections(cols);

    // Используем порядок по умолчанию
    QVector<int> rowOrder, columnOrder;

    return encryptImpl(cleanText, rows, cols, writeDirections, readDirections, rowOrder, columnOrder);
}

CipherResult RouteCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);
    Q_UNUSED(text);

    QVector<CipherStep> steps;
    steps.append(CipherStep(1, QChar(),
        "Дешифрование RouteCipher",
        "Еще не реализовано"));

    return CipherResult(QString(), steps,
                       "Дешифрование RouteCipher",
                       name() + " (дешифрование)", false);
}

// Вспомогательные методы
void RouteCipher::calculateOptimalSize(int textLength, int& optimalRows, int& optimalCols) const {
    if (optimalRows > 0 && optimalCols > 0) {
        return;
    }

    int bestRows = 0, bestCols = 0;
    int minWaste = INT_MAX;

    for (int r = 2; r <= textLength; ++r) {
        for (int c = 2; c <= textLength; ++c) {
            int capacity = r * c;
            if (capacity >= textLength) {
                int waste = capacity - textLength;
                if (waste < minWaste || (waste == minWaste && abs(r - c) < abs(bestRows - bestCols))) {
                    minWaste = waste;
                    bestRows = r;
                    bestCols = c;
                }
            }
        }
    }

    if (bestRows == 0 || bestCols == 0) {
        optimalRows = optimalCols = static_cast<int>(std::ceil(std::sqrt(textLength)));
        if (optimalRows * optimalCols < textLength) {
            optimalCols++;
        }
    } else {
        optimalRows = bestRows;
        optimalCols = bestCols;
    }
}

QString RouteCipher::tableToString(const std::vector<std::vector<QChar>>& table) const {
    int r = static_cast<int>(table.size());
    if (r == 0) return QString();

    int c = static_cast<int>(table[0].size());
    QString result;

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            if (table[i][j].isNull()) {
                result += "·";
            } else {
                result += table[i][j];
            }
        }
        if (i < r - 1) result += "\n";
    }

    return result;
}

QVector<int> RouteCipher::normalizeOrder(const QVector<int>& order, int size,
                                        const QString& orderName) const {
    if (order.isEmpty()) {
        // Создаем порядок по умолчанию: 1,2,3,...,size
        QVector<int> defaultOrder;
        for (int i = 1; i <= size; ++i) {
            defaultOrder.append(i);
        }
        return defaultOrder;
    }

    // Проверяем, что порядок корректен
    QSet<int> usedNumbers;
    for (int num : order) {
        if (num < 1 || num > size) {
            qWarning() << "Неверный номер" << num << "в порядке" << orderName
                      << "должен быть от 1 до" << size;
            // Возвращаем порядок по умолчанию
            QVector<int> defaultOrder;
            for (int i = 1; i <= size; ++i) {
                defaultOrder.append(i);
            }
            return defaultOrder;
        }
        if (usedNumbers.contains(num)) {
            qWarning() << "Повторяющийся номер" << num << "в порядке" << orderName;
            QVector<int> defaultOrder;
            for (int i = 1; i <= size; ++i) {
                defaultOrder.append(i);
            }
            return defaultOrder;
        }
        usedNumbers.insert(num);
    }

    return order;
}

std::vector<std::vector<QChar>> RouteCipher::fillTable(const QString& text,
                                                      const QVector<Direction>& writeDirections,
                                                      const QVector<int>& rowOrder,
                                                      QVector<CipherStep>& steps) const {
    int rows = rowOrder.size();
    if (rows == 0) return std::vector<std::vector<QChar>>();

    int cols = 0;
    if (rows > 0) {
        // Определяем cols из размера таблицы (нужно передавать отдельно или вычислять)
        // Временно используем длину текста / rows
        cols = static_cast<int>(std::ceil(static_cast<double>(text.length()) / rows));
    }

    std::vector<std::vector<QChar>> table(rows, std::vector<QChar>(cols, QChar()));
    int textIndex = 0;

    // Создаем карту: порядковый номер строки -> индекс в таблице
    QVector<int> rowIndexByOrder(rows);
    for (int i = 0; i < rows; ++i) {
        rowIndexByOrder[rowOrder[i] - 1] = i;
    }

    for (int orderNum = 1; orderNum <= rows && textIndex < text.length(); ++orderNum) {
        int rowIdx = rowIndexByOrder[orderNum - 1];

        // Определяем направление для текущей строки
        Direction direction;
        if (rowIdx < writeDirections.size()) {
            direction = writeDirections[rowIdx];
        } else if (!writeDirections.isEmpty()) {
            direction = writeDirections.last();
        } else {
            direction = LEFT_TO_RIGHT;
        }

        QString rowChars;

        // Заполняем строку
        if (direction == LEFT_TO_RIGHT) {
            for (int j = 0; j < cols && textIndex < text.length(); ++j) {
                table[rowIdx][j] = text[textIndex];
                rowChars += text[textIndex];
                textIndex++;
            }
        } else {
            for (int j = cols - 1; j >= 0 && textIndex < text.length(); --j) {
                table[rowIdx][j] = text[textIndex];
                rowChars += text[textIndex];
                textIndex++;
            }
        }

        if (!rowChars.isEmpty()) {
            steps.append(CipherStep(
                steps.size() + 1,
                QChar(),
                rowChars,
                QString("Запись строки %1 (порядок %2): %3")
                    .arg(rowIdx + 1)
                    .arg(orderNum)
                    .arg(direction == LEFT_TO_RIGHT ? "слева направо" : "справа налево")
            ));
        }
    }

    return table;
}

QString RouteCipher::readTable(const std::vector<std::vector<QChar>>& table,
                              const QVector<Direction>& readDirections,
                              const QVector<int>& columnOrder,
                              QVector<CipherStep>& steps) const {
    int rows = static_cast<int>(table.size());
    if (rows == 0) return QString();

    int cols = static_cast<int>(table[0].size());
    QString result;

    // Создаем карту: порядковый номер столбца -> индекс в таблице
    QVector<int> colIndexByOrder(cols);
    for (int i = 0; i < cols; ++i) {
        colIndexByOrder[columnOrder[i] - 1] = i;
    }

    for (int orderNum = 1; orderNum <= cols; ++orderNum) {
        int colIdx = colIndexByOrder[orderNum - 1];

        // Определяем направление для текущего столбца
        Direction direction;
        if (colIdx < readDirections.size()) {
            direction = readDirections[colIdx];
        } else if (!readDirections.isEmpty()) {
            direction = readDirections.last();
        } else {
            direction = TOP_TO_BOTTOM;
        }

        QString columnChars;

        // Читаем столбец
        if (direction == TOP_TO_BOTTOM) {
            for (int i = 0; i < rows; ++i) {
                if (!table[i][colIdx].isNull()) {
                    result += table[i][colIdx];
                    columnChars += table[i][colIdx];
                }
            }
        } else {
            for (int i = rows - 1; i >= 0; --i) {
                if (!table[i][colIdx].isNull()) {
                    result += table[i][colIdx];
                    columnChars += table[i][colIdx];
                }
            }
        }

        if (!columnChars.isEmpty()) {
            steps.append(CipherStep(
                steps.size() + 1,
                QChar(),
                columnChars,
                QString("Чтение столбца %1 (порядок %2): %3")
                    .arg(colIdx + 1)
                    .arg(orderNum)
                    .arg(direction == TOP_TO_BOTTOM ? "сверху вниз" : "снизу вверх")
            ));
        }
    }

    return result;
}

QString RouteCipher::name() const {
    return QStringLiteral(u"RouteCipher");
}

QString RouteCipher::description() const {
    return QStringLiteral(u"Шифр маршрутной перестановки");
}


RouteCipherRegister::RouteCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "route",
        "Маршрутная перестановка",
        []() -> CipherInterface* { return new RouteCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "route",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(widgets);

            QLabel* infoLabel = new QLabel(
                "🔄 Автоматическая маршрутная перестановка\n\n"
                "• Размер таблицы определяется автоматически\n"
                "• Запись: змейкой (↱↰ чередование)\n"
                "• Чтение: сверху вниз (↓)\n"
                "• Без параметров"
            );
            infoLabel->setWordWrap(true);
            infoLabel->setStyleSheet(
                "QLabel {"
                "    padding: 10px;"
                "    background-color: rgba(0, 150, 255, 0.1);"
                "    border: 1px solid rgba(0, 150, 255, 0.3);"
                "    border-radius: 6px;"
                "}"
            );
            layout->addWidget(infoLabel);
        }
    );
}
