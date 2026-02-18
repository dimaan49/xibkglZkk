#include "routecipher.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "routecipherwidget.h"
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
                                                     normalizedRowOrder, cols, fillSteps);

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
    // Очищаем текст
    QString cleanText = CipherUtils::filterAlphabetOnly(text,
        QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));

    // Получаем размеры из параметров
    int rows = params.value("rows", 0).toInt();
    int cols = params.value("cols", 0).toInt();

    // Если размеры не указаны (0) - определяем автоматически
    if (rows <= 0 || cols <= 0) {
        calculateOptimalSize(cleanText.length(), rows, cols);
    }

    // Получаем направления записи
    QVector<Direction> writeDirections;
    if (params.contains("writeDirections")) {
        QVariantList dirList = params.value("writeDirections").toList();
        for (const QVariant& v : dirList) {
            writeDirections.append(static_cast<Direction>(v.toInt()));
        }
    } else {
        writeDirections = getDefaultWriteDirections(rows);
    }

    // Получаем направления чтения
    QVector<Direction> readDirections;
    if (params.contains("readDirections")) {
        QVariantList dirList = params.value("readDirections").toList();
        for (const QVariant& v : dirList) {
            readDirections.append(static_cast<Direction>(v.toInt()));
        }
    } else {
        readDirections = getDefaultReadDirections(cols);
    }

    // Получаем порядок строк
    QVector<int> rowOrder;
    if (params.contains("rowOrder")) {
        QVariantList orderList = params.value("rowOrder").toList();
        for (const QVariant& v : orderList) {
            rowOrder.append(v.toInt());
        }
    }

    // Получаем порядок столбцов
    QVector<int> columnOrder;
    if (params.contains("columnOrder")) {
        QVariantList orderList = params.value("columnOrder").toList();
        for (const QVariant& v : orderList) {
            columnOrder.append(v.toInt());
        }
    }

    // Выполняем шифрование с полученными параметрами
    return encryptImpl(cleanText, rows, cols, writeDirections, readDirections,
                      rowOrder, columnOrder);
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
        qDebug() << "=== calculateOptimalSize: параметры уже заданы ===";
        qDebug() << "Заданные rows:" << optimalRows << "cols:" << optimalCols;
        qDebug() << "Произведение:" << optimalRows * optimalCols << ">= textLength:" << textLength;
        qDebug() << "============================================\n";
        return;
    }

    qDebug() << "\n*** calculateOptimalSize: поиск оптимального размера сетки ***";
    qDebug() << "Исходные данные: textLength =" << textLength;

    int bestRows = 0, bestCols = 0;
    int minWaste = INT_MAX;
    double minDistanceToSqrt = std::numeric_limits<double>::max(); // минимальное расстояние до квадратного корня

    // Вычисляем квадратный корень
    double sqrtVal = std::sqrt(textLength);
    int start = static_cast<int>(sqrtVal);

    qDebug() << "Квадратный корень из" << textLength << "=" << sqrtVal;
    qDebug() << "Начинаем поиск с r =" << start << "\n";

    qDebug() << "Перебираем варианты:";
    qDebug() << "----------------------------------------------------------------------------------------";
    qDebug() << "r\tc\tcapacity\twaste\tсреднее(r,c)\t|среднее-√N|\tприоритет\t\t\tстатус";
    qDebug() << "----------------------------------------------------------------------------------------";

    // Перебираем значения вокруг квадратного корня
    for (int offset = 0; offset <= textLength; ++offset) {
        // Проверяем r = start - offset и r = start + offset
        for (int r : {start - offset, start + offset}) {
            if (r < 1 || r > textLength) continue;

            int c = (textLength + r - 1) / r; // ceil(textLength / r)
            int capacity = r * c;
            int waste = capacity - textLength;

            double avg = (r + c) / 2.0; // среднее арифметическое между r и c
            double distanceToSqrt = std::abs(avg - sqrtVal);

            QString priority;
            bool isBetter = false;

            // Проверяем, является ли этот вариант лучше текущего лучшего
            if (bestRows == 0) {
                // Первый найденный вариант
                priority = "ПЕРВЫЙ";
                isBetter = true;
            } else {
                double bestAvg = (bestRows + bestCols) / 2.0;
                double bestDistanceToSqrt = std::abs(bestAvg - sqrtVal);

                if (std::abs(distanceToSqrt - bestDistanceToSqrt) < 0.000001) { // равное расстояние
                    if (waste < minWaste) {
                        priority = "ЛУЧШЕ (меньше потерь при равной близости)";
                        isBetter = true;
                    } else {
                        priority = "хуже (больше потерь при равной близости)";
                    }
                } else if (distanceToSqrt < bestDistanceToSqrt) {
                    priority = "ЛУЧШЕ (ближе к √N)";
                    isBetter = true;
                } else {
                    priority = "хуже (дальше от √N)";
                }
            }

            QString status = isBetter ? "НОВЫЙ ЛУЧШИЙ ✓" : "пропускаем ✗";

            qDebug() << r << "\t" << c << "\t" << capacity << "\t\t" << waste
                     << "\t" << QString::number(avg, 'f', 2)
                     << "\t\t" << QString::number(distanceToSqrt, 'f', 2)
                     << "\t\t" << priority.leftJustified(30)
                     << "\t" << status;

            if (isBetter) {
                minWaste = waste;
                minDistanceToSqrt = distanceToSqrt;
                bestRows = r;
                bestCols = c;
            }
        }

        // Если уже нашли вариант на этом offset и расстояние увеличивается, можно остановиться
        if (bestRows != 0 && offset > std::abs(bestRows - start) + 2) {
            qDebug() << "----------------------------------------------------------------------------------------";
            qDebug() << "Останавливаем поиск (найден оптимум)";
            break;
        }
    }

    qDebug() << "----------------------------------------------------------------------------------------\n";

    // Если ничего не нашли, используем квадрат
    if (bestRows == 0 || bestCols == 0) {
        qDebug() << "!!! Решение не найдено, используем запасной вариант !!!";
        optimalRows = optimalCols = static_cast<int>(std::ceil(sqrtVal));
        if (optimalRows * optimalCols < textLength) {
            optimalCols++;
        }
    } else {
        optimalRows = bestRows;
        optimalCols = bestCols;
    }

    double finalAvg = (optimalRows + optimalCols) / 2.0;
    qDebug() << "\n*** РЕЗУЛЬТАТ ***";
    qDebug() << "Оптимальные размеры: rows =" << optimalRows << "cols =" << optimalCols;
    qDebug() << "Произведение:" << optimalRows * optimalCols << ">= textLength:" << textLength;
    qDebug() << "Потери (waste):" << optimalRows * optimalCols - textLength;
    qDebug() << "Среднее (rows+cols)/2:" << QString::number(finalAvg, 'f', 2) << "√N:" << QString::number(sqrtVal, 'f', 2);
    qDebug() << "Расстояние до √N:" << QString::number(std::abs(finalAvg - sqrtVal), 'f', 2);
    qDebug() << "****************************************\n";
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
                                                      int cols,
                                                      QVector<CipherStep>& steps) const {
    int rows = rowOrder.size();
    if (rows == 0) return std::vector<std::vector<QChar>>();

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
        // Основной виджет
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // может быть пусто
        },
        // Расширенный виджет
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            RouteCipherAdvancedWidget* advancedWidget = new RouteCipherAdvancedWidget(parent);
            layout->addWidget(advancedWidget);
            widgets["routeAdvancedWidget"] = advancedWidget;
            qDebug() << "RouteCipherAdvancedWidget created and registered";
        }
    );
}

// Статический регистратор
static RouteCipherRegister routeCipherRegister;


void RouteCipher::getOptimalSize(int textLength, int& rows, int& cols) const
{
    calculateOptimalSize(textLength, rows, cols);
}
