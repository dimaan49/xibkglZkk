#include "columnarcipher.h"
#include <algorithm>
#include <QPair>

ColumnarCipher::ColumnarCipher(int rows, int cols)
    : rows(rows), cols(cols) {
}

void ColumnarCipher::setTableSize(int rows, int cols) {
    this->rows = rows;
    this->cols = cols;
}

QVector<int> ColumnarCipher::keyToColumnOrder(const QString& key) const {
    QString cleanKey = key.toUpper().trimmed();
    if (cleanKey.isEmpty()) {
        return QVector<int>();
    }

    // Создаем пары (буква, исходная позиция)
    QVector<QPair<QChar, int>> pairs;
    for (int i = 0; i < cleanKey.length(); ++i) {
        pairs.append(qMakePair(cleanKey[i], i));
    }

    // Сортируем по алфавитному порядку
    std::sort(pairs.begin(), pairs.end(),
              [](const QPair<QChar, int>& a, const QPair<QChar, int>& b) {
                  static QString alphabet = "АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ";
                  int indexA = alphabet.indexOf(a.first);
                  int indexB = alphabet.indexOf(b.first);
                  if (indexA != indexB) {
                      return indexA < indexB;
                  }
                  // Если буквы одинаковые, сохраняем исходный порядок
                  return a.second < b.second;
              });

    // Присваиваем порядковые номера (начиная с 1)
    QVector<int> order(cleanKey.length(), 0);

    for (int i = 0; i < pairs.size(); ++i) {
        order[pairs[i].second] = i + 1;
    }

    return order;
}

RouteCipherConfig ColumnarCipher::createConfig(const QString& key,
                                              const QVector<Direction>& writeDirections,
                                              const QVector<Direction>& readDirections) const {
    RouteCipherConfig config;

    // Размер таблицы
    config.rows = this->rows;
    config.cols = this->cols;

    // Если cols не задан, используем длину ключа
    if (config.cols == 0 && !key.isEmpty()) {
        config.cols = key.length();
    }

    // Направления записи по строкам
    if (writeDirections.isEmpty()) {
        // По умолчанию: все строки слева направо
        for (int i = 0; i < config.rows; ++i) {
            config.writeDirections.append(LEFT_TO_RIGHT);
        }
    } else {
        config.writeDirections = writeDirections;
        // Если направлений меньше чем строк, дополняем последним направлением
        while (config.writeDirections.size() < config.rows) {
            config.writeDirections.append(config.writeDirections.isEmpty() ?
                                         LEFT_TO_RIGHT : config.writeDirections.last());
        }
    }

    // Направления чтения по столбцам
    if (readDirections.isEmpty()) {
        // По умолчанию: все столбцы сверху вниз
        for (int i = 0; i < config.cols; ++i) {
            config.readDirections.append(TOP_TO_BOTTOM);
        }
    } else {
        config.readDirections = readDirections;
        // Если направлений меньше чем столбцов, дополняем последним направлением
        while (config.readDirections.size() < config.cols) {
            config.readDirections.append(config.readDirections.isEmpty() ?
                                        TOP_TO_BOTTOM : config.readDirections.last());
        }
    }

    // Порядок столбцов из ключа
    config.columnOrder = keyToColumnOrder(key);

    // Порядок строк - обычный (1,2,3,...)
    config.rowOrder.clear();
    for (int i = 1; i <= config.rows; ++i) {
        config.rowOrder.append(i);
    }

    return config;
}

// Простой интерфейс: только текст и ключ
CipherResult ColumnarCipher::encrypt(const QString& text, const QString& key) {
    return encrypt(text, key, QVector<Direction>(), QVector<Direction>(), rows, cols);
}

// Полный интерфейс со всеми параметрами
CipherResult ColumnarCipher::encrypt(const QString& text, const QString& key,
                                    const QVector<Direction>& writeDirections,
                                    const QVector<Direction>& readDirections,
                                    int rows, int cols) {
    // Устанавливаем размер (если задан)
    if (rows > 0) this->rows = rows;
    if (cols > 0) this->cols = cols;

    // Создаем конфигурацию
    RouteCipherConfig config = createConfig(key, writeDirections, readDirections);

    // Добавляем предварительные шаги
    QVector<CipherStep> allSteps;

    // Шаг 1: Очищенный текст
    QString cleanText = CipherUtils::filterAlphabetOnly(text,
        QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));

    allSteps.append(CipherStep(1, QChar(), cleanText,
        QStringLiteral(u"Очищенный текст")));

    // Шаг 2: Ключ
    allSteps.append(CipherStep(2, QChar(), key.toUpper(),
        QStringLiteral(u"Ключевое слово")));

    // Шаг 3: Порядок столбцов
    QVector<int> columnOrder = keyToColumnOrder(key);
    QString orderStr;
    for (int i = 0; i < columnOrder.size(); ++i) {
        if (!orderStr.isEmpty()) orderStr += " ";
        orderStr += QString::number(columnOrder[i]);
    }

    allSteps.append(CipherStep(3, QChar(), orderStr,
        QStringLiteral(u"Порядок столбцов")));

    // Шаг 4: Направления записи
    QString writeDirsStr;
    if (writeDirections.isEmpty()) {
        writeDirsStr = QStringLiteral(u"Все строки слева направо");
    } else {
        writeDirsStr = QStringLiteral(u"Направления записи: ");
        for (int i = 0; i < qMin(writeDirections.size(), config.rows); ++i) {
            if (i > 0) writeDirsStr += ", ";
            writeDirsStr += QString("строка %1: %2").arg(i + 1)
                .arg(writeDirections[i] == LEFT_TO_RIGHT ? "←→" : "→←");
        }
    }
    allSteps.append(CipherStep(4, QChar(), writeDirsStr,
        QStringLiteral(u"Параметры записи")));

    // Шаг 5: Используем RouteCipher
    CipherResult routeResult = routeCipher.encrypt(text, config);

    // Объединяем шаги
    for (const auto& step : routeResult.steps) {
        allSteps.append(step);
    }

    // Перенумеровываем
    for (int i = 0; i < allSteps.size(); ++i) {
        allSteps[i].index = i + 1;
    }

    // Формируем описание
    QString description = QStringLiteral(u"ColumnarCipher - Вертикальная перестановка\n")
                        + QStringLiteral(u"Ключ: %1\n").arg(key)
                        + QStringLiteral(u"Порядок столбцов: %1\n").arg(orderStr)
                        + QStringLiteral(u"Размер таблицы: %1×%2\n").arg(config.rows).arg(config.cols);

    // Добавляем информацию о направлениях
    description += QStringLiteral(u"Запись по строкам: ");
    if (writeDirections.isEmpty()) {
        description += QStringLiteral(u"все слева направо\n");
    } else {
        for (int i = 0; i < qMin(writeDirections.size(), config.rows); ++i) {
            description += QStringLiteral(u"\n  Строка %1: %2")
                .arg(i + 1)
                .arg(writeDirections[i] == LEFT_TO_RIGHT ? "слева направо" : "справа налево");
        }
        description += "\n";
    }

    description += QStringLiteral(u"Чтение по столбцам: ");
    if (readDirections.isEmpty()) {
        description += QStringLiteral(u"все сверху вниз в порядке ключа");
    } else {
        description += QStringLiteral(u"в порядке ключа");
        for (int i = 0; i < qMin(readDirections.size(), config.cols); ++i) {
            description += QStringLiteral(u"\n  Столбец %1: %2")
                .arg(i + 1)
                .arg(readDirections[i] == TOP_TO_BOTTOM ? "сверху вниз" : "снизу вверх");
        }
    }

    return CipherResult(routeResult.result, allSteps, description, name(), false);
}

// Простое дешифрование
CipherResult ColumnarCipher::decrypt(const QString& text, const QString& key) {
    return decrypt(text, key, QVector<Direction>(), QVector<Direction>(), rows, cols);
}

// Полное дешифрование
CipherResult ColumnarCipher::decrypt(const QString& text, const QString& key,
                                    const QVector<Direction>& writeDirections,
                                    const QVector<Direction>& readDirections,
                                    int rows, int cols) {
    QVector<CipherStep> steps;

    // Пока только заглушка
    steps.append(CipherStep(1, QChar(),
        QStringLiteral(u"Дешифрование ColumnarCipher"),
        QStringLiteral(u"Еще не реализовано")));

    return CipherResult(QString(), steps,
                       QStringLiteral(u"Дешифрование ColumnarCipher"),
                       name() + QStringLiteral(u" (дешифрование)"), false);
}

QString ColumnarCipher::name() const {
    return QStringLiteral(u"ColumnarCipher");
}

QString ColumnarCipher::description() const {
    return QStringLiteral(u"Шифр вертикальной перестановки с ключевым словом");
}
