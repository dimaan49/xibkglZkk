#include "cardano.h"
#include <QStringBuilder>
#include <algorithm>
#include <QDebug>

CardanoCipher::CardanoCipher(const std::vector<std::vector<bool>>& holePattern) {
    rows = holePattern.size();
    if (rows > 0) {
        cols = holePattern[0].size();
    } else {
        cols = 0;
    }

    holes = holePattern;
    grid.resize(rows, std::vector<QChar>(cols, QChar()));
}

QChar CardanoCipher::getAlphabetChar(int index) const {
    static const QString alphabet = QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ");
    return alphabet[index % alphabet.size()];
}

// Поворот на 180 градусов
std::vector<std::vector<bool>> CardanoCipher::rotate180(const std::vector<std::vector<bool>>& pattern) const {
    int r = pattern.size();
    int c = pattern[0].size();
    std::vector<std::vector<bool>> rotated(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            rotated[r-1-i][c-1-j] = pattern[i][j];
        }
    }

    return rotated;
}

std::vector<std::vector<bool>> CardanoCipher::mirrorX(const std::vector<std::vector<bool>>& pattern) const {
    int r = static_cast<int>(pattern.size());
    if (r == 0) return pattern;

    int c = static_cast<int>(pattern[0].size());
    std::vector<std::vector<bool>> mirrored(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            mirrored[r-1-i][j] = pattern[i][j]; // Отражаем по горизонтальной оси
        }
    }

    return mirrored;
}

// Зеркальное отражение относительно вертикальной оси Y
// (меняются столбцы - левое становится правым)
std::vector<std::vector<bool>> CardanoCipher::mirrorY(const std::vector<std::vector<bool>>& pattern) const {
    int r = static_cast<int>(pattern.size());
    if (r == 0) return pattern;

    int c = static_cast<int>(pattern[0].size());
    std::vector<std::vector<bool>> mirrored(r, std::vector<bool>(c, false));

    for (int i = 0; i < r; ++i) {
        for (int j = 0; j < c; ++j) {
            mirrored[i][c-1-j] = pattern[i][j]; // Отражаем по вертикальной оси
        }
    }

    return mirrored;
}

// Получение позиции решетки для определенного шага
std::vector<std::vector<bool>> CardanoCipher::getPosition(int positionNumber) const {
    switch(positionNumber) {
        case 1: // Начальное положение
            return holes;

        case 2: // Поворот на 180 градусов
            return rotate180(holes);

        case 3: // Зеркально по оси X относительно первого
            return mirrorX(holes);

        case 4: // Зеркально по оси X относительно первого + поворот 180
        {
            std::vector<std::vector<bool>> mirrored = mirrorX(holes);
            return rotate180(mirrored);
        }

        default:
            return holes;
    }
}

int CardanoCipher::countTotalHoles() const {
    int total = 0;

    // Считаем отверстия для всех 4 позиций
    for (int pos = 1; pos <= 4; ++pos) {
        std::vector<std::vector<bool>> position = getPosition(pos);
        for (const auto& row : position) {
            for (bool hole : row) {
                if (hole) total++;
            }
        }
    }

    return total;
}

void CardanoCipher::clearGrid() {
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            grid[i][j] = QChar();
        }
    }
}

CipherResult CardanoCipher::encrypt(const QString& text) {
    QVector<CipherStep> steps;

    // Шаг 0: Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text,
        QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));

    steps.append(CipherStep(
        0,
        QChar(),
        filteredText,
        QStringLiteral(u"Очищенный текст (только буквы алфавита)")
    ));

    // Проверяем, что текст помещается
    int totalHoles = countTotalHoles();
    qDebug() << "Всего доступных отверстий за 4 позиции:" << totalHoles;
    qDebug() << "Длина текста:" << filteredText.length();

    if (filteredText.length() > totalHoles) {
        filteredText = filteredText.left(totalHoles);
        steps.append(CipherStep(
            1,
            QChar(),
            filteredText,
            QStringLiteral(u"Текст обрезан до %1 символов (максимум для решетки)").arg(totalHoles)
        ));
    }

    // Шаг 1: Записываем текст через отверстия в 4 положениях
    clearGrid();
    int textIndex = 0;

    // Позиция 1: Начальное положение
    std::vector<std::vector<bool>> pos1 = getPosition(1);
    QString placedPos1;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (pos1[i][j] && textIndex < filteredText.length()) {
                grid[i][j] = filteredText[textIndex];
                placedPos1.append(filteredText[textIndex]);
                textIndex++;
            }
        }
    }
    if (!placedPos1.isEmpty()) {
        steps.append(CipherStep(
            2,
            QChar(),
            placedPos1,
            QStringLiteral(u"Позиция 1: Начальное положение (%1 букв)").arg(placedPos1.length())
        ));
    }

    // Позиция 2: Поворот 180 градусов
    std::vector<std::vector<bool>> pos2 = getPosition(2);
    QString placedPos2;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (pos2[i][j] && textIndex < filteredText.length()) {
                grid[i][j] = filteredText[textIndex];
                placedPos2.append(filteredText[textIndex]);
                textIndex++;
            }
        }
    }
    if (!placedPos2.isEmpty()) {
        steps.append(CipherStep(
            3,
            QChar(),
            placedPos2,
            QStringLiteral(u"Позиция 2: Поворот 180° (%1 букв)").arg(placedPos2.length())
        ));
    }

    // Позиция 3: Зеркально по оси X
    std::vector<std::vector<bool>> pos3 = getPosition(3);
    QString placedPos3;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (pos3[i][j] && textIndex < filteredText.length()) {
                grid[i][j] = filteredText[textIndex];
                placedPos3.append(filteredText[textIndex]);
                textIndex++;
            }
        }
    }
    if (!placedPos3.isEmpty()) {
        steps.append(CipherStep(
            4,
            QChar(),
            placedPos3,
            QStringLiteral(u"Позиция 3: Зеркально по оси X (%1 букв)").arg(placedPos3.length())
        ));
    }

    // Позиция 4: Зеркально по оси X + поворот 180
    std::vector<std::vector<bool>> pos4 = getPosition(4);
    QString placedPos4;
    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (pos4[i][j] && textIndex < filteredText.length()) {
                grid[i][j] = filteredText[textIndex];
                placedPos4.append(filteredText[textIndex]);
                textIndex++;
            }
        }
    }
    if (!placedPos4.isEmpty()) {
        steps.append(CipherStep(
            5,
            QChar(),
            placedPos4,
            QStringLiteral(u"Позиция 4: Зеркально по оси X + поворот 180° (%1 букв)").arg(placedPos4.length())
        ));
    }

    // Статистика размещения
    int placedLetters = placedPos1.length() + placedPos2.length() +
                       placedPos3.length() + placedPos4.length();
    steps.append(CipherStep(
        6,
        QChar(),
        QString::number(placedLetters),
        QStringLiteral(u"Всего размещено букв в отверстиях")
    ));

    // Шаг 2: Заполняем оставшиеся клетки по порядку алфавита
    QString result;
    int alphabetIndex = 0;
    int filledCells = 0;

    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            if (grid[i][j].isNull()) {
                QChar ch = getAlphabetChar(alphabetIndex);
                grid[i][j] = ch;
                alphabetIndex++;
                filledCells++;
            }
            result += grid[i][j];
        }
    }

    steps.append(CipherStep(
        7,
        QChar(),
        QString::number(filledCells),
        QStringLiteral(u"Заполнено оставшихся ячеек по алфавиту")
    ));

    steps.append(CipherStep(
        8,
        QChar(),
        result,
        QStringLiteral(u"Итоговая матрица %1×%2").arg(rows).arg(cols)
    ));

    // Формируем описание решетки для отображения
    QString gridDescription;
    gridDescription += QStringLiteral(u"Решетка Кардано %1×%2\n").arg(rows).arg(cols);
    gridDescription += QStringLiteral(u"Отверстия (1) и нет (0):\n");

    for (int i = 0; i < rows; ++i) {
        for (int j = 0; j < cols; ++j) {
            gridDescription += holes[i][j] ? "1" : "0";
        }
        gridDescription += "\n";
    }

    gridDescription += QStringLiteral(u"\n4 позиции решетки:\n");
    gridDescription += QStringLiteral(u"1. Начальное положение\n");
    gridDescription += QStringLiteral(u"2. Поворот 180°\n");
    gridDescription += QStringLiteral(u"3. Зеркально по оси X\n");
    gridDescription += QStringLiteral(u"4. Зеркально по оси X + поворот 180°");

    return CipherResult(result, steps, gridDescription, name(), false);
}

CipherResult CardanoCipher::decrypt(const QString& text) {
    // Для дешифрования нужно знать исходную решетку и порядок позиций
    // Пока возвращаем заглушку
    QVector<CipherStep> steps;

    steps.append(CipherStep(
        1,
        QChar(),
        QStringLiteral(u"Не реализовано"),
        QStringLiteral(u"Дешифрование решетки Кардано")
    ));

    return CipherResult(QString(), steps,
                       QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"),
                       name() + QStringLiteral(u" (дешифрование)"), false);
}

QString CardanoCipher::name() const {
    return QStringLiteral(u"Решетка Кардано");
}

QString CardanoCipher::description() const {
    return QStringLiteral(u"Шифр с перфорированной решеткой 6×10 (4 позиции)");
}
