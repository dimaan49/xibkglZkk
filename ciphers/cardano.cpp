#include "cardano.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QStringBuilder>
#include <algorithm>
#include <QDebug>

CardanoCipher::CardanoCipher()
{
    m_holes = createDefaultGrid();
    m_rows = m_holes.size();
    if (m_rows > 0) {
        m_cols = m_holes[0].size();
    } else {
        m_cols = 0;
    }
    m_grid.resize(m_rows, std::vector<QChar>(m_cols, QChar()));
}

std::vector<std::vector<bool>> CardanoCipher::createDefaultGrid() const
{
    return {
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {1,0,0,0,1,0,1,1,0,0},  // 1000101100
        {0,1,0,0,0,1,0,0,0,1},  // 0100010001
        {0,0,0,1,0,0,0,1,0,0},  // 0001000100
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {0,0,1,0,0,1,1,0,0,1}   // 0010011001
    };
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
            return m_holes;

        case 2: // Поворот на 180 градусов
            return rotate180(m_holes);

        case 3: // Зеркально по оси X относительно первого
            return mirrorX(m_holes);

        case 4: // Зеркально по оси X относительно первого + поворот 180
        {
            std::vector<std::vector<bool>> mirrored = mirrorX(m_holes);
            return rotate180(mirrored);
        }

        default:
            return m_holes;
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
    for (int i = 0; i < m_rows; ++i) {
        for (int j = 0; j < m_cols; ++j) {
            m_grid[i][j] = QChar();
        }
    }
}

CipherResult CardanoCipher::encrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    QVector<CipherStep> steps;

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    // Проверяем, что текст помещается
    int totalHoles = countTotalHoles();

    if (filteredText.length() > totalHoles) {
        filteredText = filteredText.left(totalHoles);
    }

    // Записываем текст через отверстия
    clearGrid();
    int textIndex = 0;

    // Все 4 позиции
    for (int pos = 1; pos <= 4; ++pos) {
        std::vector<std::vector<bool>> position = getPosition(pos);
        QString placedChars;

        for (int i = 0; i < m_rows; ++i) {
            for (int j = 0; j < m_cols; ++j) {
                if (position[i][j] && textIndex < filteredText.length()) {
                    m_grid[i][j] = filteredText[textIndex];
                    placedChars.append(filteredText[textIndex]);
                    textIndex++;
                }
            }
        }

        if (!placedChars.isEmpty()) {
            steps.append(CipherStep(
                pos,
                QChar(),
                placedChars,
                QString("Позиция %1: %2 букв").arg(pos).arg(placedChars.length())
            ));
        }
    }

    // Заполняем оставшиеся клетки
    QString result;
    int alphabetIndex = 0;

    for (int i = 0; i < m_rows; ++i) {
        for (int j = 0; j < m_cols; ++j) {
            if (m_grid[i][j].isNull()) {
                QChar ch = getAlphabetChar(alphabetIndex);
                m_grid[i][j] = ch;
                alphabetIndex++;
            }
            result += m_grid[i][j];
        }
    }

    steps.append(CipherStep(
        5,
        QChar(),
        result,
        QString("Итоговая матрица %1×%2").arg(m_rows).arg(m_cols)
    ));

    return CipherResult(result, steps, "Решетка Кардано 6×10", name(), false);
}

CipherResult CardanoCipher::decrypt(const QString& text, const QVariantMap& params)
{
    Q_UNUSED(params);

    // Заглушка - нужно реализовать дешифрование
    QVector<CipherStep> steps;

    steps.append(CipherStep(
        1,
        QChar(),
        "Не реализовано",
        "Дешифрование решетки Кардано"
    ));

    return CipherResult(QString(), steps, m_alphabet, name(), false);
}

// Остальные вспомогательные методы остаются как были (normalizeShift, getShiftForPosition, etc.)
// Только заменить alphabet на m_alphabet, rows на m_rows, cols на m_cols, holes на m_holes

CardanoCipherRegister::CardanoCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "cardano",
        "Кардано",
        []() -> CipherInterface* { return new CardanoCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "cardano",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(widgets);

            QLabel* infoLabel = new QLabel(
                "Используется решетка 6×10:\n"
                "0100000000\n"
                "1000101100\n"
                "0100010001\n"
                "0001000100\n"
                "0100000000\n"
                "0010011001\n"
                "\n"
                "1 = отверстие, 0 = нет отверстия"
            );
            infoLabel->setWordWrap(true);
            infoLabel->setStyleSheet("font-family: monospace; color: white; padding: 5px;");
            layout->addWidget(infoLabel);
        }
    );
}

QString CardanoCipher::name() const {
    return QStringLiteral(u"Решетка Кардано");
}

QString CardanoCipher::description() const {
    return QStringLiteral(u"Шифр с перфорированной решеткой 6×10 (4 позиции)");
}
