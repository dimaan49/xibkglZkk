#include "a51.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QStackedWidget>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <cstring>

// ==================== Многочлены обратной связи ====================
const int A51Cipher::R1_TAPS[4] = {18, 17, 16, 13};
const int A51Cipher::R2_TAPS[2] = {21, 20};
const int A51Cipher::R3_TAPS[4] = {22, 21, 20, 7};

// ==================== BinaryKeyEdit Implementation ====================

BinaryKeyEdit::BinaryKeyEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression binaryRegex("^[01]{0,64}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(binaryRegex, this);
    setValidator(validator);

    setPlaceholderText("64 бита (0 и 1)");
    setMaxLength(64);
}

void BinaryKeyEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("BinaryKeyEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void BinaryKeyEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

std::bitset<64> BinaryKeyEdit::getKey() const
{
    std::bitset<64> result;
    QString text = this->text();

    // Исправляем: используем qMin для сравнения qsizetype и int
    int len = qMin(text.length(), 64);
    for (int i = 0; i < len; ++i) {
        if (text[i] == '1') {
            result.set(63 - i);
        }
    }
    return result;
}

void BinaryKeyEdit::setKey(const std::bitset<64>& key)
{
    QString binaryStr;
    for (int i = 63; i >= 0; --i) {
        binaryStr.append(key[i] ? '1' : '0');
    }
    setText(binaryStr);
}

// ==================== TextKeyEdit Implementation ====================

TextKeyEdit::TextKeyEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    setMaxLength(13);
    setPlaceholderText("13 букв русского алфавита");
}

void TextKeyEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("TextKeyEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void TextKeyEdit::setAlphabet(const QString& alphabet)
{
    m_alphabet = alphabet;
}

QString TextKeyEdit::getTextKey() const
{
    return text().toUpper();
}

void TextKeyEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

void TextKeyEdit::focusOutEvent(QFocusEvent* event)
{
    QString txt = text().toUpper();
    bool valid = true;
    for (QChar ch : txt) {
        if (!m_alphabet.contains(ch)) {
            valid = false;
            break;
        }
    }
    if (!valid && !txt.isEmpty()) {
        setValid(false);
        setToolTip("Только буквы русского алфавита");
    }
    QLineEdit::focusOutEvent(event);
}

// ==================== A51Cipher Implementation ====================

A51Cipher::A51Cipher()
    : m_r1(0), m_r2(0), m_r3(0), m_frameNumber(0)
{
}

uint32_t A51Cipher::feedbackR1() const
{
    uint32_t fb = 0;
    fb ^= (m_r1 >> 18) & 1;
    fb ^= (m_r1 >> 17) & 1;
    fb ^= (m_r1 >> 16) & 1;
    fb ^= (m_r1 >> 13) & 1;
    return fb;
}

uint32_t A51Cipher::feedbackR2() const
{
    uint32_t fb = 0;
    fb ^= (m_r2 >> 21) & 1;
    fb ^= (m_r2 >> 20) & 1;
    return fb;
}

uint32_t A51Cipher::feedbackR3() const
{
    uint32_t fb = 0;
    fb ^= (m_r3 >> 22) & 1;
    fb ^= (m_r3 >> 21) & 1;
    fb ^= (m_r3 >> 20) & 1;
    fb ^= (m_r3 >> 7) & 1;
    return fb;
}

bool A51Cipher::majority(bool x, bool y, bool z) const
{
    return (x && y) || (x && z) || (y && z);
}

bool A51Cipher::getClockBit(uint32_t reg, int bitPos) const
{
    return (reg >> bitPos) & 1;
}

void A51Cipher::shiftR1()
{
    uint32_t fb = feedbackR1();
    m_r1 = (m_r1 >> 1) | (fb << (R1_LEN - 1));
    m_r1 &= (1 << R1_LEN) - 1;
}

void A51Cipher::shiftR2()
{
    uint32_t fb = feedbackR2();
    m_r2 = (m_r2 >> 1) | (fb << (R2_LEN - 1));
    m_r2 &= (1 << R2_LEN) - 1;
}

void A51Cipher::shiftR3()
{
    uint32_t fb = feedbackR3();
    m_r3 = (m_r3 >> 1) | (fb << (R3_LEN - 1));
    m_r3 &= (1 << R3_LEN) - 1;
}

void A51Cipher::initializeRegisters(const std::bitset<64>& key, uint32_t frameNumber)
{
    // Обнуляем регистры
    m_r1 = 0;
    m_r2 = 0;
    m_r3 = 0;

    // Этап 1: 64 такта, XOR с битами ключа
    for (int i = 0; i < 64; ++i) {
        // Безопасное получение бита ключа
        bool keyBit = false;
        int keyIndex = 63 - i;
        if (keyIndex >= 0 && keyIndex < 64) {
            keyBit = key[keyIndex];
        }

        // Сдвигаем регистры и XOR-им бит ключа с младшим битом
        uint32_t new_r1 = (m_r1 >> 1);
        uint32_t new_r2 = (m_r2 >> 1);
        uint32_t new_r3 = (m_r3 >> 1);

        uint32_t lsb1 = m_r1 & 1;
        uint32_t lsb2 = m_r2 & 1;
        uint32_t lsb3 = m_r3 & 1;

        new_r1 |= ((keyBit ^ lsb1) << (R1_LEN - 1));
        new_r2 |= ((keyBit ^ lsb2) << (R2_LEN - 1));
        new_r3 |= ((keyBit ^ lsb3) << (R3_LEN - 1));

        m_r1 = new_r1 & ((1 << R1_LEN) - 1);
        m_r2 = new_r2 & ((1 << R2_LEN) - 1);
        m_r3 = new_r3 & ((1 << R3_LEN) - 1);
    }

    // Этап 2: 22 такта, XOR с битами номера кадра
    for (int i = 0; i < 22; ++i) {
        bool frameBit = (frameNumber >> i) & 1;

        uint32_t new_r1 = (m_r1 >> 1);
        uint32_t new_r2 = (m_r2 >> 1);
        uint32_t new_r3 = (m_r3 >> 1);

        uint32_t lsb1 = m_r1 & 1;
        uint32_t lsb2 = m_r2 & 1;
        uint32_t lsb3 = m_r3 & 1;

        new_r1 |= ((frameBit ^ lsb1) << (R1_LEN - 1));
        new_r2 |= ((frameBit ^ lsb2) << (R2_LEN - 1));
        new_r3 |= ((frameBit ^ lsb3) << (R3_LEN - 1));

        m_r1 = new_r1 & ((1 << R1_LEN) - 1);
        m_r2 = new_r2 & ((1 << R2_LEN) - 1);
        m_r3 = new_r3 & ((1 << R3_LEN) - 1);
    }

    // Этап 3: 100 тактов холостого прогона
    for (int i = 0; i < 100; ++i) {
        bool clock1 = (m_r1 >> R1_CLOCK_BIT) & 1;
        bool clock2 = (m_r2 >> R2_CLOCK_BIT) & 1;
        bool clock3 = (m_r3 >> R3_CLOCK_BIT) & 1;

        bool maj = (clock1 && clock2) || (clock1 && clock3) || (clock2 && clock3);

        if (clock1 == maj) {
            uint32_t fb = feedbackR1();
            m_r1 = (m_r1 >> 1) | (fb << (R1_LEN - 1));
            m_r1 &= (1 << R1_LEN) - 1;
        }
        if (clock2 == maj) {
            uint32_t fb = feedbackR2();
            m_r2 = (m_r2 >> 1) | (fb << (R2_LEN - 1));
            m_r2 &= (1 << R2_LEN) - 1;
        }
        if (clock3 == maj) {
            uint32_t fb = feedbackR3();
            m_r3 = (m_r3 >> 1) | (fb << (R3_LEN - 1));
            m_r3 &= (1 << R3_LEN) - 1;
        }
    }
}

bool A51Cipher::generateKeystreamBit()
{
    // Получаем биты синхронизации
    bool clock1 = (m_r1 >> R1_CLOCK_BIT) & 1;
    bool clock2 = (m_r2 >> R2_CLOCK_BIT) & 1;
    bool clock3 = (m_r3 >> R3_CLOCK_BIT) & 1;

    // Вычисляем мажоритарный бит
    bool maj = (clock1 && clock2) || (clock1 && clock3) || (clock2 && clock3);

    // Сдвигаем регистры
    if (clock1 == maj) {
        uint32_t fb = feedbackR1();
        m_r1 = (m_r1 >> 1) | (fb << (R1_LEN - 1));
        m_r1 &= (1 << R1_LEN) - 1;
    }
    if (clock2 == maj) {
        uint32_t fb = feedbackR2();
        m_r2 = (m_r2 >> 1) | (fb << (R2_LEN - 1));
        m_r2 &= (1 << R2_LEN) - 1;
    }
    if (clock3 == maj) {
        uint32_t fb = feedbackR3();
        m_r3 = (m_r3 >> 1) | (fb << (R3_LEN - 1));
        m_r3 &= (1 << R3_LEN) - 1;
    }

    // Выходной бит
    bool out1 = (m_r1 >> (R1_LEN - 1)) & 1;
    bool out2 = (m_r2 >> (R2_LEN - 1)) & 1;
    bool out3 = (m_r3 >> (R3_LEN - 1)) & 1;

    return out1 ^ out2 ^ out3;
}

std::bitset<64> A51Cipher::generateGamma(int numBits)
{
    std::bitset<64> gamma;
    int maxBits = qMin(numBits, 64);

    for (int i = 0; i < maxBits; ++i) {
        bool bit = generateKeystreamBit();
        if (bit) {
            gamma.set(63 - i);
        }
    }
    return gamma;
}


std::bitset<64> A51Cipher::textToBits(const QString& text) const
{
    std::bitset<64> result;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    // Исправляем: используем qMin
    int numChars = qMin(filtered.length(), 13);
    for (int i = 0; i < numChars; ++i) {
        int pos = m_alphabet.indexOf(filtered[i]);
        if (pos >= 0 && pos < 32) {
            for (int b = 0; b < 5; ++b) {
                bool bit = (pos >> (4 - b)) & 1;
                int bitPos = (i * 5) + b;
                if (bitPos < 64) {
                    result.set(63 - bitPos, bit);
                }
            }
        }
    }

    return result;
}

QString A51Cipher::bitsToText(const std::bitset<64>& bits) const
{
    QString result;

    for (int i = 0; i < 13; ++i) {
        int pos = 0;
        for (int b = 0; b < 5; ++b) {
            int bitPos = (i * 5) + b;
            if (bitPos < 64 && bits[63 - bitPos]) {
                pos |= (1 << (4 - b));
            }
        }
        if (pos < m_alphabet.length()) {
            result.append(m_alphabet[pos]);
        } else {
            result.append('?');
        }
    }

    return result;
}

CipherResult A51Cipher::processText(const QString& text, const std::bitset<64>& key, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало работы A5/1", "Инициализация"));

    // 1. Фильтруем только буквы алфавита
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Входной текст: %1").arg(filteredText.left(50) + (filteredText.length() > 50 ? "..." : "")),
        "Подготовка данных"));

    // 2. Преобразуем весь текст в биты (каждая буква = 5 бит)
    int totalBits = filteredText.length() * 5;
    std::bitset<1024> textBits; // Достаточно большой для текста любой длины

    for (int i = 0; i < filteredText.length(); ++i) {
        int pos = m_alphabet.indexOf(filteredText[i]);
        if (pos >= 0 && pos < 32) {
            for (int b = 0; b < 5; ++b) {
                bool bit = (pos >> (4 - b)) & 1;
                int bitPos = (i * 5) + b;
                if (bitPos < totalBits) {
                    textBits.set(totalBits - 1 - bitPos, bit);
                }
            }
        }
    }

    steps.append(CipherStep(2, QChar(),
        QString("Всего бит для шифрования: %1").arg(totalBits),
        "Преобразование текста"));

    // 3. Инициализируем регистры (один раз для всего сообщения)
    // Используем фиксированный номер кадра (например 0)
    initializeRegisters(key, 0);

    steps.append(CipherStep(3, QChar(),
        "Инициализация регистров (кадр 0)",
        "Инициализация"));

    // 4. Генерируем гамму на ВСЮ длину текста (непрерывно)
    std::bitset<1024> gamma;
    for (int i = 0; i < totalBits; ++i) {
        bool bit = generateKeystreamBit();
        if (bit) {
            gamma.set(totalBits - 1 - i);
        }
    }

    // Строка гаммы для отладки (первые 20 бит)
    QString gammaPreview;
    for (int i = 0; i < qMin(20, totalBits); ++i) {
        gammaPreview.append(gamma[totalBits - 1 - i] ? '1' : '0');
        if ((i + 1) % 5 == 0 && i + 1 < qMin(20, totalBits)) gammaPreview.append(" ");
    }
    steps.append(CipherStep(4, QChar(),
        QString("Гамма (первые %1 бит): %2...").arg(qMin(20, totalBits)).arg(gammaPreview),
        "Генерация гаммы"));

    // 5. XOR
    std::bitset<1024> resultBits;
    for (int i = 0; i < totalBits; ++i) {
        resultBits[i] = textBits[i] ^ gamma[i];
    }

    // 6. Преобразуем обратно в текст
    QString resultText;
    int numLetters = totalBits / 5;
    for (int i = 0; i < numLetters; ++i) {
        int pos = 0;
        for (int b = 0; b < 5; ++b) {
            int bitPos = (i * 5) + b;
            if (bitPos < totalBits && resultBits[totalBits - 1 - bitPos]) {
                pos |= (1 << (4 - b));
            }
        }
        if (pos < m_alphabet.length()) {
            resultText.append(m_alphabet[pos]);
        } else {
            resultText.append('?');
        }
    }

    steps.append(CipherStep(5, QChar(),
        QString("Результат: %1").arg(resultText),
        "Завершение"));

    result.result = resultText;
    result.steps = steps;

    return result;
}

CipherResult A51Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    QString keyType = params.value("keyType", "binary").toString();
    std::bitset<64> key;

    if (keyType == "binary") {
        QString binaryKey = params.value("binaryKey", "").toString();
        // Исправляем: удаляем пробелы безопасно
        binaryKey.remove(QChar(' '));
        int keyLen = qMin(binaryKey.length(), 64);
        for (int i = 0; i < keyLen; ++i) {
            if (binaryKey[i] == '1') {
                key.set(63 - i);
            }
        }
    } else {
        QString textKey = params.value("textKey", "").toString();
        key = textToBits(textKey);
    }

    return processText(text, key, true);
}

CipherResult A51Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    return encrypt(text, params);
}


void A51Cipher::reset()
{
    m_r1 = 0;
    m_r2 = 0;
    m_r3 = 0;
    m_frameNumber = 0;
}

// ==================== A51CipherRegister Implementation ====================

A51CipherRegister::A51CipherRegister()
{
    CipherFactory::instance().registerCipher(
        "a51",
        "A5/1 (GSM)",
        []() -> CipherInterface* { return new A51Cipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "a51",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Выбор типа ключа в одной строке с полем ввода
            QHBoxLayout* typeRow = new QHBoxLayout();
            typeRow->setSpacing(10);

            QLabel* typeLabel = new QLabel("Тип ключа:");
            typeLabel->setFixedWidth(80);
            QComboBox* typeCombo = new QComboBox();
            typeCombo->addItem("Двоичный (64 бита)", "binary");
            typeCombo->addItem("Текстовый (13 букв)", "text");
            typeCombo->setFixedWidth(150);

            typeRow->addWidget(typeLabel);
            typeRow->addWidget(typeCombo);
            typeRow->addStretch();
            mainLayout->addLayout(typeRow);

            // Стек для переключения
            QStackedWidget* stackedWidget = new QStackedWidget();
            stackedWidget->setFixedHeight(50);

            // Двоичный ключ
            QWidget* binaryWidget = new QWidget();
            QHBoxLayout* binaryLayout = new QHBoxLayout(binaryWidget);
            binaryLayout->setContentsMargins(0, 0, 0, 0);
            binaryLayout->setSpacing(10);
            QLabel* binaryLabel = new QLabel("Ключ (64 бита):");
            binaryLabel->setFixedWidth(80);
            BinaryKeyEdit* binaryEdit = new BinaryKeyEdit();
            binaryEdit->setObjectName("binaryKey");
            binaryEdit->setText("1010101010101010101010101010101010101010101010101010101010101010");
            binaryLayout->addWidget(binaryLabel);
            binaryLayout->addWidget(binaryEdit);
            binaryLayout->addStretch();
            stackedWidget->addWidget(binaryWidget);

            // Текстовый ключ
            QWidget* textWidget = new QWidget();
            QHBoxLayout* textLayout = new QHBoxLayout(textWidget);
            textLayout->setContentsMargins(0, 0, 0, 0);
            textLayout->setSpacing(10);
            QLabel* textLabel = new QLabel("Ключ (13 букв):");
            textLabel->setFixedWidth(80);
            TextKeyEdit* textEdit = new TextKeyEdit();
            textEdit->setObjectName("textKey");
            textEdit->setText("АБВГДЕЖЗИЙКЛ");
            textLayout->addWidget(textLabel);
            textLayout->addWidget(textEdit);
            textLayout->addStretch();
            stackedWidget->addWidget(textWidget);

            mainLayout->addWidget(stackedWidget);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "A5/1 (GSM) — потоковый шифр с тремя РСЛОС:\n"
                "R1: x^19 + x^18 + x^17 + x^14 + 1 (19 бит)\n"
                "R2: x^22 + x^21 + 1 (22 бита)\n"
                "R3: x^23 + x^22 + x^21 + x^8 + 1 (23 бита)\n"
                "Управление тактированием: majority function\n"
                "Ключ: 64 бита (двоичный или 13 букв по 5 бит)"
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["keyType"] = typeCombo;
            widgets["binaryKey"] = binaryEdit;
            widgets["textKey"] = textEdit;
            widgets["stackedWidget"] = stackedWidget;

            // Подключаем сигнал для переключения
            QObject::connect(typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                [stackedWidget](int index) {
                    stackedWidget->setCurrentIndex(index);
                });
        },
        nullptr
    );
}

static A51CipherRegister a51Register;
