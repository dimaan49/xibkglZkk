#include "a52.h"
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

// ==================== Многочлены обратной связи ====================
// R1: x^19 + x^18 + x^17 + x^14 + 1
const int A52Cipher::R1_TAPS[4] = {18, 17, 16, 13};

// R2: x^22 + x^21 + 1
const int A52Cipher::R2_TAPS[2] = {21, 20};

// R3: x^23 + x^22 + x^21 + x^8 + 1
const int A52Cipher::R3_TAPS[4] = {22, 21, 20, 7};

// R4: x^17 + x^12 + 1
const int A52Cipher::R4_TAPS[2] = {16, 11};  // биты 16 и 11 (индексы с 0)

// Биты для мажоритарной функции F*
const int A52Cipher::R1_F_BITS[3] = {12, 14, 15};
const int A52Cipher::R2_F_BITS[3] = {9, 13, 16};
const int A52Cipher::R3_F_BITS[3] = {13, 16, 18};

// ==================== A52BinaryKeyEdit Implementation ====================

A52BinaryKeyEdit::A52BinaryKeyEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression binaryRegex("^[01]{0,64}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(binaryRegex, this);
    setValidator(validator);

    setPlaceholderText("64 бита (0 и 1)");
    setMaxLength(64);
}

void A52BinaryKeyEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("A52BinaryKeyEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void A52BinaryKeyEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

std::bitset<64> A52BinaryKeyEdit::getKey() const
{
    std::bitset<64> result;
    QString text = this->text();

    int len = qMin(text.length(), 64);
    for (int i = 0; i < len; ++i) {
        if (text[i] == '1') {
            result.set(63 - i);
        }
    }
    return result;
}

void A52BinaryKeyEdit::setKey(const std::bitset<64>& key)
{
    QString binaryStr;
    for (int i = 63; i >= 0; --i) {
        binaryStr.append(key[i] ? '1' : '0');
    }
    setText(binaryStr);
}

// ==================== A52TextKeyEdit Implementation ====================

A52TextKeyEdit::A52TextKeyEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    setMaxLength(13);
    setPlaceholderText("13 букв русского алфавита");
}

void A52TextKeyEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("A52TextKeyEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void A52TextKeyEdit::setAlphabet(const QString& alphabet)
{
    m_alphabet = alphabet;
}

QString A52TextKeyEdit::getTextKey() const
{
    return text().toUpper();
}

void A52TextKeyEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

void A52TextKeyEdit::focusOutEvent(QFocusEvent* event)
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

// ==================== A52Cipher Implementation ====================

A52Cipher::A52Cipher()
    : m_r1(0), m_r2(0), m_r3(0), m_r4(0), m_frameNumber(0)
{
}

uint32_t A52Cipher::feedbackR1() const
{
    uint32_t fb = 0;
    for (int i = 0; i < 4; ++i) {
        fb ^= (m_r1 >> R1_TAPS[i]) & 1;
    }
    return fb;
}

uint32_t A52Cipher::feedbackR2() const
{
    uint32_t fb = 0;
    for (int i = 0; i < 2; ++i) {
        fb ^= (m_r2 >> R2_TAPS[i]) & 1;
    }
    return fb;
}

uint32_t A52Cipher::feedbackR3() const
{
    uint32_t fb = 0;
    for (int i = 0; i < 4; ++i) {
        fb ^= (m_r3 >> R3_TAPS[i]) & 1;
    }
    return fb;
}

uint32_t A52Cipher::feedbackR4() const
{
    uint32_t fb = 0;
    for (int i = 0; i < 2; ++i) {
        fb ^= (m_r4 >> R4_TAPS[i]) & 1;
    }
    return fb;
}

bool A52Cipher::majority(bool x, bool y, bool z) const
{
    return (x && y) || (x && z) || (y && z);
}

bool A52Cipher::majorityFromBits(uint32_t reg, int bit1, int bit2, int bit3) const
{
    bool x = (reg >> bit1) & 1;
    bool y = (reg >> bit2) & 1;
    bool z = (reg >> bit3) & 1;
    return majority(x, y, z);
}

bool A52Cipher::getBit(uint32_t reg, int bitPos) const
{
    return (reg >> bitPos) & 1;
}

void A52Cipher::shiftR1()
{
    uint32_t fb = feedbackR1();
    m_r1 = (m_r1 >> 1) | (fb << (R1_LEN - 1));
    m_r1 &= (1 << R1_LEN) - 1;
}

void A52Cipher::shiftR2()
{
    uint32_t fb = feedbackR2();
    m_r2 = (m_r2 >> 1) | (fb << (R2_LEN - 1));
    m_r2 &= (1 << R2_LEN) - 1;
}

void A52Cipher::shiftR3()
{
    uint32_t fb = feedbackR3();
    m_r3 = (m_r3 >> 1) | (fb << (R3_LEN - 1));
    m_r3 &= (1 << R3_LEN) - 1;
}

void A52Cipher::shiftR4()
{
    uint32_t fb = feedbackR4();
    m_r4 = (m_r4 >> 1) | (fb << (R4_LEN - 1));
    m_r4 &= (1 << R4_LEN) - 1;
}

void A52Cipher::initializeRegisters(const std::bitset<64>& key, uint32_t frameNumber)
{
    // Обнуляем регистры
    m_r1 = 0;
    m_r2 = 0;
    m_r3 = 0;
    m_r4 = 0;

    // Этап 1: 64 такта, XOR с битами ключа
    for (int i = 0; i < 64; ++i) {
        bool keyBit = key[63 - i];

        uint32_t lsb1 = m_r1 & 1;
        uint32_t lsb2 = m_r2 & 1;
        uint32_t lsb3 = m_r3 & 1;
        uint32_t lsb4 = m_r4 & 1;

        m_r1 = (m_r1 >> 1) | ((keyBit ^ lsb1) << (R1_LEN - 1));
        m_r2 = (m_r2 >> 1) | ((keyBit ^ lsb2) << (R2_LEN - 1));
        m_r3 = (m_r3 >> 1) | ((keyBit ^ lsb3) << (R3_LEN - 1));
        m_r4 = (m_r4 >> 1) | ((keyBit ^ lsb4) << (R4_LEN - 1));

        m_r1 &= (1 << R1_LEN) - 1;
        m_r2 &= (1 << R2_LEN) - 1;
        m_r3 &= (1 << R3_LEN) - 1;
        m_r4 &= (1 << R4_LEN) - 1;
    }

    // Этап 2: 22 такта, XOR с битами номера кадра
    for (int i = 0; i < 22; ++i) {
        bool frameBit = (frameNumber >> i) & 1;

        uint32_t lsb1 = m_r1 & 1;
        uint32_t lsb2 = m_r2 & 1;
        uint32_t lsb3 = m_r3 & 1;
        uint32_t lsb4 = m_r4 & 1;

        m_r1 = (m_r1 >> 1) | ((frameBit ^ lsb1) << (R1_LEN - 1));
        m_r2 = (m_r2 >> 1) | ((frameBit ^ lsb2) << (R2_LEN - 1));
        m_r3 = (m_r3 >> 1) | ((frameBit ^ lsb3) << (R3_LEN - 1));
        m_r4 = (m_r4 >> 1) | ((frameBit ^ lsb4) << (R4_LEN - 1));

        m_r1 &= (1 << R1_LEN) - 1;
        m_r2 &= (1 << R2_LEN) - 1;
        m_r3 &= (1 << R3_LEN) - 1;
        m_r4 &= (1 << R4_LEN) - 1;
    }

    // Этап 3: 1 такт - установка битов R4(3), R4(7), R4(10) в 1
    m_r4 |= (1 << 3) | (1 << 7) | (1 << 10);
    m_r4 &= (1 << R4_LEN) - 1;

    // Этап 4: 99 тактов холостого прогона
    for (int i = 0; i < 99; ++i) {
        bool clock1 = getBit(m_r4, R4_CLOCK_BIT3);  // R4(10) для R1
        bool clock2 = getBit(m_r4, R4_CLOCK_BIT1);  // R4(3) для R2
        bool clock3 = getBit(m_r4, R4_CLOCK_BIT2);  // R4(7) для R3

        bool maj = majority(clock1, clock2, clock3);

        if (clock1 == maj) shiftR1();
        if (clock2 == maj) shiftR2();
        if (clock3 == maj) shiftR3();

        // R4 всегда сдвигается (по описанию A5/2)
        shiftR4();
    }
}

bool A52Cipher::generateKeystreamBit()
{
    // Получаем биты синхронизации из R4
    bool clock1 = getBit(m_r4, R4_CLOCK_BIT3);  // для R1
    bool clock2 = getBit(m_r4, R4_CLOCK_BIT1);  // для R2
    bool clock3 = getBit(m_r4, R4_CLOCK_BIT2);  // для R3

    bool maj = majority(clock1, clock2, clock3);

    // Сдвигаем регистры
    if (clock1 == maj) shiftR1();
    if (clock2 == maj) shiftR2();
    if (clock3 == maj) shiftR3();
    shiftR4();  // R4 всегда сдвигается

    // Вычисляем F* для каждого регистра
    bool f1 = majorityFromBits(m_r1, R1_F_BITS[0], R1_F_BITS[1], R1_F_BITS[2]);
    bool f2 = majorityFromBits(m_r2, R2_F_BITS[0], R2_F_BITS[1], R2_F_BITS[2]);
    bool f3 = majorityFromBits(m_r3, R3_F_BITS[0], R3_F_BITS[1], R3_F_BITS[2]);

    // Выходной бит = XOR старших битов и F*
    bool out1 = (m_r1 >> (R1_LEN - 1)) & 1;
    bool out2 = (m_r2 >> (R2_LEN - 1)) & 1;
    bool out3 = (m_r3 >> (R3_LEN - 1)) & 1;

    return out1 ^ out2 ^ out3 ^ f1 ^ f2 ^ f3;
}

std::bitset<1024> A52Cipher::generateGamma(int numBits)
{
    std::bitset<1024> gamma;
    for (int i = 0; i < numBits; ++i) {
        bool bit = generateKeystreamBit();
        if (bit) {
            gamma.set(numBits - 1 - i);
        }
    }
    return gamma;
}

std::bitset<1024> A52Cipher::textToBits(const QString& text, int& totalBits) const
{
    std::bitset<1024> result;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    totalBits = filtered.length() * 5;

    for (int i = 0; i < filtered.length(); ++i) {
        int pos = m_alphabet.indexOf(filtered[i]);
        if (pos >= 0 && pos < 32) {
            for (int b = 0; b < 5; ++b) {
                bool bit = (pos >> (4 - b)) & 1;
                int bitPos = (i * 5) + b;
                if (bitPos < totalBits) {
                    result.set(totalBits - 1 - bitPos, bit);
                }
            }
        }
    }
    return result;
}

QString A52Cipher::bitsToText(const std::bitset<1024>& bits, int totalBits) const
{
    QString result;
    int numLetters = totalBits / 5;

    for (int i = 0; i < numLetters; ++i) {
        int pos = 0;
        for (int b = 0; b < 5; ++b) {
            int bitPos = (i * 5) + b;
            if (bitPos < totalBits && bits[totalBits - 1 - bitPos]) {
                pos |= (1 << (4 - b));
            }
        }
        if (pos < m_alphabet.length()) {
            result.append(m_alphabet[pos]);
        }
    }
    return result;
}

CipherResult A52Cipher::processText(const QString& text, const std::bitset<64>& key, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало работы A5/2", "Инициализация"));

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Входной текст: %1").arg(filteredText.left(50)),
        "Подготовка данных"));

    int totalBits;
    std::bitset<1024> textBits = textToBits(filteredText, totalBits);

    steps.append(CipherStep(2, QChar(),
        QString("Всего бит: %1").arg(totalBits),
        "Преобразование текста"));

    initializeRegisters(key, 0);

    steps.append(CipherStep(3, QChar(), "Инициализация регистров (кадр 0)", "Инициализация"));

    std::bitset<1024> gamma = generateGamma(totalBits);

    QString gammaPreview;
    for (int i = 0; i < qMin(20, totalBits); ++i) {
        gammaPreview.append(gamma[totalBits - 1 - i] ? '1' : '0');
    }
    steps.append(CipherStep(4, QChar(),
        QString("Гамма (первые %1 бит): %2...").arg(qMin(20, totalBits)).arg(gammaPreview),
        "Генерация гаммы"));

    std::bitset<1024> resultBits;
    for (int i = 0; i < totalBits; ++i) {
        resultBits[i] = textBits[i] ^ gamma[i];
    }

    QString resultText = bitsToText(resultBits, totalBits);

    steps.append(CipherStep(5, QChar(),
        QString("Результат: %1").arg(resultText),
        "Завершение"));

    result.result = resultText;
    result.steps = steps;

    return result;
}

CipherResult A52Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    QString keyType = params.value("keyType", "binary").toString();
    std::bitset<64> key;

    if (keyType == "binary") {
        QString binaryKey = params.value("binaryKey", "").toString();
        binaryKey.remove(QChar(' '));
        int keyLen = qMin(binaryKey.length(), 64);
        for (int i = 0; i < keyLen; ++i) {
            if (binaryKey[i] == '1') {
                key.set(63 - i);
            }
        }
    } else {
        QString textKey = params.value("textKey", "").toString();
        int totalBits;
        std::bitset<1024> textBits = textToBits(textKey, totalBits);
        for (int i = 0; i < 64; ++i) {
            key.set(63 - i, textBits[63 - i]);
        }
    }

    return processText(text, key, true);
}

CipherResult A52Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    return encrypt(text, params);
}

// ==================== A52CipherRegister Implementation ====================

A52CipherRegister::A52CipherRegister()
{
    CipherFactory::instance().registerCipher(
        "a52",
        "A5/2 ",
        []() -> CipherInterface* { return new A52Cipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "a52",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Пустые основные виджеты - ничего не добавляем
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
        },
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Выбор типа ключа
            QHBoxLayout* typeRow = new QHBoxLayout();
            QLabel* typeLabel = new QLabel("Тип ключа:");
            typeLabel->setFixedWidth(100);
            QComboBox* typeCombo = new QComboBox();
            typeCombo->addItem("Двоичный (64 бита)", "binary");
            typeCombo->addItem("Текстовый (13 букв)", "text");
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
            QLabel* binaryLabel = new QLabel("Ключ (64 бита):");
            binaryLabel->setFixedWidth(100);
            A52BinaryKeyEdit* binaryEdit = new A52BinaryKeyEdit();
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
            QLabel* textLabel = new QLabel("Ключ (13 букв):");
            textLabel->setFixedWidth(100);
            A52TextKeyEdit* textEdit = new A52TextKeyEdit();
            textEdit->setObjectName("textKey");
            textEdit->setAlphabet(QStringLiteral(u"АБВГДЕЖЗИЙКЛМНОПРСТУФХЦЧШЩЪЫЬЭЮЯ"));
            textEdit->setText("АБВГДЕЖЗИЙКЛ");
            textLayout->addWidget(textLabel);
            textLayout->addWidget(textEdit);
            textLayout->addStretch();
            stackedWidget->addWidget(textWidget);

            mainLayout->addWidget(stackedWidget);

            layout->addWidget(paramsContainer);

            widgets["keyType"] = typeCombo;
            widgets["binaryKey"] = binaryEdit;
            widgets["textKey"] = textEdit;
            widgets["stackedWidget"] = stackedWidget;

            QObject::connect(typeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                [stackedWidget](int index) {
                    stackedWidget->setCurrentIndex(index);
                });
        }
    );
}


static A52CipherRegister a52Register;
