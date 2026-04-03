#include "kuznechik.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <cstring>

// ==================== S-блок из ГОСТ Р 34.12-2015 (раздел 4.1.1) ====================
const std::array<uint8_t, 256> KuznechikCipher::PI = {
    0xFC, 0xEE, 0xDD, 0x11, 0xCF, 0x6E, 0x31, 0x16, 0xFB, 0xC4, 0xFA, 0xDA, 0x23, 0xC5, 0x04, 0x4D,
    0xE9, 0x77, 0xF0, 0xDB, 0x93, 0x2E, 0x99, 0xBA, 0x17, 0x36, 0xF1, 0xBB, 0x14, 0xCD, 0x5F, 0xC1,
    0xF9, 0x18, 0x65, 0x5A, 0xE2, 0x5C, 0xEF, 0x21, 0x81, 0x1C, 0x3C, 0x42, 0x8B, 0x01, 0x8E, 0x4F,
    0x05, 0x84, 0x02, 0xAE, 0xE3, 0x6A, 0x8F, 0xA0, 0x06, 0x0B, 0xED, 0x98, 0x7F, 0xD4, 0xD3, 0x1F,
    0xEB, 0x34, 0x2C, 0x51, 0xEA, 0xC8, 0x48, 0xAB, 0xF2, 0x2A, 0x68, 0xA2, 0xFD, 0x3A, 0xCE, 0xCC,
    0xB5, 0x70, 0x0E, 0x56, 0x08, 0x0C, 0x76, 0x12, 0xBF, 0x72, 0x13, 0x47, 0x9C, 0xB7, 0x5D, 0x87,
    0x15, 0xA1, 0x96, 0x29, 0x10, 0x7B, 0x9A, 0xC7, 0xF3, 0x91, 0x78, 0x6F, 0x9D, 0x9E, 0xB2, 0xB1,
    0x32, 0x75, 0x19, 0x3D, 0xFF, 0x35, 0x8A, 0x7E, 0x6D, 0x54, 0xC6, 0x80, 0xC3, 0xBD, 0x0D, 0x57,
    0xDF, 0xF5, 0x24, 0xA9, 0x3E, 0xA8, 0x43, 0xC9, 0xD7, 0x79, 0xD6, 0xF6, 0x7C, 0x22, 0xB9, 0x03,
    0xE0, 0x0F, 0xEC, 0xDE, 0x7A, 0x94, 0xB0, 0xBC, 0xDC, 0xE8, 0x28, 0x50, 0x4E, 0x33, 0x0A, 0x4A,
    0xA7, 0x97, 0x60, 0x73, 0x1E, 0x00, 0x62, 0x44, 0x1A, 0xB8, 0x38, 0x82, 0x64, 0x9F, 0x26, 0x41,
    0xAD, 0x45, 0x46, 0x92, 0x27, 0x5E, 0x55, 0x2F, 0x8C, 0xA3, 0xA5, 0x7D, 0x69, 0xD5, 0x95, 0x3B,
    0x07, 0x58, 0xB3, 0x40, 0x86, 0xAC, 0x1D, 0xF7, 0x30, 0x37, 0x6B, 0xE4, 0x88, 0xD9, 0xE7, 0x89,
    0xE1, 0x1B, 0x83, 0x49, 0x4C, 0x3F, 0xF8, 0xFE, 0x8D, 0x53, 0xAA, 0x90, 0xCA, 0xD8, 0x85, 0x61,
    0x20, 0x71, 0x67, 0xA4, 0x2D, 0x2B, 0x09, 0x5B, 0xCB, 0x9B, 0x25, 0xD0, 0xBE, 0xE5, 0x6C, 0x52,
    0x59, 0xA6, 0x74, 0xD2, 0xE6, 0xF4, 0xB4, 0xC0, 0xD1, 0x66, 0xAF, 0xC2, 0x39, 0x4B, 0x63, 0xB6
};

// Обратный S-блок
const std::array<uint8_t, 256> KuznechikCipher::PI_INV = []() {
    std::array<uint8_t, 256> inv{};
    for (int i = 0; i < 256; ++i) {
        inv[PI[i]] = i;
    }
    return inv;
}();

// Коэффициенты для линейного преобразования L (раздел 4.1.2)
const std::array<uint8_t, 16> KuznechikCipher::L_VEC = {
    148, 32, 133, 16, 194, 192, 1, 251, 1, 192, 194, 16, 133, 32, 148, 1
};

// ==================== KuznechikHexEdit ====================
KuznechikHexEdit::KuznechikHexEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(hexRegex, this);
    setValidator(validator);
    setPlaceholderText("HEX (0-9, A-F)");
}

void KuznechikHexEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("KuznechikHexEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void KuznechikHexEdit::setExpectedLength(int bytes)
{
    m_expectedBytes = bytes;
    if (bytes > 0) {
        setPlaceholderText(QString("HEX (%1 байт, %2 символа)").arg(bytes).arg(bytes * 2));
        setMaxLength(bytes * 2);
    }
}

void KuznechikHexEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) setValid(true);
    QLineEdit::focusInEvent(event);
}

void KuznechikHexEdit::focusOutEvent(QFocusEvent* event)
{
    QString txt = text().trimmed();
    if (!txt.isEmpty() && m_expectedBytes > 0 && txt.length() != m_expectedBytes * 2) {
        setValid(false);
        setToolTip(QString("Требуется %1 HEX-символов (%2 байт)").arg(m_expectedBytes * 2).arg(m_expectedBytes));
    }
    QLineEdit::focusOutEvent(event);
}

QString KuznechikHexEdit::getHex() const { return text().trimmed().toUpper(); }
void KuznechikHexEdit::setHex(const QString& hex) { setText(hex.toUpper()); }

// ==================== Арифметика GF(2^8) ====================
// Исправленная функция умножения с неприводимым многочленом x^8 + x^7 + x^6 + x + 1 (0x1C3)
uint8_t KuznechikCipher::gf256Mul(uint8_t a, uint8_t b) const
{
    uint16_t c = 0;               // используем 16-бит для промежуточных результатов
    uint16_t aa = a;
    while (b) {
        if (b & 1) c ^= aa;
        aa <<= 1;
        if (aa & 0x100) aa ^= 0x1C3; // редукция по модулю 0x1C3
        b >>= 1;
    }
    return static_cast<uint8_t>(c & 0xFF);
}

// ==================== Базовые преобразования ====================
void KuznechikCipher::X(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const
{
    for (int i = 0; i < 16; ++i) {
        state[i] ^= key[i];
    }
}

void KuznechikCipher::S(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; ++i) {
        state[i] = PI[state[i]];
    }
}

void KuznechikCipher::invS(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; ++i) {
        state[i] = PI_INV[state[i]];
    }
}

void KuznechikCipher::R(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp;
    uint8_t l = 0;
    for (int i = 0; i < 16; ++i) {
        l ^= gf256Mul(state[i], L_VEC[i]);
    }
    for (int i = 0; i < 15; ++i) {
        temp[i + 1] = state[i];
    }
    temp[0] = l;
    state = temp;
}

void KuznechikCipher::invR(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp;
    for (int i = 0; i < 15; ++i) {
        temp[i] = state[i + 1];
    }
    uint8_t l = 0;
    for (int i = 0; i < 15; ++i) {
        l ^= gf256Mul(state[i + 1], L_VEC[i]);
    }
    l ^= gf256Mul(state[0], L_VEC[15]);
    temp[15] = l;
    state = temp;
}

void KuznechikCipher::L(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; ++i) {
        R(state);
    }
}

void KuznechikCipher::invL(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; ++i) {
        invR(state);
    }
}

void KuznechikCipher::LSX(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const
{
    X(state, key);
    S(state);
    L(state);
}

void KuznechikCipher::invLSX(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& key) const
{
    invL(state);
    invS(state);
    X(state, key);
}

void KuznechikCipher::F(std::array<uint8_t, 16>& out1, std::array<uint8_t, 16>& out2,
                         const std::array<uint8_t, 16>& in1, const std::array<uint8_t, 16>& in2,
                         const std::array<uint8_t, 16>& iterConst) const
{
    out2 = in1;
    std::array<uint8_t, 16> temp = in1;
    X(temp, iterConst);
    S(temp);
    L(temp);
    X(temp, in2);
    out1 = temp;
}

// ==================== Генерация итерационных констант C1..C32 ====================
std::array<std::array<uint8_t, 16>, 32> KuznechikCipher::generateIterConstants() const
{
    std::array<std::array<uint8_t, 16>, 32> C;
    std::array<uint8_t, 16> zero = {0};

    for (int i = 1; i <= 32; ++i) {
        std::array<uint8_t, 16> ic = zero;
        ic[15] = static_cast<uint8_t>(i); // iter_const_i: последний байт = i
        L(ic);                            // C_i = L(iter_const_i)
        C[i - 1] = ic;
    }
    return C;
}

// ==================== Развертывание ключа ====================
std::array<std::array<uint8_t, 16>, 10> KuznechikCipher::expandKey(const std::array<uint8_t, 32>& masterKey) const
{
    std::array<std::array<uint8_t, 16>, 10> roundKeys;

    // K1, K2
    for (int i = 0; i < 16; ++i) {
        roundKeys[0][i] = masterKey[i];
        roundKeys[1][i] = masterKey[i + 16];
    }

    std::array<std::array<uint8_t, 16>, 32> C = generateIterConstants();

    std::array<uint8_t, 16> A = roundKeys[0];  // K1
    std::array<uint8_t, 16> B = roundKeys[1];  // K2

    // Блок i=0: C1..C8 → K3, K4
    for (int j = 0; j < 8; ++j) {
        std::array<uint8_t, 16> newA, newB;
        F(newA, newB, A, B, C[j]);
        A = newA;
        B = newB;
    }
    roundKeys[2] = A;  // K3
    roundKeys[3] = B;  // K4

    // Блок i=1: C9..C16 → K5, K6
    for (int j = 8; j < 16; ++j) {
        std::array<uint8_t, 16> newA, newB;
        F(newA, newB, A, B, C[j]);
        A = newA;
        B = newB;
    }
    roundKeys[4] = A;  // K5
    roundKeys[5] = B;  // K6

    // Блок i=2: C17..C24 → K7, K8
    for (int j = 16; j < 24; ++j) {
        std::array<uint8_t, 16> newA, newB;
        F(newA, newB, A, B, C[j]);
        A = newA;
        B = newB;
    }
    roundKeys[6] = A;  // K7
    roundKeys[7] = B;  // K8

    // Блок i=3: C25..C32 → K9, K10
    for (int j = 24; j < 32; ++j) {
        std::array<uint8_t, 16> newA, newB;
        F(newA, newB, A, B, C[j]);
        A = newA;
        B = newB;
    }
    roundKeys[8] = A;  // K9
    roundKeys[9] = B;  // K10

    return roundKeys;
}

// ==================== Вспомогательные функции ====================
QString KuznechikCipher::prepareHexInput(const QString& text) const
{
    QString filtered;
    QRegularExpression hexRegex("[0-9A-Fa-f]");
    QRegularExpressionMatchIterator it = hexRegex.globalMatch(text);
    while (it.hasNext()) {
        filtered.append(it.next().captured());
    }
    return filtered.toUpper();
}

QString KuznechikCipher::bytesToHex(const uint8_t* data, int len) const
{
    QString result;
    for (int i = 0; i < len; ++i) {
        result.append(QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper());
    }
    return result;
}

void KuznechikCipher::hexToBytes(const QString& hex, uint8_t* out, int len) const
{
    QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
    for (int i = 0; i < len && i < bytes.size(); ++i) {
        out[i] = static_cast<uint8_t>(bytes[i]);
    }
}

// ==================== Конструктор ====================
KuznechikCipher::KuznechikCipher()
{
}

// ==================== Шифрование ====================
CipherResult KuznechikCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования Кузнечик", "Инициализация"));

    QString keyHex = params.value("key", "").toString();
    QString cleanedKey = prepareHexInput(keyHex);

    if (cleanedKey.length() != 64) {
        result.result = QString("ОШИБКА: Ключ должен быть 64 HEX символа. Получено: %1")
                        .arg(cleanedKey.length());
        return result;
    }

    steps.append(CipherStep(1, QChar(), QString("Ключ: %1").arg(cleanedKey), "Параметры"));

    QString hexData = prepareHexInput(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных для шифрования";
        return result;
    }

    if (hexData.length() % 32 != 0) {
        result.result = QString("ОШИБКА: Длина данных должна быть кратна 32 HEX символам. Получено: %1")
                        .arg(hexData.length());
        return result;
    }

    steps.append(CipherStep(2, QChar(), QString("Входные данные: %1").arg(hexData), "Данные"));

    // Преобразуем ключ
    std::array<uint8_t, 32> masterKey{};
    hexToBytes(cleanedKey, masterKey.data(), 32);

    // Разворачиваем ключи
    std::array<std::array<uint8_t, 16>, 10> roundKeys = expandKey(masterKey);

    // Выводим все итерационные ключи
    steps.append(CipherStep(3, QChar(), "Развертывание ключа:", "Развертывание ключа"));
    for (int r = 0; r < 10; ++r) {
        QString keyStr = bytesToHex(roundKeys[r].data(), 16);
        steps.append(CipherStep(4 + r, QChar(),
            QString("K%1 = %2").arg(r + 1).arg(keyStr),
            QString("Раундовый ключ %1").arg(r + 1)));
    }

    // Шифрование блока
    std::array<uint8_t, 16> state{};
    hexToBytes(hexData, state.data(), 16);

    steps.append(CipherStep(14, QChar(),
        QString("Начальное состояние: %1").arg(bytesToHex(state.data(), 16)),
        "Начало"));

    // Раунды 1-9: LSX[Ki]
    for (int r = 0; r < 9; ++r) {
        // X
        X(state, roundKeys[r]);
        steps.append(CipherStep(15 + r * 3, QChar(),
            QString("Раунд %1: X[K%2] = %3").arg(r + 1).arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - X").arg(r + 1)));
        // S
        S(state);
        steps.append(CipherStep(16 + r * 3, QChar(),
            QString("Раунд %1: S = %2").arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - S").arg(r + 1)));
        // L
        L(state);
        steps.append(CipherStep(17 + r * 3, QChar(),
            QString("Раунд %1: L = %2").arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - L").arg(r + 1)));
    }

    // Финальный раунд: X[K10]
    X(state, roundKeys[9]);
    steps.append(CipherStep(42, QChar(),
        QString("Финальный X[K10] = %1").arg(bytesToHex(state.data(), 16)),
        "Финальный раунд"));

    QString encryptedHex = bytesToHex(state.data(), 16);
    steps.append(CipherStep(43, QChar(),
        QString("Результат: %1").arg(encryptedHex),
        "Завершение"));

    result.result = encryptedHex;
    result.steps = steps;

    return result;
}

// ==================== Расшифрование ====================
CipherResult KuznechikCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало расшифрования Кузнечик", "Инициализация"));

    QString keyHex = params.value("key", "").toString();
    QString cleanedKey = prepareHexInput(keyHex);

    if (cleanedKey.length() != 64) {
        result.result = QString("ОШИБКА: Ключ должен быть 64 HEX символа. Получено: %1")
                        .arg(cleanedKey.length());
        return result;
    }

    steps.append(CipherStep(1, QChar(), QString("Ключ: %1").arg(cleanedKey), "Параметры"));

    QString hexData = prepareHexInput(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных для расшифрования";
        return result;
    }

    if (hexData.length() % 32 != 0) {
        result.result = QString("ОШИБКА: Длина данных должна быть кратна 32 HEX символам. Получено: %1")
                        .arg(hexData.length());
        return result;
    }

    steps.append(CipherStep(2, QChar(), QString("Входные данные: %1").arg(hexData), "Данные"));

    std::array<uint8_t, 32> masterKey{};
    hexToBytes(cleanedKey, masterKey.data(), 32);

    std::array<std::array<uint8_t, 16>, 10> roundKeys = expandKey(masterKey);

    steps.append(CipherStep(3, QChar(), "Развернуто 10 итерационных ключей", "Развертывание ключа"));

    std::array<uint8_t, 16> state{};
    hexToBytes(hexData, state.data(), 16);

    steps.append(CipherStep(4, QChar(),
        QString("Начальное состояние: %1").arg(bytesToHex(state.data(), 16)),
        "Начало"));

    // X[K10]
    X(state, roundKeys[9]);
    steps.append(CipherStep(5, QChar(),
        QString("После X[K10]: %1").arg(bytesToHex(state.data(), 16)),
        "Начальный X"));

    // Раунды 8..1: invLSX
    for (int r = 8; r >= 0; --r) {
        // invL
        invL(state);
        steps.append(CipherStep(6 + (8 - r) * 3, QChar(),
            QString("Раунд %1: L⁻¹ = %2").arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - L⁻¹").arg(r + 1)));
        // invS
        invS(state);
        steps.append(CipherStep(7 + (8 - r) * 3, QChar(),
            QString("Раунд %1: S⁻¹ = %2").arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - S⁻¹").arg(r + 1)));
        // X[Kr]
        X(state, roundKeys[r]);
        steps.append(CipherStep(8 + (8 - r) * 3, QChar(),
            QString("Раунд %1: X[K%2] = %3").arg(r + 1).arg(r + 1).arg(bytesToHex(state.data(), 16)),
            QString("Раунд %1 - X").arg(r + 1)));
    }

    QString decryptedHex = bytesToHex(state.data(), 16);
    steps.append(CipherStep(35, QChar(),
        QString("Результат: %1").arg(decryptedHex),
        "Завершение"));

    result.result = decryptedHex;
    result.steps = steps;

    return result;
}

// ==================== Регистратор ====================
KuznechikCipherRegister::KuznechikCipherRegister()
{
    CipherFactory::instance().registerCipher(
        20,
        "Кузнечик (ГОСТ Р 34.12-2015)",
        []() -> CipherInterface* { return new KuznechikCipher(); },
        CipherCategory::Combinatorial
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "kuznechik",
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* vbox = new QVBoxLayout(container);

            QHBoxLayout* keyRow = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Ключ (256 бит):");
            keyLabel->setFixedWidth(120);
            KuznechikHexEdit* keyEdit = new KuznechikHexEdit();
            keyEdit->setExpectedLength(32);
            keyEdit->setObjectName("key");
            keyEdit->setHex("8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef");
            keyRow->addWidget(keyLabel);
            keyRow->addWidget(keyEdit);
            keyRow->addStretch();
            vbox->addLayout(keyRow);

            QLabel* infoLabel = new QLabel(
                "Кузнечик (ГОСТ Р 34.12-2015) — блочный шифр с SP-сетью:\n"
                "• Длина блока: 128 бит (32 HEX символа)\n"
                "• Длина ключа: 256 бит (64 HEX символа)\n"
                "• Количество раундов: 10\n\n"
                "Контрольный пример (А.1.5):\n"
                "  Ключ: 8899aabbccddeeff0011223344556677fedcba98765432100123456789abcdef\n"
                "  Открытый текст: 1122334455667700ffeeddccbbaa9988\n"
                "  Ожидаемый шифртекст: 7f679d90bebc24305a468d42b9d4edcd"
            );
            infoLabel->setStyleSheet("color: #666; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            vbox->addWidget(infoLabel);

            layout->addWidget(container);

            widgets["key"] = keyEdit;
        }
    );
}

static KuznechikCipherRegister kuznechikRegister;
