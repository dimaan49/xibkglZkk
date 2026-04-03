#include "magma_ctr.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <cstring>

// ==================== S-блоки ГОСТ Р 34.12-2015 (раздел 5.1.1) ====================
const std::array<uint8_t, 16> MagmaCTRCipher::PI0 = {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1};
const std::array<uint8_t, 16> MagmaCTRCipher::PI1 = {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15};
const std::array<uint8_t, 16> MagmaCTRCipher::PI2 = {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0};
const std::array<uint8_t, 16> MagmaCTRCipher::PI3 = {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11};
const std::array<uint8_t, 16> MagmaCTRCipher::PI4 = {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12};
const std::array<uint8_t, 16> MagmaCTRCipher::PI5 = {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0};
const std::array<uint8_t, 16> MagmaCTRCipher::PI6 = {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7};
const std::array<uint8_t, 16> MagmaCTRCipher::PI7 = {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2};

// ==================== MagmaCTRHexEdit ====================
MagmaCTRHexEdit::MagmaCTRHexEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(hexRegex, this);
    setValidator(validator);
    setPlaceholderText("HEX (0-9, A-F)");
}

void MagmaCTRHexEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("MagmaCTRHexEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void MagmaCTRHexEdit::setExpectedLength(int bytes)
{
    m_expectedBytes = bytes;
    if (bytes > 0) {
        setPlaceholderText(QString("HEX (%1 байт, %2 символа)").arg(bytes).arg(bytes * 2));
        setMaxLength(bytes * 2);
    }
}

void MagmaCTRHexEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) setValid(true);
    QLineEdit::focusInEvent(event);
}

void MagmaCTRHexEdit::focusOutEvent(QFocusEvent* event)
{
    QString txt = text().trimmed();
    if (!txt.isEmpty() && m_expectedBytes > 0 && txt.length() != m_expectedBytes * 2) {
        setValid(false);
        setToolTip(QString("Требуется %1 HEX-символов (%2 байт)").arg(m_expectedBytes * 2).arg(m_expectedBytes));
    }
    QLineEdit::focusOutEvent(event);
}

QString MagmaCTRHexEdit::getHex() const { return text().trimmed().toUpper(); }
void MagmaCTRHexEdit::setHex(const QString& hex) { setText(hex.toUpper()); }

// ==================== MagmaCTRCipher Implementation ====================

MagmaCTRCipher::MagmaCTRCipher()
{
}

QString MagmaCTRCipher::prepareHexInput(const QString& text) const
{
    QString filtered;
    QRegularExpression hexRegex("[0-9A-Fa-f]");
    QRegularExpressionMatchIterator it = hexRegex.globalMatch(text);
    while (it.hasNext()) {
        filtered.append(it.next().captured());
    }
    return filtered.toUpper();
}

QString MagmaCTRCipher::bytesToHex(const uint8_t* data, int len) const
{
    QString result;
    for (int i = 0; i < len; i++) {
        result.append(QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper());
    }
    return result;
}

void MagmaCTRCipher::hexToBytes(const QString& hex, uint8_t* out, int len) const
{
    QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
    for (int i = 0; i < len && i < bytes.size(); i++) {
        out[i] = static_cast<uint8_t>(bytes[i]);
    }
}

uint32_t MagmaCTRCipher::hexToUint32(const QString& hex) const
{
    bool ok;
    uint32_t value = hex.toUInt(&ok, 16);
    return ok ? value : 0;
}

QString MagmaCTRCipher::uint32ToHex(uint32_t value) const
{
    return QString("%1").arg(value, 8, 16, QChar('0')).toUpper();
}

uint64_t MagmaCTRCipher::hexToUint64(const QString& hex) const
{
    bool ok;
    uint64_t value = hex.toULongLong(&ok, 16);
    return ok ? value : 0;
}

QString MagmaCTRCipher::uint64ToHex(uint64_t value) const
{
    return QString("%1").arg(value, 16, 16, QChar('0')).toUpper();
}

// ==================== Преобразование t (формула 14) ====================
// t(a) = t(a7||...||a0) = π7(a7)||...||π0(a0)
uint32_t MagmaCTRCipher::tTransform(uint32_t x) const
{
    uint32_t result = 0;

    for (int i = 0; i < 8; ++i) {
        uint8_t nibble = (x >> (4 * i)) & 0xF;
        uint8_t substituted;

        switch (i) {
            case 0: substituted = PI0[nibble]; break;
            case 1: substituted = PI1[nibble]; break;
            case 2: substituted = PI2[nibble]; break;
            case 3: substituted = PI3[nibble]; break;
            case 4: substituted = PI4[nibble]; break;
            case 5: substituted = PI5[nibble]; break;
            case 6: substituted = PI6[nibble]; break;
            case 7: substituted = PI7[nibble]; break;
            default: substituted = nibble;
        }

        result |= (static_cast<uint32_t>(substituted) << (4 * i));
    }

    return result;
}

// Циклический сдвиг влево на 11 бит
uint32_t MagmaCTRCipher::leftShift11(uint32_t x) const
{
    return (x << 11) | (x >> (32 - 11));
}

// Функция g (формула 15): g[k](a) = (t((a + k) mod 2^32)) <<< 11
uint32_t MagmaCTRCipher::gFunction(uint32_t a, uint32_t k) const
{
    uint32_t sum = a + k;
    uint32_t transformed = tTransform(sum);
    return leftShift11(transformed);
}

// Раундовое преобразование G (формула 16): G[k](a1, a0) = (a0, g[k](a0) ⊕ a1)
std::pair<uint32_t, uint32_t> MagmaCTRCipher::G(uint32_t a1, uint32_t a0, uint32_t k) const
{
    return std::make_pair(a0, gFunction(a0, k) ^ a1);
}

// Заключительное преобразование G* (формула 17): G*[k](a1, a0) = (g[k](a0) ⊕ a1) || a0
uint64_t MagmaCTRCipher::GStar(uint32_t a1, uint32_t a0, uint32_t k) const
{
    uint32_t left = gFunction(a0, k) ^ a1;
    return (static_cast<uint64_t>(left) << 32) | static_cast<uint64_t>(a0);
}

// ==================== Развертывание ключа (формула 18) ====================
std::array<uint32_t, 32> MagmaCTRCipher::keySchedule(const QString& keyHex) const
{
    std::array<uint32_t, 32> roundKeys;
    roundKeys.fill(0);

    QString cleanKey = prepareHexInput(keyHex);

    // Ключ должен быть 64 HEX символа (256 бит)
    if (cleanKey.length() < 64) {
        cleanKey = cleanKey.leftJustified(64, '0', true);
    }
    if (cleanKey.length() > 64) {
        cleanKey = cleanKey.left(64);
    }

    // Разбираем 256-битный ключ на 8 32-битных частей (big-endian)
    std::array<uint32_t, 8> keyParts;
    for (int i = 0; i < 8; ++i) {
        QString partHex = cleanKey.mid(i * 8, 8);
        keyParts[i] = hexToUint32(partHex);
    }

    // Формируем 32 итерационных ключа по формуле 18:
    // K1..K8 = ключ
    // K9..K16 = K1..K8
    // K17..K24 = K1..K8
    // K25..K32 = K8..K1
    for (int i = 0; i < 24; ++i) {
        roundKeys[i] = keyParts[i % 8];
    }
    for (int i = 0; i < 8; ++i) {
        roundKeys[24 + i] = keyParts[7 - i];
    }

    return roundKeys;
}

// ==================== Шифрование одного блока (формула 19) ====================
// E(a) = G*[K32] ◦ G[K31] ◦ ... ◦ G[K2] ◦ G[K1](a1, a0)
uint64_t MagmaCTRCipher::encryptBlock(uint64_t block, const std::array<uint32_t, 32>& roundKeys) const
{
    // Разбиваем 64-битный блок на две 32-битные половины (big-endian)
    uint32_t a1 = static_cast<uint32_t>(block >> 32);
    uint32_t a0 = static_cast<uint32_t>(block & 0xFFFFFFFF);

    // Раунды 1..31: G[K1]..G[K31]
    for (int i = 0; i < 31; ++i) {
        auto result = G(a1, a0, roundKeys[i]);
        a1 = result.first;
        a0 = result.second;
    }

    // Раунд 32: G*[K32]
    return GStar(a1, a0, roundKeys[31]);
}

// ==================== Режим CTR (ГОСТ Р 34.13-2015, раздел 5.2) ====================
QByteArray MagmaCTRCipher::ctrProcess(const QByteArray& data, const QString& keyHex, const QString& ivHex) const
{
    if (data.isEmpty()) return QByteArray();

    // Разворачиваем ключ
    std::array<uint32_t, 32> roundKeys = keySchedule(keyHex);

    // IV — 64-битная синхропосылка (16 HEX символов)
    QString cleanIV = prepareHexInput(ivHex);
    if (cleanIV.length() < 16) {
        cleanIV = cleanIV.leftJustified(16, '0', true);
    } else if (cleanIV.length() > 16) {
        cleanIV = cleanIV.left(16);
    }

    // Преобразуем IV в 64-битное число (big-endian)
    uint64_t ctr = 0;
    for (int i = 0; i < 8; ++i) {
        ctr = (ctr << 8) | cleanIV.mid(i * 2, 2).toUInt(nullptr, 16);
    }

    QByteArray result;
    result.reserve(data.size());

    // Обрабатываем данные блоками по 8 байт (64 бита)
    for (int i = 0; i < data.size(); i += 8) {
        // Текущий блок счетчика
        uint64_t inputBlock = ctr;

        // Гамма = E(счетчик, ключ)
        uint64_t gamma = encryptBlock(inputBlock, roundKeys);

        // Преобразуем гамму в байты (big-endian)
        QByteArray gammaBytes(8, 0);
        for (int j = 0; j < 8; ++j) {
            gammaBytes[j] = static_cast<char>((gamma >> (56 - j * 8)) & 0xFF);
        }

        // Берем блок данных
        QByteArray chunk = data.mid(i, 8);

        // XOR гаммы с данными
        QByteArray encryptedBlock(8, 0);
        for (int j = 0; j < chunk.size(); ++j) {
            encryptedBlock[j] = chunk[j] ^ gammaBytes[j];
        }

        // Обрезаем до исходной длины для последнего блока
        if (i + 8 > data.size()) {
            int remaining = data.size() - i;
            result.append(encryptedBlock.left(remaining));
        } else {
            result.append(encryptedBlock);
        }

        // Инкрементируем счетчик (по модулю 2^64)
        ctr++;
    }

    return result;
}

// ==================== Шифрование ====================
CipherResult MagmaCTRCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования Магма (режим CTR)", "Инициализация"));

    // Получаем параметры
    QString keyHex = params.value("key", "").toString();
    QString ivHex = params.value("iv", "").toString();

    steps.append(CipherStep(1, QChar(),
        QString("Ключ: %1").arg(keyHex.isEmpty() ? "(пустой)" : keyHex.left(16) + "..."),
        "Параметры"));
    steps.append(CipherStep(2, QChar(),
        QString("Синхропосылка (IV): %1").arg(ivHex.isEmpty() ? "(пустая)" : ivHex),
        "Параметры"));

    // Проверяем ключ
    if (keyHex.isEmpty()) {
        result.result = "ОШИБКА: Не указан ключ шифрования (256 бит в HEX)";
        return result;
    }

    // Проверяем IV
    if (ivHex.isEmpty()) {
        result.result = "ОШИБКА: Не указана синхропосылка (IV) (64 бита в HEX)";
        return result;
    }

    // Подготавливаем входные данные
    QString hexData = prepareHexInput(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных для шифрования (введите HEX-строку)";
        return result;
    }

    steps.append(CipherStep(3, QChar(),
        QString("Входные данные (HEX): %1").arg(hexData.left(64) + (hexData.length() > 64 ? "..." : "")),
        "Данные"));

    // Преобразуем HEX-строку в байты
    QByteArray data = QByteArray::fromHex(hexData.toLatin1());

    steps.append(CipherStep(4, QChar(),
        QString("Длина данных: %1 байт").arg(data.size()),
        "Данные"));

    // Выполняем шифрование в режиме CTR
    QByteArray encrypted = ctrProcess(data, keyHex, ivHex);

    // Преобразуем результат в HEX
    QString resultHex = encrypted.toHex().toUpper();

    steps.append(CipherStep(5, QChar(),
        QString("Результат (HEX): %1").arg(resultHex.left(64) + (resultHex.length() > 64 ? "..." : "")),
        "Завершение"));

    result.result = resultHex;
    result.steps = steps;

    return result;
}

// ==================== Дешифрование ====================
// Для режима CTR дешифрование идентично шифрованию (XOR симметричен)
CipherResult MagmaCTRCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return encrypt(text, params);
}

// ==================== Регистратор ====================
MagmaCTRCipherRegister::MagmaCTRCipherRegister()
{
    CipherFactory::instance().registerCipher(
        15,
        "Магма CTR",
        []() -> CipherInterface* { return new MagmaCTRCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "magma_ctr",
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* vbox = new QVBoxLayout(container);
            vbox->setSpacing(8);
            vbox->setContentsMargins(0, 5, 0, 5);

            // Строка для ключа
            QHBoxLayout* keyRow = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Ключ (256 бит):");
            keyLabel->setFixedWidth(120);
            MagmaCTRHexEdit* keyEdit = new MagmaCTRHexEdit();
            keyEdit->setExpectedLength(32);
            keyEdit->setObjectName("key");
            keyEdit->setHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            keyRow->addWidget(keyLabel);
            keyRow->addWidget(keyEdit);
            keyRow->addStretch();
            vbox->addLayout(keyRow);

            // Строка для IV
            QHBoxLayout* ivRow = new QHBoxLayout();
            QLabel* ivLabel = new QLabel("Синхропосылка (IV):");
            ivLabel->setFixedWidth(120);
            MagmaCTRHexEdit* ivEdit = new MagmaCTRHexEdit();
            ivEdit->setExpectedLength(8);
            ivEdit->setObjectName("iv");
            ivEdit->setHex("12345678");
            ivRow->addWidget(ivLabel);
            ivRow->addWidget(ivEdit);
            ivRow->addStretch();
            vbox->addLayout(ivRow);

            // Информационная панель с контрольными примерами
            QLabel* infoLabel = new QLabel(
                "Магма (ГОСТ Р 34.12-2015) — режим гаммирования (CTR) по ГОСТ Р 34.13-2015:\n"
                "• Длина блока: 64 бита (16 HEX символов)\n"
                "• Длина ключа: 256 бит (64 HEX символа)\n"
                "• Длина синхропосылки (IV): 64 бита (16 HEX символов)\n"
                "• Вход/выход: HEX-строки любой длины\n\n"
                "Контрольный пример (ГОСТ Р 34.13-2015, А.2.2):\n"
                "  Ключ: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n"
                "  IV: 12345678\n"
                "  Открытый текст: 92def06b3c130a59\n"
                "  Шифртекст: 4e98110c97b7b93c"
            );
            infoLabel->setStyleSheet("color: #666; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            vbox->addWidget(infoLabel);

            layout->addWidget(container);

            widgets["key"] = keyEdit;
            widgets["iv"] = ivEdit;
        }
    );
}

static MagmaCTRCipherRegister magmaCTRRegister;
