#include "magmagamma.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QSpinBox>
#include <QTextEdit>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>

// ==================== S-блоки ГОСТ ====================

const std::array<uint8_t, 16> MagmaGammaCipher::PI0 = {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1};
const std::array<uint8_t, 16> MagmaGammaCipher::PI1 = {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15};
const std::array<uint8_t, 16> MagmaGammaCipher::PI2 = {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0};
const std::array<uint8_t, 16> MagmaGammaCipher::PI3 = {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11};
const std::array<uint8_t, 16> MagmaGammaCipher::PI4 = {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12};
const std::array<uint8_t, 16> MagmaGammaCipher::PI5 = {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0};
const std::array<uint8_t, 16> MagmaGammaCipher::PI6 = {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7};
const std::array<uint8_t, 16> MagmaGammaCipher::PI7 = {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2};

// ==================== HexLineEdit Implementation ====================

HexLineEdit::HexLineEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    // Валидатор для HEX
    QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(hexRegex, this);
    setValidator(validator);

    setPlaceholderText("HEX (только 0-9, A-F)");
}

void HexLineEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("HexLineEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void HexLineEdit::focusInEvent(QFocusEvent* event)
{
    // При получении фокуса сбрасываем красную подсветку
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

void HexLineEdit::focusOutEvent(QFocusEvent* event)
{
    // При потере фокуса проверяем длину
    QString text = this->text().replace(" ", "");
    if (!text.isEmpty()) {
        if (m_expectedBytes > 0 && text.length() != m_expectedBytes * 2) {
            setValid(false);
            setToolTip(QString("Требуется %1 HEX-символов (%2 байт)").arg(m_expectedBytes * 2).arg(m_expectedBytes));
        } else if (text.length() % 2 != 0) {
            setValid(false);
            setToolTip("HEX-строка должна иметь четную длину");
        }
    }
    QLineEdit::focusOutEvent(event);
}

// ==================== MagmaGammaCipher Implementation ====================

MagmaGammaCipher::MagmaGammaCipher()
{
}

QString MagmaGammaCipher::prepareHexInput(const QString& text) const
{
    QString filtered;
    QRegularExpression hexRegex("[0-9A-Fa-f]");
    QRegularExpressionMatchIterator it = hexRegex.globalMatch(text);
    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        filtered.append(match.captured());
    }
    return filtered.toUpper();
}

bool MagmaGammaCipher::isValidHex(const QString& text) const
{
    QString cleaned = prepareHexInput(text);
    return !cleaned.isEmpty() && (cleaned.length() % 2 == 0);
}

uint32_t MagmaGammaCipher::hexToUint32(const QString& hex) const
{
    bool ok;
    uint32_t value = hex.toUInt(&ok, 16);
    if (!ok) return 0;
    return value;
}

QString MagmaGammaCipher::uint32ToHex(uint32_t value) const
{
    return QString("%1").arg(value, 8, 16, QChar('0')).toUpper();
}

uint64_t MagmaGammaCipher::hexToUint64(const QString& hex) const
{
    bool ok;
    uint64_t value = hex.toULongLong(&ok, 16);
    if (!ok) return 0;
    return value;
}

QString MagmaGammaCipher::uint64ToHex(uint64_t value) const
{
    return QString("%1").arg(value, 16, 16, QChar('0')).toUpper();
}

// Нелинейное биективное преобразование t: V32 → V32
uint32_t MagmaGammaCipher::tTransform(uint32_t x) const
{
    uint32_t result = 0;

    // Разбиваем на 8 полубайт (4 бита) и заменяем каждый S-блоком
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
uint32_t MagmaGammaCipher::leftShift11(uint32_t x) const
{
    return (x << 11) | (x >> (32 - 11));
}

// Функция g[k](a) = (t((a + k) mod 2^32)) <<< 11
uint32_t MagmaGammaCipher::g(uint32_t a, uint32_t k) const
{
    uint32_t sum = a + k;  // Автоматическое переполнение по модулю 2^32
    uint32_t transformed = tTransform(sum);
    return leftShift11(transformed);
}

// Развертывание ключа (key schedule) по ГОСТ Р 34.12-2015
std::array<uint32_t, 32> MagmaGammaCipher::keySchedule(const QString& keyHex) const
{
    std::array<uint32_t, 32> roundKeys;
    roundKeys.fill(0);

    QString cleanKey = prepareHexInput(keyHex);

    // Если ключ пустой или слишком короткий, используем тестовый ключ
    if (cleanKey.length() < 64) {
        cleanKey = "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    }

    // Берем первые 64 символа (256 бит)
    if (cleanKey.length() > 64) {
        cleanKey = cleanKey.left(64);
    }

    // Разбираем 256-битный ключ на 8 32-битных частей (big-endian)
    std::array<uint32_t, 8> keyParts;
    for (int i = 0; i < 8; ++i) {
        QString partHex = cleanKey.mid(i * 8, 8);
        keyParts[i] = hexToUint32(partHex);
    }

    // Формируем 32 итерационных ключа по формуле из ГОСТ:
    // Раунды 1-24: K1..K8, K1..K8, K1..K8 (трижды)
    // Раунды 25-32: K8..K1 (обратный порядок)
    for (int i = 0; i < 3; ++i) {
        for (int j = 0; j < 8; ++j) {
            roundKeys[i * 8 + j] = keyParts[j];
        }
    }

    // Последние 8 ключей в обратном порядке
    for (int j = 0; j < 8; ++j) {
        roundKeys[24 + j] = keyParts[7 - j];
    }

    return roundKeys;
}

// Шифрование одного 64-битного блока (как в Python-скрипте)
uint64_t MagmaGammaCipher::encryptBlock(uint64_t block, const std::array<uint32_t, 32>& roundKeys) const
{
    // Разбиваем блок на левую и правую части (по 32 бита)
    // В big-endian: a = a1 || a0, где a1 - старшие 32 бита, a0 - младшие
    uint32_t a1 = static_cast<uint32_t>(block >> 32);
    uint32_t a0 = static_cast<uint32_t>(block & 0xFFFFFFFF);

    // Раунды 1..31
    for (int i = 0; i < 31; ++i) {
        // G[k](a1, a0) = (a0, g[k](a0) xor a1)
        uint32_t new_a1 = a0;
        uint32_t new_a0 = g(a0, roundKeys[i]) ^ a1;
        a1 = new_a1;
        a0 = new_a0;
    }

    // Раунд 32: G*[k](a1, a0) = (g[k](a0) xor a1) || a0
    uint32_t left = g(a0, roundKeys[31]) ^ a1;

    // Результат: left (32 бита) || a0 (32 бита)
    return (static_cast<uint64_t>(left) << 32) | static_cast<uint64_t>(a0);
}

// Режим CTR для данных произвольной длины
QByteArray MagmaGammaCipher::ctrProcess(const QByteArray& data, const QString& keyHex, const QString& ivHex) const
{
    if (data.isEmpty()) return QByteArray();

    // Разворачиваем ключ
    std::array<uint32_t, 32> roundKeys = keySchedule(keyHex);

    // Преобразуем IV в 64-битный счетчик
    QString cleanIV = prepareHexInput(ivHex);
    if (cleanIV.length() < 16) {
        cleanIV = cleanIV.leftJustified(16, '0', true);
    } else if (cleanIV.length() > 16) {
        cleanIV = cleanIV.left(16);
    }
    uint64_t ctr = hexToUint64(cleanIV);

    QByteArray result;
    result.reserve(data.size());

    // Обрабатываем данные блоками по 8 байт
    for (int i = 0; i < data.size(); i += 8) {
        // Шифруем текущее значение счетчика
        uint64_t gamma = encryptBlock(ctr, roundKeys);
        QByteArray gammaBytes(8, 0);
        // Записываем gamma в big-endian порядке
        for (int j = 0; j < 8; ++j) {
            gammaBytes[j] = static_cast<char>((gamma >> (56 - j * 8)) & 0xFF);
        }

        // Берем блок данных (может быть неполным в конце)
        QByteArray chunk = data.mid(i, 8);

        // XOR гаммы с данными
        for (int j = 0; j < chunk.size(); ++j) {
            result.append(chunk[j] ^ gammaBytes[j]);
        }

        // Инкрементируем счетчик (по модулю 2^64)
        ctr = (ctr + 1) & 0xFFFFFFFFFFFFFFFF;
    }

    return result;
}

CipherResult MagmaGammaCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = "HEX";
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования (ГОСТ Магма, режим CTR)", "Инициализация"));

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
        QString("Входные данные (HEX): %1").arg(hexData.left(32) + (hexData.length() > 32 ? "..." : "")),
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
        QString("Результат (HEX): %1").arg(resultHex.left(32) + (resultHex.length() > 32 ? "..." : "")),
        "Завершение"));

    result.result = resultHex;
    result.steps = steps;

    return result;
}

CipherResult MagmaGammaCipher::decrypt(const QString& text, const QVariantMap& params)
{
    // Для режима CTR дешифрование идентично шифрованию
    return encrypt(text, params);
}

// ==================== MagmaGammaCipherRegister Implementation ====================

MagmaGammaCipherRegister::MagmaGammaCipherRegister()
{
    // Регистрируем шифр в основной фабрике
    CipherFactory::instance().registerCipher(
        "magma_ctr",
        "Магма (ГОСТ) - CTR",
        []() -> CipherInterface* { return new MagmaGammaCipher(); }
    );

    // Регистрируем виджеты параметров
    // Регистрируем виджеты параметров
    CipherWidgetFactory::instance().registerCipherWidgets(
        "magma_ctr",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Создаем контейнер для параметров
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // === ОДНА СТРОКА: Ключ слева, Синхропосылка справа ===
            QHBoxLayout* rowLayout = new QHBoxLayout();
            rowLayout->setSpacing(20);
            rowLayout->setContentsMargins(0, 0, 0, 0);

            // ---- Ключ (слева) ----
            QHBoxLayout* keyLayout = new QHBoxLayout();
            keyLayout->setSpacing(5);
            QLabel* keyLabel = new QLabel("Ключ (256 бит):");
            keyLabel->setFixedWidth(100);
            keyLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

            HexLineEdit* keyEdit = new HexLineEdit();
            keyEdit->setExpectedLength(32);
            keyEdit->setPlaceholderText("64 HEX символа");
            keyEdit->setObjectName("key");
            keyEdit->setText("FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF");
            keyEdit->setMinimumWidth(350);

            keyLayout->addWidget(keyLabel);
            keyLayout->addWidget(keyEdit);

            // ---- Синхропосылка (справа) ----
            QHBoxLayout* ivLayout = new QHBoxLayout();
            ivLayout->setSpacing(5);
            QLabel* ivLabel = new QLabel("Синхропосылка:");
            ivLabel->setFixedWidth(100);
            ivLabel->setAlignment(Qt::AlignRight | Qt::AlignVCenter);

            HexLineEdit* ivEdit = new HexLineEdit();
            ivEdit->setExpectedLength(8);
            ivEdit->setPlaceholderText("16 HEX символов");
            ivEdit->setObjectName("iv");
            ivEdit->setText("1234567890ABCDEF");
            ivEdit->setMinimumWidth(150);

            ivLayout->addWidget(ivLabel);
            ivLayout->addWidget(ivEdit);

            // Добавляем оба layout'а в одну строку
            rowLayout->addLayout(keyLayout);
            rowLayout->addLayout(ivLayout);
            rowLayout->addStretch(); // Растяжение справа

            mainLayout->addLayout(rowLayout);
            layout->addWidget(paramsContainer);

            // Сохраняем виджеты в карту
            widgets["key"] = keyEdit;
            widgets["iv"] = ivEdit;
        },
        nullptr
    );
}

// Статический экземпляр для автоматической регистрации
static MagmaGammaCipherRegister magmaGammaRegister;
