#include "feistel.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QStringBuilder>
#include <QDebug>
#include <QRegularExpression>
#include <QVector>
#include <array>
#include <cstdint>

// g[k](a) = (t(Vec32(Int32(a) + Int32(k) mod 2^32))) <<< 11
// G[k](a1, a0 ) = (a0 , g[k](a0 ) xor a1),
// G*[k](a1, a0 ) = (g[k](a0 ) xor a1) || a0 (|| - сложение строк)

// Определение S-блоков из ГОСТ Р 34.12-2015 (раздел 5.1.1)
const std::array<uint8_t, 16> FeistelCipher::PI0 = {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1};
const std::array<uint8_t, 16> FeistelCipher::PI1 = {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15};
const std::array<uint8_t, 16> FeistelCipher::PI2 = {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0};
const std::array<uint8_t, 16> FeistelCipher::PI3 = {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11};
const std::array<uint8_t, 16> FeistelCipher::PI4 = {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12};
const std::array<uint8_t, 16> FeistelCipher::PI5 = {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0};
const std::array<uint8_t, 16> FeistelCipher::PI6 = {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7};
const std::array<uint8_t, 16> FeistelCipher::PI7 = {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2};

FeistelCipher::FeistelCipher()
{
    // Инициализация ключей нулями
    m_roundKeys.fill(0);
}

QString FeistelCipher::name() const
{
    return QStringLiteral(u"Магма (ГОСТ Р 34.12-2015)");
}

QString FeistelCipher::description() const
{
    return QStringLiteral("Блочный шифр с длиной блока 64 бит (сеть Фейстеля)");
}

uint32_t FeistelCipher::stringToUint32(const QString& str, int start) const
{
    uint32_t result = 0;
    for (int i = 0; i < 4; ++i) {
        if (start + i < str.length()) {
            result = (result << 8) | (static_cast<uint32_t>(str[start + i].unicode()) & 0xFF);
        }
    }
    return result;
}

QString FeistelCipher::uint32ToHex(uint32_t value) const
{
    return QString("%1").arg(value, 8, 16, QChar('0')).toUpper();
}

uint32_t FeistelCipher::hexToUint32(const QString& hex) const
{
    bool ok;
    uint32_t value = hex.toUInt(&ok, 16);
    if (!ok) return 0;
    return value;
}

QString FeistelCipher::prepareInput(const QString& text) const
{
    // Фильтруем только шестнадцатеричные символы
    QString filtered;
    QRegularExpression hexRegex("[0-9A-Fa-f]");
    QRegularExpressionMatchIterator it = hexRegex.globalMatch(text);
    while (it.hasNext()) {
        QRegularExpressionMatch match = it.next();
        filtered.append(match.captured());
    }
    return filtered.toUpper();
}

// Преобразование t (нелинейное биективное преобразование)
uint32_t FeistelCipher::t(uint32_t value) const
{
    uint32_t result = 0;

    // Применяем S-блоки к каждому полубайту (4 бита)
    // a = a7||a6||a5||a4||a3||a2||a1||a0 (каждый ai - 4 бита)
    for (int i = 0; i < 8; ++i) {
        uint8_t nibble = (value >> (4 * i)) & 0xF;  // Получаем i-й полубайт
        uint8_t substituted;

        // Применяем соответствующий S-блок
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

// Преобразование g (сеть Фейстеля)
uint32_t FeistelCipher::g(uint32_t value, uint32_t key) const
{
    // 1. Сложение с ключом по модулю 2^32
    uint32_t sum = value + key;

    // 2. Применение преобразования t
    uint32_t transformed = t(sum);

    // 3. Циклический сдвиг влево на 11 бит
    return (transformed << 11) | (transformed >> (32 - 11));
}

// Преобразование G (один раунд сети Фейстеля)
std::pair<uint32_t, uint32_t> FeistelCipher::G(uint32_t a1, uint32_t a0, uint32_t key) const
{
    // G[k](a1, a0) = (a0, g[k](a0) ⊕ a1)
    uint32_t new_a1 = a0;
    uint32_t new_a0 = g(a0, key) ^ a1;

    return std::make_pair(new_a1, new_a0);
}

// Преобразование G* (заключительное преобразование)
uint64_t FeistelCipher::GStar(uint32_t a1, uint32_t a0, uint32_t key) const
{
    // G*[k](a1, a0) = (g[k](a0) ⊕ a1) || a0
    uint32_t left = g(a0, key) ^ a1;
    return (static_cast<uint64_t>(left) << 32) | static_cast<uint64_t>(a0);
}

void FeistelCipher::setKey(const QString& hexKey)
{
    expandKey(hexKey);
}

// Алгоритм развертывания ключа (раздел 5.3)
void FeistelCipher::expandKey(const QString& key)
{
    // Очищаем ключи
    m_roundKeys.fill(0);

    QString hexKey = prepareInput(key);

    // Для теста используем ключ из примера А.2.3
    if (hexKey.isEmpty() || hexKey.length() < 64) {
        // Ключ по умолчанию из примера А.2.3
        hexKey = "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF";
    }

    // Берем первые 64 символа (256 бит)
    if (hexKey.length() > 64) {
        hexKey = hexKey.left(64);
    }

    // Выравниваем до 64 символов
    while (hexKey.length() < 64) {
        hexKey.append('0');
    }

    // Разбираем 256-битный ключ на 8 32-битных частей
    std::array<uint32_t, 8> keyParts;
    for (int i = 0; i < 8; ++i) {
        QString partHex = hexKey.mid(i * 8, 8);
        keyParts[i] = hexToUint32(partHex);
    }

    // Формируем итерационные ключи согласно ГОСТ (формулы 18)
    // Первые 8 ключей - прямая последовательность
    for (int i = 0; i < 8; ++i) {
        m_roundKeys[i] = keyParts[i];
    }

    // Следующие 8 ключей - повтор первых 8
    for (int i = 0; i < 8; ++i) {
        m_roundKeys[i + 8] = keyParts[i];
    }

    // Следующие 8 ключей - повтор первых 6? Нет, согласно ГОСТ:
    // K_{i+16} = K_i, i = 1,2,...,8 (то есть повтор первых 8)
    for (int i = 0; i < 8; ++i) {
        m_roundKeys[i + 16] = keyParts[i];
    }

    // Исправляем согласно примеру А.2.3
    m_roundKeys[24] = keyParts[7]; // K25 = K8
    m_roundKeys[25] = keyParts[6]; // K26 = K7
    m_roundKeys[26] = keyParts[5]; // K27 = K6
    m_roundKeys[27] = keyParts[4]; // K28 = K5
    m_roundKeys[28] = keyParts[3]; // K29 = K4
    m_roundKeys[29] = keyParts[2]; // K30 = K3
    m_roundKeys[30] = keyParts[1]; // K31 = K2
    m_roundKeys[31] = keyParts[0]; // K32 = K1

    // Для отладки выводим ключи
    qDebug() << "Итерационные ключи:";
    for (int i = 0; i < 32; ++i) {
        qDebug() << QString("K%1 = %2").arg(i + 1).arg(uint32ToHex(m_roundKeys[i]));
    }
}

CipherResult FeistelCipher::encrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования (ГОСТ Р 34.12-2015, Магма)", "Инициализация"));

    // Получаем ключ из параметров или используем тестовый
    QString keyHex = params.value("key", "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF").toString();

    // Разворачиваем ключ
    expandKey(keyHex);
    steps.append(CipherStep(1, QChar(), "Ключ развернут в 32 итерационных ключа", "Развертывание ключа"));

    // Подготавливаем входной текст (должен быть в hex формате)
    QString hexText = prepareInput(text);

    // Если текст пустой, используем тестовый из примера А.2.4
    if (hexText.isEmpty()) {
        hexText = "FEDCBA9876543210";
        steps.append(CipherStep(2, QChar(),
            QString("Используется тестовый текст: %1").arg(hexText),
            "Подготовка данных"));
    }

    // Выравниваем до 16 символов (64 бита)
    while (hexText.length() < 16) {
        hexText = "0" + hexText;
    }
    if (hexText.length() > 16) {
        hexText = hexText.left(16);
    }

    steps.append(CipherStep(3, QChar(),
        QString("Блок данных (64 бит): %1").arg(hexText),
        "Подготовка блока"));

    // Разбиваем на левую и правую части (по 32 бита)
    QString a1_hex = hexText.left(8);  // старшие 32 бита
    QString a0_hex = hexText.right(8); // младшие 32 бита

    uint32_t a1 = hexToUint32(a1_hex);
    uint32_t a0 = hexToUint32(a0_hex);

    steps.append(CipherStep(4, QChar(),
        QString("a1 = %1, a0 = %2").arg(a1_hex).arg(a0_hex),
        "Разделение блока"));

    // Выполняем 32 раунда сети Фейстеля
    steps.append(CipherStep(5, QChar(), "Начало 32 раундов шифрования", "Раунды"));

    for (int round = 0; round < 32; ++round) {
        uint32_t key = m_roundKeys[round];

        QString old_a1_hex = uint32ToHex(a1);
        QString old_a0_hex = uint32ToHex(a0);

        // Выполняем раунд
        auto result = G(a1, a0, key);
        a1 = result.first;
        a0 = result.second;

        // Для отладки добавляем шаг
        if (round < 5 || round >= 30) { // Показываем первые 5 и последние 2 раунда
            steps.append(CipherStep(6 + round, QChar(),
                QString("Раунд %1: (%2, %3) -> (%4, %5) [ключ %6]")
                    .arg(round + 1)
                    .arg(old_a1_hex)
                    .arg(old_a0_hex)
                    .arg(uint32ToHex(a1))
                    .arg(uint32ToHex(a0))
                    .arg(uint32ToHex(key)),
                QString("Раунд %1").arg(round + 1)));
        }
    }

    // Согласно формуле 19: E(a) = G*[K32]G[K31]...G[K2]G[K1](a1, a0)
    uint64_t result = (static_cast<uint64_t>(a0) << 32) | static_cast<uint64_t>(a1);
    QString resultHex = QString("%1%2").arg(uint32ToHex(a0), uint32ToHex(a1));

    steps.append(CipherStep(38, QChar(),
        QString("Результат шифрования: %1").arg(resultHex),
        "Завершение"));

    return CipherResult(resultHex, steps, "Магма (ГОСТ Р 34.12-2015)", name(), false);
}

CipherResult FeistelCipher::decrypt(const QString& text, const QVariantMap& params)
{
    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало дешифрования (ГОСТ Р 34.12-2015, Магма)", "Инициализация"));

    // Получаем ключ из параметров или используем тестовый
    QString keyHex = params.value("key", "FFEEDDCCBBAA99887766554433221100F0F1F2F3F4F5F6F7F8F9FAFBFCFDFEFF").toString();

    // Разворачиваем ключ
    expandKey(keyHex);
    steps.append(CipherStep(1, QChar(), "Ключ развернут в 32 итерационных ключа", "Развертывание ключа"));

    // Подготавливаем входной шифртекст
    QString hexText = prepareInput(text);

    // Если текст пустой, используем тестовый из примера А.2.5
    if (hexText.isEmpty()) {
        hexText = "4EE901E5C2D8CA3D";
        steps.append(CipherStep(2, QChar(),
            QString("Используется тестовый шифртекст: %1").arg(hexText),
            "Подготовка данных"));
    }

    // Выравниваем до 16 символов (64 бита)
    while (hexText.length() < 16) {
        hexText = "0" + hexText;
    }
    if (hexText.length() > 16) {
        hexText = hexText.left(16);
    }

    steps.append(CipherStep(3, QChar(),
        QString("Блок шифртекста (64 бит): %1").arg(hexText),
        "Подготовка блока"));

    // Разбиваем на левую и правую части
    uint32_t a1 = hexToUint32(hexText.left(8));
    uint32_t a0 = hexToUint32(hexText.right(8));

    steps.append(CipherStep(4, QChar(),
        QString("a1 = %1, a2 = %2").arg(hexText.left(8)).arg(hexText.right(8)),
        "Разделение блока"));

    // Дешифрование - используем ключи в обратном порядке (формула 20)
    steps.append(CipherStep(5, QChar(), "Начало 32 раундов дешифрования (ключи в обратном порядке)", "Раунды"));

    for (int round = 0; round < 32; ++round) {
        // При дешифровании ключи используются в обратном порядке
        uint32_t key = m_roundKeys[31 - round];

        QString old_a1_hex = uint32ToHex(a1);
        QString old_a0_hex = uint32ToHex(a0);

        auto result = G(a1, a0, key);
        a1 = result.first;
        a0 = result.second;

        if (round < 5 || round >= 30) {
            steps.append(CipherStep(6 + round, QChar(),
                QString("Раунд %1 (ключ K%2): (%3, %4) -> (%5, %6)")
                    .arg(round + 1)
                    .arg(32 - round)
                    .arg(old_a1_hex)
                    .arg(old_a0_hex)
                    .arg(uint32ToHex(a1))
                    .arg(uint32ToHex(a0)),
                QString("Раунд %1").arg(round + 1)));
        }
    }

    QString resultHex = QString("%1%2").arg(uint32ToHex(a0), uint32ToHex(a1));

    steps.append(CipherStep(38, QChar(),
        QString("Результат дешифрования: %1").arg(resultHex),
        "Завершение"));

    return CipherResult(resultHex, steps, "Магма (ГОСТ Р 34.12-2015)", name(), false);
}

// Регистратор
FeistelCipherRegister::FeistelCipherRegister()
{
    CipherFactory::instance().registerCipher(
        13,
        "Cеть фейстеля МАГМА",
        []() -> CipherInterface* { return new FeistelCipher(); }
    );

    // Здесь можно добавить регистрацию виджетов, если нужно
    CipherWidgetFactory::instance().registerCipherWidgets(
        "feistel",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
            // Базовые виджеты (если нужны)
        },
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
            // Расширенные виджеты (если нужны)
        }
    );
}

// Статический регистратор
static FeistelCipherRegister feistelCipherRegister;
