#include "magma_ecb.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "classes/hexedit.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <QCheckBox>

// ==================== S-блоки ГОСТ Р 34.12-2015 ====================
const std::array<uint8_t, 16> MagmaECBCipher::PI0 = {12, 4, 6, 2, 10, 5, 11, 9, 14, 8, 13, 7, 0, 3, 15, 1};
const std::array<uint8_t, 16> MagmaECBCipher::PI1 = {6, 8, 2, 3, 9, 10, 5, 12, 1, 14, 4, 7, 11, 13, 0, 15};
const std::array<uint8_t, 16> MagmaECBCipher::PI2 = {11, 3, 5, 8, 2, 15, 10, 13, 14, 1, 7, 4, 12, 9, 6, 0};
const std::array<uint8_t, 16> MagmaECBCipher::PI3 = {12, 8, 2, 1, 13, 4, 15, 6, 7, 0, 10, 5, 3, 14, 9, 11};
const std::array<uint8_t, 16> MagmaECBCipher::PI4 = {7, 15, 5, 10, 8, 1, 6, 13, 0, 9, 3, 14, 11, 4, 2, 12};
const std::array<uint8_t, 16> MagmaECBCipher::PI5 = {5, 13, 15, 6, 9, 2, 12, 10, 11, 7, 8, 1, 4, 3, 14, 0};
const std::array<uint8_t, 16> MagmaECBCipher::PI6 = {8, 14, 2, 5, 6, 9, 1, 12, 15, 4, 11, 0, 13, 10, 3, 7};
const std::array<uint8_t, 16> MagmaECBCipher::PI7 = {1, 7, 14, 13, 0, 5, 8, 3, 4, 15, 10, 6, 9, 12, 11, 2};


// ==================== MagmaECBCipher Implementation ====================

MagmaECBCipher::MagmaECBCipher()
{
}

// Нелинейное биективное преобразование t: V32 → V32 (формула 14 ГОСТ Р 34.12-2015)
uint32_t MagmaECBCipher::tTransform(uint32_t x) const
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
uint32_t MagmaECBCipher::leftShift11(uint32_t x) const
{
    return (x << 11) | (x >> (32 - 11));
}

// Функция g[k](a) = (t((a + k) mod 2^32)) <<< 11 (формула 15 ГОСТ Р 34.12-2015)
uint32_t MagmaECBCipher::g(uint32_t a, uint32_t k) const
{
    uint32_t sum = a + k;  // сложение по модулю 2^32
    uint32_t transformed = tTransform(sum);
    return leftShift11(transformed);
}

// Развертывание ключа (формула 18 ГОСТ Р 34.12-2015)
std::array<uint32_t, 32> MagmaECBCipher::keySchedule(const QString& keyHex) const
{
    std::array<uint32_t, 32> roundKeys;
    roundKeys.fill(0);

    QString cleanKey = CoreHex::normalizeHex(keyHex);

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
        keyParts[i] = CoreHex::hexToUint32(partHex);
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

// Шифрование одного 64-битного блока (формула 19 ГОСТ Р 34.12-2015)
uint64_t MagmaECBCipher::encryptBlock(uint64_t block, const std::array<uint32_t, 32>& roundKeys) const
{
    // Разбиваем блок на левую и правую части (по 32 бита)
    // a = a1 || a0, где a1 - старшие 32 бита, a0 - младшие 32 бита
    uint32_t a1 = static_cast<uint32_t>(block >> 32);
    uint32_t a0 = static_cast<uint32_t>(block & 0xFFFFFFFF);

    // Раунды 1..31: G[k](a1, a0) = (a0, g[k](a0) ⊕ a1)
    for (int i = 0; i < 31; ++i) {
        uint32_t new_a1 = a0;
        uint32_t new_a0 = g(a0, roundKeys[i]) ^ a1;
        a1 = new_a1;
        a0 = new_a0;
    }

    // Раунд 32: G*[k](a1, a0) = (g[k](a0) ⊕ a1) || a0
    uint32_t left = g(a0, roundKeys[31]) ^ a1;

    // Результат: left (32 бита) || a0 (32 бита)
    return (static_cast<uint64_t>(left) << 32) | static_cast<uint64_t>(a0);
}

// ==================== Шифрование (режим простой замены) ====================
// ГОСТ Р 34.13-2015, раздел 5.1.1, формула (1)

CipherResult MagmaECBCipher::process(const QString& text, const QVariantMap& params, bool encrypt)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(),
        QString("Начало %1 Магма (режим простой замены)")
            .arg(encrypt ? "шифрования" : "расшифрования"),
        "Инициализация"));

    // Ключ
    QString keyHex = params.value("key", "").toString();
    QString cleanedKey = CoreHex::normalizeHex(keyHex);

    if (cleanedKey.length() != 64) {
        result.result = QString("ОШИБКА: Ключ должен быть 64 HEX символа (256 бит). Получено: %1")
                        .arg(cleanedKey.length());
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Ключ: %1").arg(cleanedKey), "Параметры"));

    // Развертывание ключа
    std::array<uint32_t, 32> roundKeys = keySchedule(cleanedKey);

    // Для расшифрования — обратный порядок
    std::array<uint32_t, 32> effectiveKeys;
    if (encrypt) {
        effectiveKeys = roundKeys;
    } else {
        for (int i = 0; i < 32; ++i) effectiveKeys[i] = roundKeys[31 - i];
    }

    steps.append(CipherStep(2, QChar(),
        QString("Развернуто 32 итерационных ключа (%1)")
            .arg(encrypt ? "прямой порядок" : "обратный порядок"),
        "Развертывание ключа"));

    // Входные данные
    QString hexData = CoreHex::normalizeHex(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных";
        return result;
    }

    bool usePadding = params.value("usePadding", true).toBool();

    if (encrypt) {
        if (usePadding) {
            QByteArray bytes = CoreHex::hexToBytes(hexData);
            QByteArray padded = CoreHex::pkcs7Pad(bytes, 8);
            hexData = CoreHex::bytesToHex(padded);

            if (padded.size() != bytes.size()) {
                steps.append(CipherStep(3, QChar(),
                    QString("Паддинг PKCS#7: %1 → %2 (добавлено %3 байт)")
                        .arg(CoreHex::bytesToHex(bytes)).arg(hexData).arg(padded.size() - bytes.size()),
                    "Дополнение"));
            }
        } else {
            if (hexData.length() % 16 != 0) {
                result.result = QString("ОШИБКА: Длина данных (%1 HEX символов) должна быть кратна 16")
                                .arg(hexData.length());
                return result;
            }
        }
    }

    steps.append(CipherStep(encrypt ? 4 : 3, QChar(),
        QString("Входные данные: %1").arg(hexData.left(64) + (hexData.length() > 64 ? "..." : "")),
        "Данные"));

    // Обработка блоков
    QString outputHex;
    int blockCounter = 0;

    for (int i = 0; i < hexData.length(); i += 16) {
        QString blockHex = hexData.mid(i, 16);
        blockCounter++;

        std::array<uint8_t, 8> block{};
        CoreHex::hexToBytes(blockHex, block.data(), 8);

        uint64_t blockNum = 0;
        for (int j = 0; j < 8; ++j) blockNum = (blockNum << 8) | block[j];

        uint64_t resultNum = encryptBlock(blockNum, effectiveKeys);

        std::array<uint8_t, 8> resultBlock{};
        for (int j = 0; j < 8; ++j) resultBlock[j] = (resultNum >> (56 - j * 8)) & 0xFF;

        QString resultBlockHex = CoreHex::bytesToHex(resultBlock.data(), 8);
        outputHex.append(resultBlockHex);

        steps.append(CipherStep((encrypt ? 5 : 4) + blockCounter, QChar(),
            QString("Блок %1: %2 → %3").arg(blockCounter).arg(blockHex).arg(resultBlockHex),
            QString("Блок %1").arg(blockCounter)));
    }

    // Удаление паддинга при расшифровании
    if (!encrypt && usePadding) {
        QByteArray decryptedBytes = CoreHex::hexToBytes(outputHex);
        QByteArray unpadded = CoreHex::pkcs7Unpad(decryptedBytes);
        outputHex = CoreHex::bytesToHex(unpadded);

        if (unpadded.size() != decryptedBytes.size()) {
            steps.append(CipherStep(5 + blockCounter, QChar(),
                QString("Удаление паддинга: %1 → %2 (удалено %3 байт)")
                    .arg(CoreHex::bytesToHex(decryptedBytes)).arg(outputHex)
                    .arg(decryptedBytes.size() - unpadded.size()),
                "Удаление паддинга"));
        }
    }

    steps.append(CipherStep((encrypt ? 6 : 6) + blockCounter, QChar(),
        QString("Результат: %1").arg(outputHex.left(64) + (outputHex.length() > 64 ? "..." : "")),
        "Завершение"));

    result.result = outputHex;
    result.steps = steps;
    return result;
}

CipherResult MagmaECBCipher::encrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, true);
}

CipherResult MagmaECBCipher::decrypt(const QString& text, const QVariantMap& params)
{
    return process(text, params, false);
}

// ==================== MagmaECBCipherRegister Implementation ====================

MagmaECBCipherRegister::MagmaECBCipherRegister()
{
    CipherFactory::instance().registerCipher(
        18,
        "Магма ECB",
        []() -> CipherInterface* { return new MagmaECBCipher(); },
        CipherCategory::Combinatorial
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        18,
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* vbox = new QVBoxLayout(container);

            // Ключ
            QHBoxLayout* keyRow = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Ключ (256 бит):");
            keyLabel->setFixedWidth(120);
            HexEdit* keyEdit = new HexEdit();
            keyEdit->setExpectedLength(32);
            keyEdit->setObjectName("key");
            keyEdit->setHex("ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff");
            keyRow->addWidget(keyLabel);
            keyRow->addWidget(keyEdit);
            keyRow->addStretch();
            vbox->addLayout(keyRow);

            QCheckBox* paddingCheck = new QCheckBox("Добавлять PKCS#7 паддинг");
            paddingCheck->setObjectName("usePadding");
            paddingCheck->setChecked(true);
            paddingCheck->setToolTip("Отключите для тестов ГОСТ (длина уже кратна 8 байтам)");
            vbox->addWidget(paddingCheck);

            widgets["usePadding"] = paddingCheck;

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "Магма (ГОСТ Р 34.12-2015) — режим простой замены (ECB):\n"
                "• Длина блока: 64 бита (16 HEX символов)\n"
                "• Длина ключа: 256 бит (64 HEX символа)\n"
                "• Количество раундов: 32\n"
                "• Вход/выход: HEX-строки (длина кратна 16 символам)\n"
                "• Контрольный пример (А.2.1):\n"
                "  Ключ: ffeeddccbbaa99887766554433221100f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff\n"
                "  Открытый текст: 92def06b3c130a59\n"
                "  Шифртекст: 2b073f0494f372a0"
            );
            infoLabel->setStyleSheet("color: #666; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            vbox->addWidget(infoLabel);

            layout->addWidget(container);

            widgets["key"] = keyEdit;
        }
    );
}

static MagmaECBCipherRegister magmaECBRegister;
