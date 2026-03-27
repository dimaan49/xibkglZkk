#include "aes.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QComboBox>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>

AESCipher::AESCipher()
{
}

// ==================== S-блок  ====================
const std::array<uint8_t, 256> AESCipher::S_BOX = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

// Обратный S-блок (FIPS-197, Рис. 14)
const std::array<uint8_t, 256> AESCipher::INV_S_BOX = {
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
};

// Константы раундов Rcon (FIPS-197, подраздел 5.2)
const std::array<uint32_t, 10> AESCipher::RCON = {
    0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
    0x20000000, 0x40000000, 0x80000000, 0x1B000000, 0x36000000
};

// ==================== AESHexEdit ====================

AESHexEdit::AESHexEdit(QWidget* parent) : QLineEdit(parent)
{
    m_originalStyle = styleSheet();
    QRegularExpression hexRegex("^[0-9A-Fa-f]*$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(hexRegex, this);
    setValidator(validator);
    setPlaceholderText("HEX (0-9, A-F)");
}

void AESHexEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("AESHexEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void AESHexEdit::setExpectedLength(int bytes)
{
    m_expectedBytes = bytes;
    if (bytes > 0) {
        setPlaceholderText(QString("HEX (%1 байт, %2 символа)").arg(bytes).arg(bytes * 2));
        setMaxLength(bytes * 2);
    }
}

void AESHexEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) setValid(true);
    QLineEdit::focusInEvent(event);
}

void AESHexEdit::focusOutEvent(QFocusEvent* event)
{
    QString txt = text().trimmed();
    if (!txt.isEmpty() && m_expectedBytes > 0 && txt.length() != m_expectedBytes * 2) {
        setValid(false);
        setToolTip(QString("Требуется %1 HEX-символов (%2 байт)").arg(m_expectedBytes * 2).arg(m_expectedBytes));
    }
    QLineEdit::focusOutEvent(event);
}

QString AESHexEdit::getHex() const { return text().trimmed().toUpper(); }
void AESHexEdit::setHex(const QString& hex) { setText(hex.toUpper()); }

// ==================== Арифметика GF(2^8) ====================

uint8_t AESCipher::gf256Mul(uint8_t a, uint8_t b) const
{
    uint8_t result = 0;
    uint8_t temp = a;

    for (int i = 0; i < 8; i++) {
        if (b & 1) result ^= temp;
        uint8_t hi_bit = temp & 0x80;
        temp <<= 1;
        if (hi_bit) temp ^= 0x1B;  // полином x^8 + x^4 + x^3 + x + 1
        b >>= 1;
    }
    return result;
}

// ==================== Преобразования ====================

void AESCipher::subBytes(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; i++) {
        state[i] = S_BOX[state[i]];
    }
}

void AESCipher::invSubBytes(std::array<uint8_t, 16>& state) const
{
    for (int i = 0; i < 16; i++) {
        state[i] = INV_S_BOX[state[i]];
    }
}

// ShiftRows: строка r сдвигается влево на r байт (r = 0,1,2,3)
void AESCipher::shiftRows(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp = state;

    // строка 1 (индексы 1,5,9,13) сдвиг на 1 влево
    temp[1] = state[5];
    temp[5] = state[9];
    temp[9] = state[13];
    temp[13] = state[1];

    // строка 2 (индексы 2,6,10,14) сдвиг на 2 влево
    temp[2] = state[10];
    temp[6] = state[14];
    temp[10] = state[2];
    temp[14] = state[6];

    // строка 3 (индексы 3,7,11,15) сдвиг на 3 влево
    temp[3] = state[15];
    temp[7] = state[3];
    temp[11] = state[7];
    temp[15] = state[11];

    state = temp;
}

// InvShiftRows: строка r сдвигается вправо на r байт
void AESCipher::invShiftRows(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp = state;

    // строка 1 сдвиг на 1 вправо
    temp[5] = state[1];
    temp[9] = state[5];
    temp[13] = state[9];
    temp[1] = state[13];

    // строка 2 сдвиг на 2 вправо
    temp[10] = state[2];
    temp[14] = state[6];
    temp[2] = state[10];
    temp[6] = state[14];

    // строка 3 сдвиг на 3 вправо
    temp[15] = state[3];
    temp[3] = state[7];
    temp[7] = state[11];
    temp[11] = state[15];

    state = temp;
}

// MixColumns: умножение столбцов на фиксированный многочлен a(x) = {03}x^3 + {01}x^2 + {01}x + {02}
void AESCipher::mixColumns(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp = state;

    for (int c = 0; c < 4; c++) {
        int i0 = c * 4;
        int i1 = c * 4 + 1;
        int i2 = c * 4 + 2;
        int i3 = c * 4 + 3;

        uint8_t s0 = state[i0];
        uint8_t s1 = state[i1];
        uint8_t s2 = state[i2];
        uint8_t s3 = state[i3];

        temp[i0] = gf256Mul(0x02, s0) ^ gf256Mul(0x03, s1) ^ s2 ^ s3;
        temp[i1] = s0 ^ gf256Mul(0x02, s1) ^ gf256Mul(0x03, s2) ^ s3;
        temp[i2] = s0 ^ s1 ^ gf256Mul(0x02, s2) ^ gf256Mul(0x03, s3);
        temp[i3] = gf256Mul(0x03, s0) ^ s1 ^ s2 ^ gf256Mul(0x02, s3);
    }

    state = temp;
}

// InvMixColumns: умножение на a^{-1}(x) = {0b}x^3 + {0d}x^2 + {09}x + {0e}
void AESCipher::invMixColumns(std::array<uint8_t, 16>& state) const
{
    std::array<uint8_t, 16> temp = state;

    for (int c = 0; c < 4; c++) {
        int i0 = c * 4;
        int i1 = c * 4 + 1;
        int i2 = c * 4 + 2;
        int i3 = c * 4 + 3;

        uint8_t s0 = state[i0];
        uint8_t s1 = state[i1];
        uint8_t s2 = state[i2];
        uint8_t s3 = state[i3];

        temp[i0] = gf256Mul(0x0e, s0) ^ gf256Mul(0x0b, s1) ^ gf256Mul(0x0d, s2) ^ gf256Mul(0x09, s3);
        temp[i1] = gf256Mul(0x09, s0) ^ gf256Mul(0x0e, s1) ^ gf256Mul(0x0b, s2) ^ gf256Mul(0x0d, s3);
        temp[i2] = gf256Mul(0x0d, s0) ^ gf256Mul(0x09, s1) ^ gf256Mul(0x0e, s2) ^ gf256Mul(0x0b, s3);
        temp[i3] = gf256Mul(0x0b, s0) ^ gf256Mul(0x0d, s1) ^ gf256Mul(0x09, s2) ^ gf256Mul(0x0e, s3);
    }

    state = temp;
}

void AESCipher::addRoundKey(std::array<uint8_t, 16>& state, const std::array<uint8_t, 16>& roundKey) const
{
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// ==================== Развертывание ключа ====================

std::vector<std::array<uint8_t, 16>> AESCipher::expandKey(const std::array<uint8_t, 32>& key, int keySize) const
{
    int Nk = keySize / 32;  // 4, 6 или 8
    int Nr = Nk + 6;        // 10, 12 или 14
    int Nb = 4;
    int totalWords = Nb * (Nr + 1);

    std::vector<uint32_t> w(totalWords, 0);

    // Копируем ключ в первые Nk слов (little-endian: байт 0 = младший)
    for (int i = 0; i < Nk; i++) {
        w[i] = (key[i*4] << 24) | (key[i*4+1] << 16) | (key[i*4+2] << 8) | key[i*4+3];
    }

    // Расширение ключа
    for (int i = Nk; i < totalWords; i++) {
        uint32_t temp = w[i-1];

        if (i % Nk == 0) {
            // RotWord + SubWord + Rcon
            uint32_t rot = (temp << 8) | (temp >> 24);
            uint32_t sub = (S_BOX[(rot >> 24) & 0xFF] << 24) |
                           (S_BOX[(rot >> 16) & 0xFF] << 16) |
                           (S_BOX[(rot >> 8) & 0xFF] << 8) |
                           S_BOX[rot & 0xFF];
            temp = sub ^ RCON[i / Nk - 1];
        } else if (Nk > 6 && i % Nk == 4) {
            // SubWord для AES-256 на i % Nk == 4
            temp = (S_BOX[(temp >> 24) & 0xFF] << 24) |
                   (S_BOX[(temp >> 16) & 0xFF] << 16) |
                   (S_BOX[(temp >> 8) & 0xFF] << 8) |
                   S_BOX[temp & 0xFF];
        }

        w[i] = w[i - Nk] ^ temp;
    }

    // Преобразуем слова в байтовые ключи раундов
    std::vector<std::array<uint8_t, 16>> roundKeys(Nr + 1);

    for (int r = 0; r <= Nr; r++) {
        for (int c = 0; c < Nb; c++) {
            int wordIndex = r * Nb + c;
            roundKeys[r][c*4] = (w[wordIndex] >> 24) & 0xFF;
            roundKeys[r][c*4+1] = (w[wordIndex] >> 16) & 0xFF;
            roundKeys[r][c*4+2] = (w[wordIndex] >> 8) & 0xFF;
            roundKeys[r][c*4+3] = w[wordIndex] & 0xFF;
        }
    }

    return roundKeys;
}

// ==================== Вспомогательные функции ====================

QString AESCipher::prepareHexInput(const QString& text) const
{
    QString filtered;
    QRegularExpression hexRegex("[0-9A-Fa-f]");
    QRegularExpressionMatchIterator it = hexRegex.globalMatch(text);
    while (it.hasNext()) {
        filtered.append(it.next().captured());
    }
    return filtered.toUpper();
}

QString AESCipher::bytesToHex(const uint8_t* data, int len) const
{
    QString result;
    for (int i = 0; i < len; i++) {
        result.append(QString("%1").arg(data[i], 2, 16, QChar('0')).toUpper());
    }
    return result;
}

void AESCipher::hexToBytes(const QString& hex, uint8_t* out, int len) const
{
    QByteArray bytes = QByteArray::fromHex(hex.toLatin1());
    for (int i = 0; i < len && i < bytes.size(); i++) {
        out[i] = static_cast<uint8_t>(bytes[i]);
    }
}

// ==================== Шифрование ====================

CipherResult AESCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования AES (Rijndael)", "Инициализация"));

    // Получаем параметры
    QString keyHex = params.value("key", "").toString();
    QString keySizeStr = params.value("keySize", "128").toString();
    int keySize = keySizeStr.toInt();  // 128, 192 или 256

    QString cleanedKey = prepareHexInput(keyHex);
    int expectedKeyLen = keySize / 4;  // 32, 48 или 64 HEX символа

    if (cleanedKey.length() != expectedKeyLen) {
        result.result = QString("ОШИБКА: Ключ должен быть %1 HEX символов для %2 бит. Получено: %3")
                        .arg(expectedKeyLen).arg(keySize).arg(cleanedKey.length());
        return result;
    }

    // Подготавливаем входные данные
    QString hexData = prepareHexInput(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных для шифрования (введите HEX-строку)";
        return result;
    }

    if (hexData.length() % 32 != 0) {
        result.result = QString("ОШИБКА: Длина данных (%1 HEX символов) должна быть кратна 32 (128 бит)")
                        .arg(hexData.length());
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: %1 бит, ключ: %2...").arg(keySize).arg(cleanedKey.left(16)),
        "Параметры"));

    // Преобразуем ключ в байты
    std::array<uint8_t, 32> masterKey{};
    hexToBytes(cleanedKey, masterKey.data(), keySize / 8);

    // Развертываем ключи
    std::vector<std::array<uint8_t, 16>> roundKeys = expandKey(masterKey, keySize);
    int Nr = keySize / 32 + 6;  // 10, 12 или 14

    steps.append(CipherStep(2, QChar(),
        QString("Развернуто %1 раундовых ключей").arg(Nr + 1),
        "Развертывание ключей"));

    // Шифрование блоков
    QString encryptedHex;
    int blockCounter = 0;
    int Nb = 4;

    for (int i = 0; i < hexData.length(); i += 32) {
        QString blockHex = hexData.mid(i, 32);
        blockCounter++;

        std::array<uint8_t, 16> state{};
        hexToBytes(blockHex, state.data(), 16);

        // Начальный раунд: AddRoundKey
        addRoundKey(state, roundKeys[0]);

        // Раунды 1..Nr-1
        for (int round = 1; round < Nr; round++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state);
            addRoundKey(state, roundKeys[round]);
        }

        // Последний раунд (без MixColumns)
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, roundKeys[Nr]);

        QString encryptedBlockHex = bytesToHex(state.data(), 16);
        encryptedHex.append(encryptedBlockHex);

        steps.append(CipherStep(3 + blockCounter, QChar(),
            QString("Блок %1: %2 → %3").arg(blockCounter).arg(blockHex).arg(encryptedBlockHex),
            QString("Блок %1").arg(blockCounter)));
    }

    steps.append(CipherStep(4 + blockCounter, QChar(),
        "Шифрование завершено", "Завершение"));

    result.result = encryptedHex;
    result.steps = steps;

    return result;
}

// ==================== Дешифрование ====================

CipherResult AESCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало дешифрования AES (Rijndael)", "Инициализация"));

    // Получаем параметры
    QString keyHex = params.value("key", "").toString();
    QString keySizeStr = params.value("keySize", "128").toString();
    int keySize = keySizeStr.toInt();

    QString cleanedKey = prepareHexInput(keyHex);
    int expectedKeyLen = keySize / 4;

    if (cleanedKey.length() != expectedKeyLen) {
        result.result = QString("ОШИБКА: Ключ должен быть %1 HEX символов для %2 бит. Получено: %3")
                        .arg(expectedKeyLen).arg(keySize).arg(cleanedKey.length());
        return result;
    }

    QString hexData = prepareHexInput(text);
    if (hexData.isEmpty()) {
        result.result = "ОШИБКА: Нет данных для дешифрования (введите HEX-строку)";
        return result;
    }

    if (hexData.length() % 32 != 0) {
        result.result = QString("ОШИБКА: Длина данных (%1 HEX символов) должна быть кратна 32 (128 бит)")
                        .arg(hexData.length());
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: %1 бит, ключ: %2...").arg(keySize).arg(cleanedKey.left(16)),
        "Параметры"));

    // Преобразуем ключ в байты
    std::array<uint8_t, 32> masterKey{};
    hexToBytes(cleanedKey, masterKey.data(), keySize / 8);

    // Развертываем ключи
    std::vector<std::array<uint8_t, 16>> roundKeys = expandKey(masterKey, keySize);
    int Nr = keySize / 32 + 6;

    steps.append(CipherStep(2, QChar(),
        QString("Развернуто %1 раундовых ключей").arg(Nr + 1),
        "Развертывание ключей"));

    // Дешифрование блоков
    QString decryptedHex;
    int blockCounter = 0;

    for (int i = 0; i < hexData.length(); i += 32) {
        QString blockHex = hexData.mid(i, 32);
        blockCounter++;

        std::array<uint8_t, 16> state{};
        hexToBytes(blockHex, state.data(), 16);

        // Начальный раунд дешифрования
        addRoundKey(state, roundKeys[Nr]);
        invShiftRows(state);
        invSubBytes(state);

        // Раунды Nr-1 .. 1
        for (int round = Nr - 1; round >= 1; round--) {
            addRoundKey(state, roundKeys[round]);
            invMixColumns(state);
            invShiftRows(state);
            invSubBytes(state);
        }

        // Финальный раунд
        addRoundKey(state, roundKeys[0]);

        QString decryptedBlockHex = bytesToHex(state.data(), 16);
        decryptedHex.append(decryptedBlockHex);

        steps.append(CipherStep(3 + blockCounter, QChar(),
            QString("Блок %1: %2 → %3").arg(blockCounter).arg(blockHex).arg(decryptedBlockHex),
            QString("Блок %1").arg(blockCounter)));
    }

    steps.append(CipherStep(4 + blockCounter, QChar(),
        "Дешифрование завершено", "Завершение"));

    result.result = decryptedHex;
    result.steps = steps;

    return result;
}

// ==================== Регистратор ====================

AESCipherRegister::AESCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "aes",
        "AES",
        []() -> CipherInterface* { return new AESCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "aes",
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* container = new QWidget(parent);
            QVBoxLayout* vbox = new QVBoxLayout(container);

            // Выбор длины ключа
            QHBoxLayout* keySizeRow = new QHBoxLayout();
            QLabel* keySizeLabel = new QLabel("Длина ключа:");
            keySizeLabel->setFixedWidth(100);
            QComboBox* keySizeCombo = new QComboBox();
            keySizeCombo->addItem("128 бит (32 HEX символа)", "128");
            keySizeCombo->addItem("192 бит (48 HEX символов)", "192");
            keySizeCombo->addItem("256 бит (64 HEX символа)", "256");
            keySizeCombo->setObjectName("keySize");
            keySizeRow->addWidget(keySizeLabel);
            keySizeRow->addWidget(keySizeCombo);
            keySizeRow->addStretch();
            vbox->addLayout(keySizeRow);

            // Ключ
            QHBoxLayout* keyRow = new QHBoxLayout();
            QLabel* keyLabel = new QLabel("Ключ:");
            keyLabel->setFixedWidth(100);
            AESHexEdit* keyEdit = new AESHexEdit();
            keyEdit->setExpectedLength(16);  // 128 бит по умолчанию
            keyEdit->setObjectName("key");
            keyEdit->setHex("000102030405060708090a0b0c0d0e0f");
            keyRow->addWidget(keyLabel);
            keyRow->addWidget(keyEdit);
            keyRow->addStretch();
            vbox->addLayout(keyRow);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "AES (Rijndael) — симметричный блочный шифр, стандарт FIPS-197:\n"
                "• Длина блока: 128 бит (32 HEX символа)\n"
                "• Длина ключа: 128, 192 или 256 бит\n"
                "• Количество раундов: 10, 12 или 14\n"
                "• Преобразования: SubBytes, ShiftRows, MixColumns, AddRoundKey\n"
                "• Вход/выход: HEX-строки (длина кратна 32 символам)"
            );
            infoLabel->setStyleSheet("color: #666; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            vbox->addWidget(infoLabel);

            layout->addWidget(container);

            widgets["keySize"] = keySizeCombo;
            widgets["key"] = keyEdit;

            // Обновляем ожидаемую длину ключа при изменении выбора
            QObject::connect(keySizeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                [keyEdit](int index) {
                    int bytes = (index == 0) ? 16 : (index == 1) ? 24 : 32;
                    keyEdit->setExpectedLength(bytes);
                    keyEdit->setPlaceholderText(QString("HEX (%1 байт, %2 символа)").arg(bytes).arg(bytes * 2));
                });
        }
    );
}

static AESCipherRegister aesRegister;
