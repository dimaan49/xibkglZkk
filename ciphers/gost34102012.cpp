#include "gost34102012.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <random>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>

// ==================== BigInt Implementation ====================

void BigInt::normalize() {
    while (!limbs.empty() && limbs.back() == 0) {
        limbs.pop_back();
    }
}

BigInt::BigInt() {}

BigInt::BigInt(uint64_t value) {
    if (value != 0) {
        limbs.push_back(value);
    }
}

BigInt::BigInt(const std::string& str) {
    std::string s = str;

    // Убираем префикс 0x если есть (на всякий случай)
    if (s.substr(0, 2) == "0x" || s.substr(0, 2) == "0X") {
        s = s.substr(2);
    }

    limbs.clear();

    // Всегда парсим как десятичное число
    try {
        // Для больших чисел используем посегментный парсинг десятичных цифр
        if (s.length() > 19) {  // Больше чем влезает в uint64_t
            BigInt result;
            BigInt multiplier(10000000000000000000ULL); // 10^19

            for (size_t i = 0; i < s.length(); i += 19) {
                int len = std::min(19, (int)(s.length() - i));
                std::string part = s.substr(i, len);
                uint64_t val = std::stoull(part, nullptr, 10);

                result = result * multiplier + BigInt(val);
            }
            *this = result;
        } else {
            uint64_t val = std::stoull(s, nullptr, 10);
            if (val != 0) {
                limbs.push_back(val);
            }
        }
    } catch (const std::exception& e) {
        // Если не удалось распарсить, оставляем 0
        limbs.clear();
    }

    normalize();
}

BigInt::BigInt(const QByteArray& bytes) {
    limbs.clear();
    for (int i = bytes.size() - 1; i >= 0; i -= 8) {
        uint64_t val = 0;
        for (int j = 0; j < 8 && i - j >= 0; ++j) {
            val |= (static_cast<uint64_t>(static_cast<uint8_t>(bytes[i - j])) << (j * 8));
        }
        limbs.push_back(val);
    }
    normalize();
}

bool BigInt::isZero() const {
    return limbs.empty() || (limbs.size() == 1 && limbs[0] == 0);
}

bool BigInt::isOne() const {
    return limbs.size() == 1 && limbs[0] == 1;
}

bool BigInt::operator==(const BigInt& other) const {
    if (limbs.size() != other.limbs.size()) return false;
    for (size_t i = 0; i < limbs.size(); ++i) {
        if (limbs[i] != other.limbs[i]) return false;
    }
    return true;
}

bool BigInt::operator!=(const BigInt& other) const {
    return !(*this == other);
}

bool BigInt::operator<(const BigInt& other) const {
    if (limbs.size() != other.limbs.size()) {
        return limbs.size() < other.limbs.size();
    }
    for (int i = limbs.size() - 1; i >= 0; --i) {
        if (limbs[i] != other.limbs[i]) {
            return limbs[i] < other.limbs[i];
        }
    }
    return false;
}

bool BigInt::operator<=(const BigInt& other) const {
    return (*this < other) || (*this == other);
}

bool BigInt::operator>(const BigInt& other) const {
    return !(*this <= other);
}

bool BigInt::operator>=(const BigInt& other) const {
    return !(*this < other);
}

BigInt BigInt::operator+(const BigInt& other) const {
    BigInt result;
    size_t maxSize = std::max(limbs.size(), other.limbs.size());
    uint64_t carry = 0;

    for (size_t i = 0; i < maxSize || carry; ++i) {
        uint64_t sum = carry;
        if (i < limbs.size()) sum += limbs[i];
        if (i < other.limbs.size()) sum += other.limbs[i];

        result.limbs.push_back(sum);
        carry = (sum < carry) ? 1 : 0;  // Исправленный перенос
        if (carry && i + 1 >= maxSize) {
            result.limbs.push_back(1);
            carry = 0;
        }
    }
    result.normalize();
    return result;
}

BigInt BigInt::operator-(const BigInt& other) const {
    BigInt result;
    uint64_t borrow = 0;

    for (size_t i = 0; i < limbs.size(); ++i) {
        uint64_t sub = borrow;
        if (i < other.limbs.size()) sub += other.limbs[i];

        if (limbs[i] >= sub) {
            result.limbs.push_back(limbs[i] - sub);
            borrow = 0;
        } else {
            result.limbs.push_back(limbs[i] + (UINT64_MAX - sub + 1));
            borrow = 1;
        }
    }
    result.normalize();
    return result;
}

BigInt BigInt::operator*(const BigInt& other) const {
    if (isZero() || other.isZero()) return BigInt(0);

    // Временная реализация для чисел, помещающихся в uint64_t
    if (limbs.size() <= 2 && other.limbs.size() <= 2) {
        uint64_t a = 0, b = 0;
        for (int i = limbs.size() - 1; i >= 0; --i) {
            a = (a << 64) | limbs[i];
        }
        for (int i = other.limbs.size() - 1; i >= 0; --i) {
            b = (b << 64) | other.limbs[i];
        }
        __uint128_t result = static_cast<__uint128_t>(a) * b;
        BigInt res;
        res.limbs.push_back(static_cast<uint64_t>(result));
        res.limbs.push_back(static_cast<uint64_t>(result >> 64));
        res.normalize();
        return res;
    }

    return BigInt(0);
}

BigInt BigInt::operator/(const BigInt& other) const {
    BigInt result;
    return result;
}

BigInt BigInt::operator%(const BigInt& other) const {
    if (other.isZero()) return BigInt(0);
    if (this->isZero()) return BigInt(0);

    // Временная реализация для чисел, которые помещаются в uint64_t
    if (limbs.size() <= 2 && other.limbs.size() == 1) {
        uint64_t val = 0;
        for (int i = limbs.size() - 1; i >= 0; --i) {
            val = (val << 64) | limbs[i];
        }
        uint64_t mod = other.limbs[0];
        return BigInt(val % mod);
    }

    // Для больших чисел возвращаем 0 (заглушка)
    return BigInt(0);
}

BigInt& BigInt::operator+=(const BigInt& other) {
    *this = *this + other;
    return *this;
}

BigInt& BigInt::operator-=(const BigInt& other) {
    *this = *this - other;
    return *this;
}

BigInt& BigInt::operator*=(const BigInt& other) {
    *this = *this * other;
    return *this;
}

BigInt& BigInt::operator/=(const BigInt& other) {
    *this = *this / other;
    return *this;
}

BigInt& BigInt::operator%=(const BigInt& other) {
    *this = *this % other;
    return *this;
}

BigInt BigInt::modPow(const BigInt& exp, const BigInt& mod) const {
    BigInt result(1);
    BigInt base = *this % mod;
    BigInt e = exp;

    while (!e.isZero()) {
        // Упрощенная реализация для демонстрации
        break;
    }
    return result;
}

BigInt BigInt::modInverse(const BigInt& mod) const {
    if (mod.isZero() || this->isZero()) return BigInt(0);

    uint64_t a_val = this->toUInt64();
    uint64_t m_val = mod.toUInt64();

    int64_t t = 0, newt = 1;
    int64_t r = m_val, newr = a_val % m_val;

    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp = newt;
        newt = t - q * newt;
        t = tmp;

        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }

    if (r > 1) return BigInt(0); // Нет обратного

    if (t < 0) t += m_val;

    return BigInt(static_cast<uint64_t>(t));
}

std::string BigInt::toHex() const {
    if (limbs.empty()) return "0";
    std::stringstream ss;
    for (int i = limbs.size() - 1; i >= 0; --i) {
        ss << std::hex << std::setfill('0') << std::setw(16) << limbs[i];
    }
    std::string result = ss.str();
    size_t pos = result.find_first_not_of('0');
    if (pos != std::string::npos) {
        result = result.substr(pos);
    }
    return result;
}

QString BigInt::toQString() const {
    return QString::fromStdString(toHex());
}

uint64_t BigInt::toUInt64() const {
    if (limbs.empty()) return 0;
    return limbs[0];
}

QString BigInt::toDecQString() const {
    if (limbs.empty()) return "0";

    // Для чисел, помещающихся в uint64_t
    if (limbs.size() == 1) {
        return QString::number(limbs[0]);
    }

    // Для больших чисел — временно возвращаем HEX
    // В будущем можно реализовать полноценное десятичное преобразование
    return QString::fromStdString(toHex()) + " (hex)";
}

int BigInt::bitLength() const {
    if (limbs.empty()) return 0;
    uint64_t highest = limbs.back();
    int bits = (limbs.size() - 1) * 64;
    while (highest) {
        bits++;
        highest >>= 1;
    }
    return bits;
}

BigInt BigInt::random(int bits) {
    std::random_device rd;
    std::mt19937_64 gen(rd());

    BigInt result;
    int limbsNeeded = (bits + 63) / 64;
    for (int i = 0; i < limbsNeeded; ++i) {
        result.limbs.push_back(gen());
    }
    result.normalize();
    return result;
}

BigInt BigInt::random(const BigInt& max) {
    BigInt result;
    do {
        result = random(max.bitLength());
    } while (result >= max);
    return result;
}

// ==================== ECPoint Implementation ====================

ECPoint::ECPoint() : isInfinity(true) {}

ECPoint::ECPoint(const BigInt& x_, const BigInt& y_) : x(x_), y(y_), isInfinity(false) {}

bool ECPoint::operator==(const ECPoint& other) const {
    if (isInfinity && other.isInfinity) return true;
    if (isInfinity || other.isInfinity) return false;
    return x == other.x && y == other.y;
}

bool ECPoint::operator!=(const ECPoint& other) const {
    return !(*this == other);
}

QString ECPoint::toString() const {
    if (isInfinity) return "Infinity";
    return QString("(%1, %2)").arg(x.toQString()).arg(y.toQString());
}

// ==================== Арифметика эллиптической кривой ====================

// Вспомогательная функция: модульное обратное (расширенный алгоритм Евклида)
static BigInt modInverseHelper(const BigInt& a, const BigInt& m) {
    int64_t a_val = static_cast<int64_t>(a.toUInt64());
    int64_t m_val = static_cast<int64_t>(m.toUInt64());

    if (a_val == 0) return BigInt(0);

    // Нормализуем a по модулю m
    a_val = ((a_val % m_val) + m_val) % m_val;

    int64_t t = 0, newt = 1;
    int64_t r = m_val, newr = a_val;

    while (newr != 0) {
        int64_t q = r / newr;
        int64_t tmp = newt;
        newt = t - q * newt;
        t = tmp;

        tmp = newr;
        newr = r - q * newr;
        r = tmp;
    }

    if (r > 1) return BigInt(0); // Нет обратного

    if (t < 0) t += m_val;

    return BigInt(static_cast<uint64_t>(t));
}

// Удвоение точки: P + P
ECPoint GOST34102012Cipher::pointDouble(const ECPoint& P, const BigInt& p, const BigInt& a) {
    if (P.isInfinity) return P;

    uint64_t p_val = p.toUInt64();
    uint64_t x1 = P.x.toUInt64() % p_val;
    uint64_t y1 = P.y.toUInt64() % p_val;
    uint64_t a_val = a.toUInt64() % p_val;

    // Если y = 0, то касательная вертикальна → точка в бесконечности
    if (y1 == 0) return ECPoint();

    // λ = (3x₁² + a) / (2y₁) mod p
    uint64_t num = (3 * x1 * x1 + a_val) % p_val;
    uint64_t den = (2 * y1) % p_val;
    uint64_t den_inv = modInverseHelper(BigInt(den), p).toUInt64();

    if (den_inv == 0) return ECPoint();

    uint64_t lambda = (num * den_inv) % p_val;

    // x₃ = λ² - 2x₁ mod p
    uint64_t lambda2 = (lambda * lambda) % p_val;
    uint64_t x3 = (lambda2 + 2 * p_val - 2 * x1) % p_val;

    // y₃ = λ(x₁ - x₃) - y₁ mod p
    uint64_t x_diff = (x1 + p_val - x3) % p_val;
    uint64_t lambda_x_diff = (lambda * x_diff) % p_val;
    uint64_t y3 = (lambda_x_diff + p_val - y1) % p_val;

    return ECPoint(BigInt(x3), BigInt(y3));
}

// Сложение точек: P + Q (P ≠ Q)
ECPoint GOST34102012Cipher::pointAdd(const ECPoint& P, const ECPoint& Q,
                                      const BigInt& p, const BigInt& a) {
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    uint64_t p_val = p.toUInt64();
    uint64_t x1 = P.x.toUInt64() % p_val;
    uint64_t y1 = P.y.toUInt64() % p_val;
    uint64_t x2 = Q.x.toUInt64() % p_val;
    uint64_t y2 = Q.y.toUInt64() % p_val;
    uint64_t a_val = a.toUInt64() % p_val;

    // Если точки равны, используем удвоение
    if (x1 == x2 && y1 == y2) {
        return pointDouble(P, p, a);
    }

    // Если x₁ == x₂, то P + Q = O (точка в бесконечности)
    if (x1 == x2) {
        return ECPoint();
    }

    // λ = (y₂ - y₁) / (x₂ - x₁) mod p
    uint64_t num = (y2 + p_val - y1) % p_val;
    uint64_t den = (x2 + p_val - x1) % p_val;
    uint64_t den_inv = modInverseHelper(BigInt(den), p).toUInt64();

    if (den_inv == 0) return ECPoint();

    uint64_t lambda = (num * den_inv) % p_val;

    // x₃ = λ² - x₁ - x₂ mod p
    uint64_t lambda2 = (lambda * lambda) % p_val;
    uint64_t x3 = (lambda2 + 2 * p_val - x1 - x2) % p_val;

    // y₃ = λ(x₁ - x₃) - y₁ mod p
    uint64_t x_diff = (x1 + p_val - x3) % p_val;
    uint64_t lambda_x_diff = (lambda * x_diff) % p_val;
    uint64_t y3 = (lambda_x_diff + p_val - y1) % p_val;

    return ECPoint(BigInt(x3), BigInt(y3));
}

// Умножение точки на скаляр: k·P
ECPoint GOST34102012Cipher::pointMul(const BigInt& k, const ECPoint& P,
                                      const BigInt& p, const BigInt& a) {
    if (k.isZero() || P.isInfinity) return ECPoint();

    ECPoint result; // точка в бесконечности
    ECPoint base = P;
    uint64_t k_val = k.toUInt64();

    // Алгоритм удвоения-сложения (double-and-add)
    while (k_val > 0) {
        if (k_val & 1) {
            result = pointAdd(result, base, p, a);
        }
        base = pointDouble(base, p, a);
        k_val >>= 1;
    }

    return result;
}

// ==================== GOST34102012Cipher Implementation ====================

GOST34102012Cipher::GOST34102012Cipher() {}

BigInt GOST34102012Cipher::parseBigInt(const QString& str) const {
    return BigInt(str.toStdString());
}

BigInt GOST34102012Cipher::computeHash(const QString& text, const BigInt& p,
                                        QVector<CipherStep>& steps, int& stepCounter) const {
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filtered.isEmpty()) return BigInt(0);

    // Используем p как модуль для хеширования
    uint64_t mod = p.toUInt64();

    uint64_t h = 0;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Начало вычисления хеша: h0 = 0, модуль p = %1").arg(mod),
        "Хеширование"));

    for (int i = 0; i < filtered.length(); ++i) {
        int charIndex = m_alphabet.indexOf(filtered[i]);
        uint64_t Mi = static_cast<uint64_t>(charIndex + 1);

        uint64_t old_h = h;
        uint64_t sum = (h + Mi) % mod;
        h = (sum * sum) % mod;

        steps.append(CipherStep(stepCounter++, QChar(),
            QString("  h%1 = (h%2 + M%3)² mod p = (%4 + %5)² mod %6 = %7² mod %6 = %8")
                .arg(i + 1).arg(i).arg(i + 1)
                .arg(old_h).arg(Mi).arg(mod)
                .arg(sum).arg(h),
            QString("Хеш шаг %1: буква '%2' (№%3)").arg(i + 1).arg(filtered[i]).arg(Mi)));
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Итоговый хеш: H = %1").arg(h),
        "Хеш завершен"));

    return BigInt(h);
}

int GOST34102012Cipher::charToNumber(QChar ch) const {
    return m_alphabet.indexOf(ch);
}

QChar GOST34102012Cipher::numberToChar(int num) const {
    if (num >= 0 && num < m_alphabet.length()) {
        return m_alphabet[num];
    }
    return '?';
}

QVector<uint64_t> GOST34102012Cipher::textToNumbers(const QString& text) const {
    QVector<uint64_t> numbers;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    for (int i = 0; i < filtered.length(); ++i) {
        numbers.append(static_cast<uint64_t>(charToNumber(filtered[i])));
    }
    return numbers;
}

QString GOST34102012Cipher::numbersToText(const QVector<uint64_t>& numbers) const {
    QString result;
    for (uint64_t num : numbers) {
        result.append(numberToChar(static_cast<int>(num)));
    }
    return result;
}

bool GOST34102012Cipher::validateParameters(const BigInt& p, const BigInt& a, const BigInt& b,
                                             const BigInt& q, const ECPoint& P,
                                             QString& errorMessage) const {

    if (q.isZero()) {
        errorMessage = "Порядок подгруппы q не может быть нулевым";
        return false;
    }

    if (P.isInfinity) {
        errorMessage = "Точка P не может быть нулевой";
        return false;
    }

    return true;
}

// ==================== Шифрование (создание подписи) ====================
CipherResult GOST34102012Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(), "Начало формирования подписи по ГОСТ Р 34.10-2012", "Инициализация"));

    // Получаем параметры из виджетов
    QString pStr = params.value("p", "").toString();
    QString aStr = params.value("a", "").toString();
    QString bStr = params.value("b", "").toString();
    QString qStr = params.value("q", "").toString();
    QString xpStr = params.value("xp", "").toString();
    QString ypStr = params.value("yp", "").toString();
    QString dStr = params.value("d", "").toString();
    QString kStr = params.value("k", "").toString();
    // Проверка наличия всех параметров
    if (pStr.isEmpty() || aStr.isEmpty() || bStr.isEmpty() || qStr.isEmpty() ||
        xpStr.isEmpty() || ypStr.isEmpty() || dStr.isEmpty() || kStr.isEmpty()) {
        result.result = "ОШИБКА: Необходимо указать все параметры (p, a, b, q, xp, yp, d, k)";
        return result;
    }

    BigInt p = parseBigInt(pStr);
    BigInt a = parseBigInt(aStr);
    BigInt b = parseBigInt(bStr);
    BigInt q = parseBigInt(qStr);
    BigInt xp = parseBigInt(xpStr);
    BigInt yp = parseBigInt(ypStr);
    BigInt d = parseBigInt(dStr);
    BigInt k = parseBigInt(kStr);

    ECPoint G(xp, yp);

    ECPoint Q = pointMul(d, G, p, a);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Открытый ключ Q = d·G = (%1, %2)")
            .arg(Q.x.toDecQString()).arg(Q.y.toDecQString()),
        "Вычисление Q"));

    // Проверка параметров
    QString validationError;
    if (!validateParameters(p, a, b, q, G, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры эллиптической кривой:\n  p = %1\n  a = %2\n  b = %3\n  q = %4\n  G = (%5, %6)\n  d = %7\n  k = %8")
            .arg(p.toDecQString()).arg(a.toDecQString()).arg(b.toDecQString())
            .arg(q.toDecQString()).arg(xp.toDecQString()).arg(yp.toDecQString())
            .arg(d.toDecQString()).arg(k.toDecQString()),
        "Параметры схемы"));

    // Шаг 1: Вычисляем хеш сообщения
    BigInt hash = computeHash(text, p, steps, stepCounter);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 1: h(M) = %1").arg(hash.toDecQString()),
        "Хеш сообщения"));

    // Шаг 2: Вычисляем точку C = kG
    ECPoint C = pointMul(k, G, p, a);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: C = k·G = (%1, %2)").arg(C.x.toDecQString()).arg(C.y.toDecQString()),
        "Вычисление точки C"));

    // Шаг 3: Вычисляем r = x_C mod q
    BigInt r = C.x % q;

    if (r.isZero()) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "r = 0, необходимо выбрать другое k",
            "Ошибка: r = 0"));
        result.result = "ОШИБКА: r = 0, выберите другое k";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: r = x_C mod q = %1 mod %2 = %3")
            .arg(C.x.toDecQString()).arg(q.toDecQString()).arg(r.toDecQString()),
        "Вычисление r"));

    // Шаг 4: Вычисляем s = (k·h + r·d) mod q
    BigInt kh = (k * hash) % q;
    BigInt rd = (r * d) % q;
    BigInt s = (kh + rd) % q;

    if (s.isZero()) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "s = 0, необходимо выбрать другое k",
            "Ошибка: s = 0"));
        result.result = "ОШИБКА: s = 0, выберите другое k";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 4: s = (k·h + r·d) mod q = (%1·%2 + %3·%4) mod %5 = %6")
            .arg(k.toDecQString()).arg(hash.toDecQString())
            .arg(r.toDecQString()).arg(d.toDecQString())
            .arg(q.toDecQString()).arg(s.toDecQString()),
        "Вычисление s"));

    // Формируем подпись
    QString signature = QString("(%1, %2)").arg(r.toDecQString()).arg(s.toDecQString());

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Цифровая подпись: (r, s) = %1").arg(signature),
        "Завершение"));

    result.result = signature;
    result.steps = steps;

    return result;
}

// ==================== Расшифрование (проверка подписи) ====================

CipherResult GOST34102012Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(), "Начало проверки подписи по ГОСТ Р 34.10-2012", "Инициализация"));

    // Получаем параметры
    QString pStr = params.value("p", "").toString();
    QString aStr = params.value("a", "").toString();
    QString bStr = params.value("b", "").toString();
    QString qStr = params.value("q", "").toString();
    QString xpStr = params.value("xp", "").toString();
    QString ypStr = params.value("yp", "").toString();
    QString xqStr = params.value("xq", "").toString();
    QString yqStr = params.value("yq", "").toString();

    QString message = params.value("message", "").toString();

    if (pStr.isEmpty() || qStr.isEmpty() || xpStr.isEmpty() || ypStr.isEmpty() ||
        xqStr.isEmpty() || yqStr.isEmpty()) {
        result.result = "ОШИБКА: Необходимо указать все параметры (p, a, b, q, xp, yp, xq, yq)";
        return result;
    }

    if (message.isEmpty()) {
        result.result = "ОШИБКА: Укажите сообщение для проверки подписи";
        return result;
    }

    BigInt p = parseBigInt(pStr);
    BigInt a = parseBigInt(aStr);
    BigInt b = parseBigInt(bStr);
    BigInt q = parseBigInt(qStr);
    BigInt xp = parseBigInt(xpStr);
    BigInt yp = parseBigInt(ypStr);
    BigInt xq = parseBigInt(xqStr);
    BigInt yq = parseBigInt(yqStr);

    ECPoint G(xp, yp);
    ECPoint Q(xq, yq);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры:\n  p = %1\n  q = %2\n  G = (%3, %4)\n  Q = (%5, %6)")
            .arg(p.toDecQString()).arg(q.toDecQString())
            .arg(xp.toDecQString()).arg(yp.toDecQString())
            .arg(xq.toDecQString()).arg(yq.toDecQString()),
        "Параметры схемы"));

    // Парсим подпись
    QString sig = text.trimmed();
    sig.remove('(').remove(')').remove(' ');
    QStringList parts = sig.split(',');

    if (parts.size() != 2) {
        result.result = "ОШИБКА: Неверный формат подписи (ожидается r,s)";
        return result;
    }

    BigInt r = parseBigInt(parts[0].trimmed());
    BigInt s = parseBigInt(parts[1].trimmed());

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Подпись: r = %1, s = %2").arg(r.toDecQString()).arg(s.toDecQString()),
        "Извлечение подписи"));

    // Проверка 0 < r < q и 0 < s < q
    if (r.isZero() || r >= q || s.isZero() || s >= q) {
        result.result = "ОШИБКА: Неверные значения подписи (0 < r,s < q)";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(), "Шаг 1: 0 < r < q и 0 < s < q — выполнено", "Проверка"));

    // Хеш сообщения
    BigInt hash = computeHash(message, p, steps, stepCounter);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: h(M) = %1").arg(hash.toDecQString()), "Хеш"));

    // h⁻¹ mod q
    BigInt h_inv = hash.modInverse(q);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: h⁻¹ mod q = %1").arg(h_inv.toDecQString()), "Обратный элемент"));

    // u1 и u2
    BigInt u1 = (s * h_inv) % q;
    BigInt u2 = (q - (r * h_inv) % q) % q;
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 4: u1 = %1, u2 = %2").arg(u1.toDecQString()).arg(u2.toDecQString()),
        "Вычисление u1, u2"));

    // P = u1·G + u2·Q
    ECPoint P1 = pointMul(u1, G, p, a);
    ECPoint P2 = pointMul(u2, Q, p, a);
    ECPoint P = pointAdd(P1, P2, p, a);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 5: P = (%1, %2)").arg(P.x.toDecQString()).arg(P.y.toDecQString()),
        "Точка P"));

    // R = x_P mod q
    BigInt R = P.x % q;
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 6: R = %1").arg(R.toDecQString()), "Вычисление R"));

    // Проверка
    if (R == r) {
        steps.append(CipherStep(stepCounter++, QChar(), "✓ Подпись ВЕРНА!", "Успех"));
        result.result = QString("✓ ПОДПИСЬ ВЕРНА!\n\nСообщение: %1\nr = %2\ns = %3")
            .arg(message).arg(r.toDecQString()).arg(s.toDecQString());
    } else {
        steps.append(CipherStep(stepCounter++, QChar(), "✗ Подпись НЕВЕРНА!", "Ошибка"));
        result.result = QString("✗ ПОДПИСЬ НЕВЕРНА!\nR = %1\nr = %2")
            .arg(R.toDecQString()).arg(r.toDecQString());
    }

    result.steps = steps;
    return result;
}
// ==================== Статические методы ====================

BigInt GOST34102012Cipher::generatePrimeStatic(int bits) {
    return BigInt::random(bits);
}

BigInt GOST34102012Cipher::generateRandomStatic(const BigInt& max) {
    return BigInt::random(max);
}

void GOST34102012Cipher::computeCurveOrder(const BigInt& p, const BigInt& a, const BigInt& b,
                                           BigInt& curveOrder, BigInt& subgroupOrder, BigInt& cofactor,
                                           QString& log)
{
    log.clear();
    log += "=== Вычисление порядка эллиптической кривой перебором ===\n\n";

    uint64_t p_val = p.toUInt64();
    uint64_t a_val = a.toUInt64();
    uint64_t b_val = b.toUInt64();

    log += QString("Параметры кривой: p = %1, a = %2, b = %3\n")
           .arg(p_val).arg(a_val).arg(b_val);
    log += QString("Уравнение: y² = x³ + %1·x + %2 (mod %3)\n\n")
           .arg(a_val).arg(b_val).arg(p_val);

    // Шаг 1: Предвычисляем квадраты по модулю p
    QMap<uint64_t, QList<uint64_t>> squares;
    for (uint64_t y = 0; y < p_val; ++y) {
        uint64_t y2 = (y * y) % p_val;
        squares[y2].append(y);
    }

    log += "Таблица квадратов по модулю p:\n";
    log += "y    : ";
    for (uint64_t y = 0; y < p_val; ++y) log += QString("%1 ").arg(y);
    log += "\ny²   : ";
    for (uint64_t y = 0; y < p_val; ++y) log += QString("%1 ").arg((y * y) % p_val);
    log += "\n\n";

    // Шаг 2: Перебираем x, вычисляем y² = x³ + a·x + b (mod p)
    log += "Вычисление y² для каждого x:\n";
    log += "x    | x³+ax+b | y² | точки\n";
    log += "-----|---------|----|-------\n";

    QVector<ECPoint> points;

    for (uint64_t x = 0; x < p_val; ++x) {
        uint64_t x2 = (x * x) % p_val;
        uint64_t x3 = (x2 * x) % p_val;
        uint64_t ax = (a_val * x) % p_val;
        uint64_t rhs = (x3 + ax + b_val) % p_val;

        QString pointsStr;
        if (squares.contains(rhs)) {
            for (uint64_t y : squares[rhs]) {
                points.append(ECPoint(BigInt(x), BigInt(y)));
                if (!pointsStr.isEmpty()) pointsStr += ", ";
                pointsStr += QString("(%1, %2)").arg(x).arg(y);
            }
        } else {
            pointsStr = "нет";
        }

        log += QString("%1    | %2       | %3  | %4\n")
               .arg(x, -4).arg(rhs, -7).arg(rhs, -2).arg(pointsStr);
    }

    // Добавляем точку в бесконечности O
    uint64_t totalPoints = points.size() + 1;
    curveOrder = BigInt(totalPoints);

    // Находим наибольший простой делитель
    uint64_t q_val = 1;
    for (uint64_t i = 2; i <= totalPoints; ++i) {
        if (totalPoints % i == 0) {
            bool isPrime = true;
            for (uint64_t j = 2; j * j <= i; ++j) {
                if (i % j == 0) {
                    isPrime = false;
                    break;
                }
            }
            if (isPrime) {
                q_val = i;
            }
        }
    }

    uint64_t h_val = totalPoints / q_val;

    subgroupOrder = BigInt(q_val);
    cofactor = BigInt(h_val);

    log += QString("\nn = #E = %1 = h · q\n").arg(totalPoints);
    log += QString("Кофактор h = %1\n").arg(h_val);
    log += QString("Порядок подгруппы q = %1\n").arg(q_val);
    log += QString("Проверка: %1 = %2 · %3\n").arg(totalPoints).arg(h_val).arg(q_val);
}



// ==================== Регистратор ====================

GOST34102012CipherRegister::GOST34102012CipherRegister()
{
    CipherFactory::instance().registerCipher(
        27,
        "ГОСТ Р 34.10-2012 (ЭЦП на эллиптических кривых)",
        []() -> CipherInterface* { return new GOST34102012Cipher(); },
        CipherCategory::DigitalSignature
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        27,
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Заголовок
            QLabel* title = new QLabel("Параметры эллиптической кривой (ГОСТ Р 34.10-2012)");
            title->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(title);

            // Сетка для параметров кривой - увеличиваем количество столбцов
            QGridLayout* grid = new QGridLayout();
            grid->setSpacing(8);
            grid->setColumnStretch(0, 0);
            grid->setColumnStretch(1, 1);
            grid->setColumnStretch(2, 0);
            grid->setColumnStretch(3, 1);

            // Строка 0: p
            QLabel* pLabel = new QLabel("p (модуль):");
            pLabel->setFixedWidth(100);
            QLineEdit* pEdit = new QLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("Простое число (HEX)");
            pEdit->setMinimumWidth(200);
            pEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9A-Fa-f]+$"), pEdit));
            grid->addWidget(pLabel, 0, 0);
            grid->addWidget(pEdit, 0, 1);

            // Строка 0: a
            QLabel* aLabel = new QLabel("a (коэффициент):");
            aLabel->setFixedWidth(100);
            QLineEdit* aEdit = new QLineEdit();
            aEdit->setObjectName("a");
            aEdit->setText("7");
            aEdit->setMinimumWidth(200);
            aEdit->setPlaceholderText("a (HEX)");
            grid->addWidget(aLabel, 0, 2);
            grid->addWidget(aEdit, 0, 3);

            // Строка 1: b
            QLabel* bLabel = new QLabel("b (коэффициент):");
            bLabel->setFixedWidth(100);
            QLineEdit* bEdit = new QLineEdit();
            bEdit->setObjectName("b");
            bEdit->setMinimumWidth(200);
            bEdit->setPlaceholderText("b (HEX)");
            grid->addWidget(bLabel, 1, 0);
            grid->addWidget(bEdit, 1, 1);

            // Строка 1: q
            QLabel* qLabel = new QLabel("q (порядок):");
            qLabel->setFixedWidth(100);

            QHBoxLayout* qLayout = new QHBoxLayout();
            qLayout->setSpacing(5);
            QLineEdit* qEdit = new QLineEdit();
            qEdit->setObjectName("q");
            qEdit->setMinimumWidth(200);
            qEdit->setPlaceholderText("q (HEX) — нажмите 'Вычислить'");
            qEdit->setReadOnly(true);

            QPushButton* calcQButton = new QPushButton("Вычислить q");
            calcQButton->setObjectName("calcQButton");
            calcQButton->setCursor(Qt::PointingHandCursor);
            calcQButton->setFixedWidth(100);

            qLayout->addWidget(qEdit);
            qLayout->addWidget(calcQButton);

            grid->addWidget(qLabel, 1, 2);
            grid->addLayout(qLayout, 1, 3);
            // Строка 2: xp
            QLabel* xpLabel = new QLabel("xp (координата P):");
            xpLabel->setFixedWidth(100);
            QLineEdit* xpEdit = new QLineEdit();
            xpEdit->setObjectName("xp");
            xpEdit->setMinimumWidth(200);
            xpEdit->setPlaceholderText("xp (HEX)");
            grid->addWidget(xpLabel, 2, 0);
            grid->addWidget(xpEdit, 2, 1);

            // Строка 2: yp
            QLabel* ypLabel = new QLabel("yp (координата P):");
            ypLabel->setFixedWidth(100);
            QLineEdit* ypEdit = new QLineEdit();
            ypEdit->setObjectName("yp");
            ypEdit->setMinimumWidth(200);
            ypEdit->setPlaceholderText("yp (HEX)");
            grid->addWidget(ypLabel, 2, 2);
            grid->addWidget(ypEdit, 2, 3);

            mainLayout->addLayout(grid);

            // Разделитель
            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line1);

            // Заголовок для ключей
            QLabel* keyTitle = new QLabel("Ключи пользователя:");
            keyTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(keyTitle);

            // Сетка для ключей
            QGridLayout* keyGrid = new QGridLayout();
            keyGrid->setSpacing(8);
            keyGrid->setColumnStretch(0, 0);
            keyGrid->setColumnStretch(1, 1);
            keyGrid->setColumnStretch(2, 0);
            keyGrid->setColumnStretch(3, 1);

            // Строка 0: d (секретный ключ)
            QLabel* dLabel = new QLabel("d (секретный ключ):");
            dLabel->setFixedWidth(100);
            QLineEdit* dEdit = new QLineEdit();
            dEdit->setObjectName("d");
            dEdit->setMinimumWidth(200);
            dEdit->setPlaceholderText("d (HEX)");
            keyGrid->addWidget(dLabel, 0, 0);
            keyGrid->addWidget(dEdit, 0, 1);

            // Строка 1: k (случайное число)
            QLabel* kLabel = new QLabel("k (случайное):");
            kLabel->setFixedWidth(100);
            QLineEdit* kEdit = new QLineEdit();
            kEdit->setObjectName("k");
            kEdit->setMinimumWidth(200);
            kEdit->setPlaceholderText("k (десятичное)");
            kEdit->setText("5");  // Значение по умолчанию из примера
            keyGrid->addWidget(kLabel, 1, 2);
            keyGrid->addWidget(kEdit, 1, 3);

            // Строка 0: xq (открытый ключ)
            QLabel* xqLabel = new QLabel("xq (координата Q):");
            xqLabel->setFixedWidth(100);
            QLineEdit* xqEdit = new QLineEdit();
            xqEdit->setObjectName("xq");
            xqEdit->setMinimumWidth(200);
            xqEdit->setPlaceholderText("xq (HEX)");
            keyGrid->addWidget(xqLabel, 0, 2);
            keyGrid->addWidget(xqEdit, 0, 3);

            // Строка 1: yq (открытый ключ)
            QLabel* yqLabel = new QLabel("yq (координата Q):");
            yqLabel->setFixedWidth(100);
            QLineEdit* yqEdit = new QLineEdit();
            yqEdit->setObjectName("yq");
            yqEdit->setMinimumWidth(200);
            yqEdit->setPlaceholderText("yq (HEX)");
            keyGrid->addWidget(yqLabel, 1, 0);
            keyGrid->addWidget(yqEdit, 1, 1);

            mainLayout->addLayout(keyGrid);

            // Разделитель
            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line2);

            // Общие параметры
            QLabel* commonTitle = new QLabel("Общие параметры:");
            commonTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(commonTitle);

            QGridLayout* commonGrid = new QGridLayout();
            commonGrid->setSpacing(8);
            commonGrid->setColumnStretch(0, 0);
            commonGrid->setColumnStretch(1, 1);


            mainLayout->addLayout(commonGrid);

            // Разделитель
            QFrame* line3 = new QFrame();
            line3->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line3);

            // Сообщение для проверки подписи
            QLabel* messageTitle = new QLabel("Сообщение для проверки подписи:");
            messageTitle->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(messageTitle);

            QTextEdit* messageEdit = new QTextEdit();
            messageEdit->setObjectName("message");
            messageEdit->setPlaceholderText("Введите сообщение для проверки подписи\n(должно совпадать с исходным текстом, который подписывали)");
            messageEdit->setMaximumHeight(60);
            messageEdit->setAcceptRichText(false);
            mainLayout->addWidget(messageEdit);

            // Кнопка загрузки контрольного примера
            QPushButton* loadExampleButton = new QPushButton("📋 Загрузить контрольный пример (ГОСТ А.1)");
            loadExampleButton->setObjectName("loadExampleButton");
            loadExampleButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(loadExampleButton);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["a"] = aEdit;
            widgets["b"] = bEdit;
            widgets["k"] = kEdit;
            widgets["q"] = qEdit;
            widgets["xp"] = xpEdit;
            widgets["yp"] = ypEdit;
            widgets["d"] = dEdit;
            widgets["xq"] = xqEdit;
            widgets["yq"] = yqEdit;
            widgets["message"] = messageEdit;
            widgets["calcQButton"] = calcQButton;
            widgets["loadExampleButton"] = loadExampleButton;

            // Загрузка контрольного примера
            QObject::connect(loadExampleButton, &QPushButton::clicked, [pEdit, aEdit, bEdit, qEdit,
                                                                          xpEdit, ypEdit, dEdit, xqEdit, yqEdit]() {
                pEdit->setText("80000000000000000000000000000000000000000000000000000000000000000431");
                aEdit->setText("7");
                bEdit->setText("5BBFF498AA938CE739B8E022FBAFEF40563F6E6A3472FC2A514C0CE9DAE23B7E");
                qEdit->setText("80000000000000000000000000000000150FE8A1892976154C59CFC193ACCF5B3");
                xpEdit->setText("2");
                ypEdit->setText("8E2A8A0E65147D4BD6316030E16D19C85C97F0A9CA267122B96ABBCEA7E8FC8");
                dEdit->setText("7A929ADE789BB9BE10ED359DD39A72C11B60961F49397EEE1D19CE9891EC3B28");
                xqEdit->setText("7F2B49E270DB6D90D8595BEC458B50C58585BA1D4E9B788F6689DBD8E56FD80B");
                yqEdit->setText("26F1B489D6701DD185C8413A977B3CBBAF64D1C593D26627DFFB101A87FF77DA");

                QMessageBox::information(nullptr, "Контрольный пример загружен",
                    "Загружены параметры из ГОСТ Р 34.10-2012 (Пример А.1)");
            });

            QObject::connect(calcQButton, &QPushButton::clicked, [pEdit, aEdit, bEdit, qEdit]() {
                QString pStr = pEdit->text().trimmed();
                QString aStr = aEdit->text().trimmed();
                QString bStr = bEdit->text().trimmed();

                if (pStr.isEmpty() || aStr.isEmpty() || bStr.isEmpty()) {
                    QMessageBox::warning(nullptr, "Ошибка", "Заполните параметры p, a, b");
                    return;
                }

                try {
                    BigInt p(pStr.toStdString());
                    BigInt a(aStr.toStdString());
                    BigInt b(bStr.toStdString());

                    BigInt curveOrder, subgroupOrder, cofactor;
                    QString log;

                    GOST34102012Cipher::computeCurveOrder(p, a, b, curveOrder, subgroupOrder, cofactor, log);

                    qEdit->setText(subgroupOrder.toQString());

                    QMessageBox msgBox;
                    msgBox.setWindowTitle("Результаты вычисления порядка кривой");
                    msgBox.setText(QString("Порядок кривой #E = %1\nПорядок подгруппы q = %2\nКофактор h = %3")
                                   .arg(curveOrder.toDecQString())      // ← используем десятичный вывод
                                   .arg(subgroupOrder.toDecQString())   // ←
                                   .arg(cofactor.toDecQString()));      // ←
                    msgBox.setDetailedText(log);
                    msgBox.setIcon(QMessageBox::Information);
                    msgBox.exec();

                } catch (const std::exception& e) {
                    QMessageBox::critical(nullptr, "Ошибка", QString("Ошибка вычисления: %1").arg(e.what()));
                }
            });
        }
    );
}

static GOST34102012CipherRegister gost34102012Register;

