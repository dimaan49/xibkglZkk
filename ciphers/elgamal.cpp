#include "elgamal.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QStackedWidget>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <random>

// ==================== ElGamalNumberEdit Implementation ====================

ElGamalNumberEdit::ElGamalNumberEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression numRegex("^[0-9]{0,20}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(numRegex, this);
    setValidator(validator);

    setPlaceholderText("Введите число");
}

void ElGamalNumberEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("ElGamalNumberEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void ElGamalNumberEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

uint64_t ElGamalNumberEdit::getValue() const
{
    QString text = this->text();
    if (text.isEmpty()) return 0;
    bool ok;
    uint64_t value = text.toULongLong(&ok);
    return ok ? value : 0;
}

void ElGamalNumberEdit::setValue(uint64_t value)
{
    setText(QString::number(value));
}

// ==================== RandomizersEdit Implementation ====================

RandomizersEdit::RandomizersEdit(QWidget* parent)
    : QTextEdit(parent)
{
    m_originalStyle = styleSheet();
    setPlaceholderText("Введите числа через пробел (например: 5 7 11)");
    setMaximumHeight(80);
}

QVector<uint64_t> RandomizersEdit::getRandomizers() const
{
    QVector<uint64_t> result;
    QString text = toPlainText().trimmed();
    if (text.isEmpty()) return result;

    QStringList parts = text.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
    for (const QString& part : parts) {
        bool ok;
        uint64_t value = part.toULongLong(&ok);
        if (ok) {
            result.append(value);
        }
    }
    return result;
}

void RandomizersEdit::setRandomizers(const QVector<uint64_t>& randomizers)
{
    QString text;
    for (int i = 0; i < randomizers.size(); ++i) {
        if (i > 0) text += " ";
        text += QString::number(randomizers[i]);
    }
    setPlainText(text);
}

void RandomizersEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("RandomizersEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void RandomizersEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QTextEdit::focusInEvent(event);
}

// ==================== ElGamalCipher Implementation ====================

ElGamalCipher::ElGamalCipher()
{
}

// Алгоритм Миллера-Рабина для проверки простоты
bool ElGamalCipher::isPrime(uint64_t n, int k) const
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, n - 2);

    for (int i = 0; i < k; ++i) {
        uint64_t a = dist(gen);
        uint64_t x = modPow(a, d, n);

        if (x == 1 || x == n - 1) continue;

        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = modPow(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

uint64_t ElGamalCipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t ElGamalCipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) {
            result = (result * base) % mod;
        }
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

uint64_t ElGamalCipher::modInverse(uint64_t a, uint64_t mod) const
{
    int64_t t = 0, new_t = 1;
    int64_t r = mod, new_r = a;

    while (new_r != 0) {
        int64_t quotient = r / new_r;
        int64_t temp_t = t;
        t = new_t;
        new_t = temp_t - quotient * new_t;

        int64_t temp_r = r;
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (r > 1) return 0;
    if (t < 0) t += mod;
    return static_cast<uint64_t>(t);
}

bool ElGamalCipher::isPrimitiveRoot(uint64_t g, uint64_t p) const
{
    if (g >= p) return false;

    uint64_t phi = p - 1;
    QVector<uint64_t> factors;
    uint64_t temp = phi;

    // Находим простые множители phi
    for (uint64_t i = 2; i * i <= temp; ++i) {
        if (temp % i == 0) {
            factors.append(i);
            while (temp % i == 0) temp /= i;
        }
    }
    if (temp > 1) factors.append(temp);

    // Проверяем g^(phi/p) mod p != 1 для каждого простого делителя
    for (uint64_t factor : factors) {
        if (modPow(g, phi / factor, p) == 1) {
            return false;
        }
    }
    return true;
}

bool ElGamalCipher::validateParameters(uint64_t p, uint64_t g, uint64_t x, QString& errorMessage) const
{

    // Проверка 1: p - простое число
    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }

    // Проверка 2: 1 < g < p
    if (g <= 1 || g >= p) {
        errorMessage = QString("G должно быть в диапазоне 1 < G < P (P=%1)").arg(p);
        return false;
    }

    // Проверка 3: 1 < x < p-1 (а не просто < p)
    if (x <= 1 || x >= p - 1) {
        errorMessage = QString("X должно быть в диапазоне 1 < X < P-1 (P=%1)").arg(p);
        return false;
    }

    // Проверка 4: порядок g должен делить p-1 (g не должен быть 1 или p-1)
    // Вместо проверки на первообразный корень, проверяем, что g не равен 1 и не равен p-1
    // и что g не слишком маленький (для безопасности)
    if (g == 1 || g == p - 1) {
        errorMessage = QString("G = %1 не подходит (не должно быть 1 или P-1)").arg(g);
        return false;
    }

    // Дополнительная проверка: g^((p-1)/2) mod p != 1 (чтобы избежать квадратичных вычетов)
    // Это необязательно, но повышает безопасность
    uint64_t halfOrder = modPow(g, (p - 1) / 2, p);
    if (halfOrder == 1) {
        // Предупреждение, но не ошибка
        qDebug() << "Предупреждение: G является квадратичным вычетом по модулю P";
    }

    return true;
}

bool ElGamalCipher::validateMessageNumber(uint64_t m, uint64_t p, QString& errorMessage) const
{
    if (m >= p) {
        errorMessage = QString("Число сообщения %1 >= P = %2").arg(m).arg(p);
        return false;
    }
    return true;
}

uint64_t ElGamalCipher::generatePrime(int bits) const
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1 << (bits - 1), (1 << bits) - 1);

    uint64_t candidate;
    do {
        candidate = dist(gen);
        if (candidate % 2 == 0) candidate++;
    } while (!isPrime(candidate, 10));

    return candidate;
}

uint64_t ElGamalCipher::generatePrimitiveRoot(uint64_t p) const
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, p - 1);

    uint64_t g;
    do {
        g = dist(gen);
    } while (!isPrimitiveRoot(g, p));

    return g;
}

uint64_t ElGamalCipher::generateRandomK(uint64_t p) const
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, p - 2);

    uint64_t k;
    do {
        k = dist(gen);
    } while (gcd(k, p - 1) != 1);

    return k;
}

// Алфавит в число (0-31)
int ElGamalCipher::charToNumber(QChar ch) const
{
    int pos = m_alphabet.indexOf(ch);
    if (pos >= 0 && pos < 32) {
        return pos;  // 0-31, а не 1-32
    }
    return 0;  // 'А' = 0
}

// Число в букву (0-31)
QChar ElGamalCipher::numberToChar(int num) const
{
    if (num >= 0 && num < 32) {
        return m_alphabet[num];
    }
    return '?';
}

// Преобразование текста в числа (каждая буква -> число 0-31)
QVector<uint64_t> ElGamalCipher::textToNumbers(const QString& text) const
{
    QVector<uint64_t> numbers;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    for (int i = 0; i < filtered.length(); ++i) {
        int num = charToNumber(filtered[i]);
        if (num >= 0 && num < 32) {
            numbers.append(static_cast<uint64_t>(num));
        }
    }

    return numbers;
}

// Преобразование чисел в текст (каждое число 0-31 -> буква)
QString ElGamalCipher::numbersToText(const QVector<uint64_t>& numbers) const
{
    QString result;

    for (uint64_t num : numbers) {
        if (num < 32) {
            result.append(m_alphabet[static_cast<int>(num)]);
        } else {
            result.append('?');
        }
    }

    return result;
}

QPair<uint64_t, uint64_t> ElGamalCipher::encryptNumber(uint64_t m, uint64_t p, uint64_t g, uint64_t y, uint64_t k) const
{
    uint64_t a = modPow(g, k, p);
    uint64_t b = (modPow(y, k, p) * (m % p)) % p;
    return qMakePair(a, b);
}

uint64_t ElGamalCipher::decryptNumber(uint64_t a, uint64_t b, uint64_t p, uint64_t x) const
{
    uint64_t ax = modPow(a, x, p);
    uint64_t axInv = modInverse(ax, p);
    return (b * axInv) % p;
}

// Статические методы
bool ElGamalCipher::isPrimeStatic(uint64_t n, int k)
{
    if (n <= 1) return false;
    if (n <= 3) return true;
    if (n % 2 == 0) return false;

    uint64_t d = n - 1;
    int r = 0;
    while (d % 2 == 0) {
        d /= 2;
        r++;
    }

    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, n - 2);

    for (int i = 0; i < k; ++i) {
        uint64_t a = dist(gen);
        uint64_t x = modPowStatic(a, d, n);
        if (x == 1 || x == n - 1) continue;
        bool composite = true;
        for (int j = 0; j < r - 1; ++j) {
            x = modPowStatic(x, 2, n);
            if (x == n - 1) {
                composite = false;
                break;
            }
        }
        if (composite) return false;
    }
    return true;
}

uint64_t ElGamalCipher::generatePrimeStatic(int bits)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1 << (bits - 1), (1 << bits) - 1);

    uint64_t candidate;
    do {
        candidate = dist(gen);
        if (candidate % 2 == 0) candidate++;
    } while (!isPrimeStatic(candidate, 10));

    return candidate;
}

uint64_t ElGamalCipher::generatePrimitiveRootStatic(uint64_t p)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, p - 1);

    auto isPrimitiveRootStatic = [&](uint64_t g, uint64_t prime) -> bool {
        if (g >= prime) return false;
        uint64_t phi = prime - 1;
        QVector<uint64_t> factors;
        uint64_t temp = phi;
        for (uint64_t i = 2; i * i <= temp; ++i) {
            if (temp % i == 0) {
                factors.append(i);
                while (temp % i == 0) temp /= i;
            }
        }
        if (temp > 1) factors.append(temp);
        for (uint64_t factor : factors) {
            if (modPowStatic(g, phi / factor, prime) == 1) return false;
        }
        return true;
    };

    uint64_t g;
    do {
        g = dist(gen);
    } while (!isPrimitiveRootStatic(g, p));

    return g;
}

uint64_t ElGamalCipher::generateRandomKStatic(uint64_t p)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, p - 2);

    auto gcdStatic = [](uint64_t a, uint64_t b) -> uint64_t {
        while (b != 0) {
            uint64_t temp = b;
            b = a % b;
            a = temp;
        }
        return a;
    };

    uint64_t k;
    do {
        k = dist(gen);
    } while (gcdStatic(k, p - 1) != 1);

    return k;
}

uint64_t ElGamalCipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
{
    uint64_t result = 1;
    base %= mod;
    while (exp > 0) {
        if (exp & 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp >>= 1;
    }
    return result;
}

// Шифрование
CipherResult ElGamalCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования ElGamal", "Инициализация"));

    // Получаем параметры
    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t g = params.value("g", 0).toULongLong();
    uint64_t x = params.value("x", 0).toULongLong();
    QString randMode = params.value("randomizerMode", "auto").toString();
    QVector<uint64_t> manualRandomizers;

    if (randMode == "manual") {
        QString randStr = params.value("randomizers", "").toString();
        QStringList parts = randStr.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);
        for (const QString& part : parts) {
            bool ok;
            uint64_t val = part.toULongLong(&ok);
            if (ok) manualRandomizers.append(val);
        }
    }

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(p, g, x, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, G=%2, X=%3").arg(p).arg(g).arg(x),
        "Проверка параметров"));

    uint64_t y = modPow(g, x, p);
    steps.append(CipherStep(2, QChar(),
        QString("Открытый ключ Y = G^X mod P = %1^%2 mod %3 = %4").arg(g).arg(x).arg(p).arg(y),
        "Вычисление открытого ключа"));

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(3, QChar(),
        QString("Входной текст: %1").arg(filteredText),
        "Подготовка данных"));

    // Преобразуем текст в числа
    QVector<uint64_t> numbers = textToNumbers(filteredText);

    // Проверяем, что все числа меньше P
    for (int i = 0; i < numbers.size(); ++i) {
        QString msgError;
        if (!validateMessageNumber(numbers[i], p, msgError)) {
            result.result = "ОШИБКА: " + msgError;
            return result;
        }
    }

    // Показываем оригинальные числа
    QString numbersStr;
    for (int i = 0; i < numbers.size() && i < 20; ++i) {
        numbersStr += QString("%1(%2) ").arg(filteredText[i]).arg(numbers[i]);
    }
    if (numbers.size() > 20) numbersStr += "...";

    steps.append(CipherStep(4, QChar(),
        QString("Преобразовано в числа 1-32: %1").arg(numbersStr),
        "Преобразование текста"));

    // Генерируем или получаем рандомизаторы
    QVector<uint64_t> randomizers;
    if (randMode == "auto") {
        // Автоматическая генерация для каждого символа
        for (int i = 0; i < numbers.size(); ++i) {
            randomizers.append(generateRandomK(p));
        }

        // Показываем первые 10 рандомизаторов
        QString randStr;
        for (int i = 0; i < randomizers.size() && i < 10; ++i) {
            randStr += QString::number(randomizers[i]) + " ";
        }
        if (randomizers.size() > 10) randStr += "...";
        steps.append(CipherStep(5, QChar(),
            QString("Сгенерированы рандомизаторы K: %1").arg(randStr),
            "Генерация рандомизаторов"));
    } else {
        // Ручной режим: циклическое использование
        if (manualRandomizers.isEmpty()) {
            result.result = "ОШИБКА: Не указаны рандомизаторы для ручного режима";
            return result;
        }

        if (manualRandomizers.size() < numbers.size()) {
            steps.append(CipherStep(5, QChar(),
                QString("ВНИМАНИЕ: Рандомизаторов (%1) меньше длины сообщения (%2). Циклическое использование!")
                    .arg(manualRandomizers.size()).arg(numbers.size()),
                "Предупреждение"));
        }

        // Циклическое заполнение
        for (int i = 0; i < numbers.size(); ++i) {
            randomizers.append(manualRandomizers[i % manualRandomizers.size()]);
        }

        // Проверяем, что все рандомизаторы взаимно просты с p-1
        bool hasError = false;
        for (int i = 0; i < randomizers.size(); ++i) {
            if (gcd(randomizers[i], p - 1) != 1) {
                hasError = true;
                steps.append(CipherStep(5 + i, QChar(),
                    QString("ОШИБКА: Рандомизатор K%1 = %2 не взаимно прост с φ(P)=%3")
                        .arg(i + 1).arg(randomizers[i]).arg(p - 1),
                    "Ошибка валидации"));
                break;
            }
        }

        if (hasError) {
            result.result = "ОШИБКА: Рандомизатор должен быть взаимно прост с φ(P)";
            return result;
        }

        QString randStr;
        for (int i = 0; i < randomizers.size() && i < 10; ++i) {
            randStr += QString::number(randomizers[i]) + " ";
        }
        if (randomizers.size() > 10) randStr += "...";
        steps.append(CipherStep(6, QChar(),
            QString("Используются рандомизаторы K (циклически): %1").arg(randStr),
            "Рандомизаторы"));
    }

    // Шифруем каждое число
    QVector<uint64_t> encryptedA;
    QVector<uint64_t> encryptedB;
    QVector<QString> stepDetails;

    for (int i = 0; i < numbers.size(); ++i) {
        uint64_t k = randomizers[i];
        auto pair = encryptNumber(numbers[i], p, g, y, k);
        encryptedA.append(pair.first);
        encryptedB.append(pair.second);
        stepDetails.append(QString("Блок %1: '%2' = %3, K=%4 → a=%5^%4 mod %6=%7, b=%8^%4×%3 mod %6=%9")
            .arg(i + 1)
            .arg(filteredText[i])
            .arg(numbers[i])
            .arg(k)
            .arg(g)
            .arg(p)
            .arg(pair.first)
            .arg(y)
            .arg(pair.second));
    }

    // Формируем результат: a1 b1 a2 b2 ...
    QString resultNumbers;
    for (int i = 0; i < encryptedA.size(); ++i) {
        if (i > 0) resultNumbers += " ";
        resultNumbers += QString::number(encryptedA[i]) + " " + QString::number(encryptedB[i]);
    }

    steps.append(CipherStep(7, QChar(),
        QString("Результат (a b пары): %1").arg(resultNumbers.left(100) + (resultNumbers.length() > 100 ? "..." : "")),
        "Завершение"));

    // Добавляем детальные шаги
    for (int i = 0; i < stepDetails.size() && i < 10; ++i) {
        steps.append(CipherStep(8 + i, QChar(), stepDetails[i], QString("Шаг %1").arg(i + 1)));
    }

    result.result = resultNumbers;
    result.steps = steps;

    return result;
}

// Дешифрование
CipherResult ElGamalCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало дешифрования ElGamal", "Инициализация"));

    // Получаем параметры
    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t g = params.value("g", 0).toULongLong();
    uint64_t x = params.value("x", 0).toULongLong();

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(p, g, x, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, G=%2, X=%3").arg(p).arg(g).arg(x),
        "Проверка параметров"));

    // Разбираем входные числа (пары a b)
    QString inputText = text.trimmed();
    inputText.replace(',', ' ');
    inputText.replace('\n', ' ');

    QStringList parts = inputText.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    if (parts.size() % 2 != 0) {
        result.result = "ОШИБКА: Нечетное количество чисел (должны быть пары a b)";
        return result;
    }

    QVector<QPair<uint64_t, uint64_t>> encryptedPairs;
    for (int i = 0; i < parts.size(); i += 2) {
        bool ok1, ok2;
        uint64_t a = parts[i].toULongLong(&ok1);
        uint64_t b = parts[i + 1].toULongLong(&ok2);
        if (ok1 && ok2) {
            encryptedPairs.append(qMakePair(a, b));
        }
    }

    steps.append(CipherStep(2, QChar(),
        QString("Получено %1 пар (a,b) для дешифрования").arg(encryptedPairs.size()),
        "Подготовка данных"));

    // Дешифруем каждую пару
    QVector<uint64_t> decryptedNumbers;
    QVector<QString> stepDetails;

    for (int i = 0; i < encryptedPairs.size(); ++i) {
        uint64_t a = encryptedPairs[i].first;
        uint64_t b = encryptedPairs[i].second;
        uint64_t decrypted = decryptNumber(a, b, p, x);
        decryptedNumbers.append(decrypted);

        uint64_t ax = modPow(a, x, p);
        uint64_t axInv = modInverse(ax, p);

        stepDetails.append(QString("Пара %1: (a=%2, b=%3) → a^x=%4^%5 mod %6=%7 → a^-x=%8 → M=%9×%10 mod %11=%12")
            .arg(i + 1)
            .arg(a)
            .arg(b)
            .arg(a)
            .arg(x)
            .arg(p)
            .arg(ax)
            .arg(axInv)
            .arg(b)
            .arg(axInv)
            .arg(p)
            .arg(decrypted));
    }

    // Преобразуем числа обратно в текст
    QString resultText = numbersToText(decryptedNumbers);

    steps.append(CipherStep(3, QChar(),
        QString("Результат: %1").arg(resultText),
        "Завершение"));

    // Добавляем детальные шаги
    for (int i = 0; i < stepDetails.size() && i < 10; ++i) {
        steps.append(CipherStep(4 + i, QChar(), stepDetails[i], QString("Шаг %1").arg(i + 1)));
    }

    result.result = resultText;
    result.steps = steps;

    return result;
}

// ==================== ElGamalCipherRegister Implementation ====================

ElGamalCipherRegister::ElGamalCipherRegister()
{
    CipherFactory::instance().registerCipher(
        "elgamal",
        "ElGamal",
        []() -> CipherInterface* { return new ElGamalCipher(); }
    );

    // Основные виджеты - только информационная панель
    CipherWidgetFactory::instance().registerCipherWidgets(
        "elgamal",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
        },
        // Расширенные виджеты
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // P - простое число
            QHBoxLayout* pRow = new QHBoxLayout();
            QLabel* pLabel = new QLabel("P (простое число):");
            pLabel->setFixedWidth(130);
            ElGamalNumberEdit* pEdit = new ElGamalNumberEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("Простое число (например, 257)");
            pRow->addWidget(pLabel);
            pRow->addWidget(pEdit);
            pRow->addStretch();
            mainLayout->addLayout(pRow);

            // G - генератор
            QHBoxLayout* gRow = new QHBoxLayout();
            QLabel* gLabel = new QLabel("G (генератор):");
            gLabel->setFixedWidth(130);
            ElGamalNumberEdit* gEdit = new ElGamalNumberEdit();
            gEdit->setObjectName("g");
            gEdit->setPlaceholderText("Генератор группы (2 < G < P)");
            gRow->addWidget(gLabel);
            gRow->addWidget(gEdit);
            gRow->addStretch();
            mainLayout->addLayout(gRow);

            // X - секретный ключ
            QHBoxLayout* xRow = new QHBoxLayout();
            QLabel* xLabel = new QLabel("X (секретный ключ):");
            xLabel->setFixedWidth(130);
            ElGamalNumberEdit* xEdit = new ElGamalNumberEdit();
            xEdit->setObjectName("x");
            xEdit->setPlaceholderText("Секретный ключ (1 < X < P-1)");
            xRow->addWidget(xLabel);
            xRow->addWidget(xEdit);
            xRow->addStretch();
            mainLayout->addLayout(xRow);

            // Кнопка генерации ключей
            QPushButton* generateButton = new QPushButton("Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            // Разделитель
            QFrame* line = new QFrame();
            line->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line);

            // Режим рандомизаторов
            QHBoxLayout* randModeRow = new QHBoxLayout();
            QLabel* randModeLabel = new QLabel("Режим рандомизаторов:");
            randModeLabel->setFixedWidth(130);
            QComboBox* randModeCombo = new QComboBox();
            randModeCombo->addItem("Автоматический (случайные K)", "auto");
            randModeCombo->addItem("Ручной (ввод K1 K2 K3...)", "manual");
            randModeCombo->setObjectName("randomizerMode");
            randModeRow->addWidget(randModeLabel);
            randModeRow->addWidget(randModeCombo);
            randModeRow->addStretch();
            mainLayout->addLayout(randModeRow);

            // Поле для ручного ввода рандомизаторов
            RandomizersEdit* randEdit = new RandomizersEdit();
            randEdit->setObjectName("randomizers");
            randEdit->setVisible(false);
            mainLayout->addWidget(randEdit);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "ElGamal — асимметричный шифр на основе дискретного логарифмирования:\n"
                "• Y = G^X mod P (открытый ключ)\n"
                "• Шифрование: a = G^K mod P, b = Y^K × M mod P\n"
                "• Дешифрование: M = b × (a^X)^-1 mod P\n"
                "• P должно быть простым, 1 < G < P, 1 < X < P-1\n"
                "• K должен быть взаимно прост с P-1\n"
                "• Каждая буква → число 0-31\n"
                "• Результат: a1 b1 a2 b2 ..."
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["g"] = gEdit;
            widgets["x"] = xEdit;
            widgets["randomizerMode"] = randModeCombo;
            widgets["randomizers"] = randEdit;
            widgets["generateButton"] = generateButton;

            // Подключаем переключение режима
            QObject::connect(randModeCombo, QOverload<int>::of(&QComboBox::currentIndexChanged),
                [randEdit](int index) {
                    randEdit->setVisible(index == 1);
                });

            // Подключаем генерацию ключей
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, gEdit, xEdit]() {
                uint64_t p = ElGamalCipher::generatePrimeStatic(16);
                uint64_t g = ElGamalCipher::generatePrimitiveRootStatic(p);
                uint64_t x = ElGamalCipher::generateRandomKStatic(p);

                pEdit->setValue(p);
                gEdit->setValue(g);
                xEdit->setValue(x);

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("Сгенерированы ключи (16 бит):\n\n"
                            "P = %1 (простое)\n"
                            "G = %2 (генератор)\n"
                            "X = %3 (секретный ключ)\n\n"
                            "Открытый ключ Y = %2^%3 mod %1 = %4")
                        .arg(p).arg(g).arg(x)
                        .arg(ElGamalCipher::modPowStatic(g, x, p)));
            });
        }
    );
}

static ElGamalCipherRegister elgamalRegister;
