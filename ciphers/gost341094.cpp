#include "gost341094.h"
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
#include <cmath>

// ==================== Вспомогательные функции ====================


GOST341094Cipher::GOST341094Cipher()
{
}

bool GOST341094Cipher::isPrime(uint64_t n, int k) const
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

bool GOST341094Cipher::isPrimeStatic(uint64_t n, int k)
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

uint64_t GOST341094Cipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t GOST341094Cipher::gcdStatic(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t GOST341094Cipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
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

uint64_t GOST341094Cipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
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

uint64_t GOST341094Cipher::modInverse(uint64_t a, uint64_t mod) const
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

uint64_t GOST341094Cipher::generatePrimeStatic(int bits)
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

uint64_t GOST341094Cipher::generateRandomStatic(uint64_t max)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, max - 1);
    return dist(gen);
}

// ==================== Хеш-функция ====================

uint64_t GOST341094Cipher::computeHash(const QString& text, uint64_t p,
                                        QVector<CipherStep>& steps, int& stepCounter) const
{
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filtered.isEmpty()) return 0;

    uint64_t mod = p;
    if (mod < 32) mod = 257;

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
            QString("  h%1 = (h%2 + M%3)² mod %4 = (%5 + %6)² mod %4 = %7² mod %4 = %8")
                .arg(i + 1).arg(i).arg(i + 1)
                .arg(mod).arg(old_h).arg(Mi).arg(sum).arg(h),
            QString("Хеш шаг %1: буква '%2' (№%3)").arg(i + 1).arg(filtered[i]).arg(Mi)));
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Итоговый хеш: H = %1").arg(h),
        "Хеш завершен"));

    return h;
}

int GOST341094Cipher::charToNumber(QChar ch) const
{
    return m_alphabet.indexOf(ch);
}

QChar GOST341094Cipher::numberToChar(int num) const
{
    if (num >= 0 && num < m_alphabet.length()) {
        return m_alphabet[num];
    }
    return '?';
}

QVector<uint64_t> GOST341094Cipher::textToNumbers(const QString& text) const
{
    QVector<uint64_t> numbers;
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);
    for (int i = 0; i < filtered.length(); ++i) {
        numbers.append(static_cast<uint64_t>(charToNumber(filtered[i])));
    }
    return numbers;
}

QString GOST341094Cipher::numbersToText(const QVector<uint64_t>& numbers) const
{
    QString result;
    for (uint64_t num : numbers) {
        result.append(numberToChar(static_cast<int>(num)));
    }
    return result;
}

bool GOST341094Cipher::validateParameters(uint64_t p, uint64_t q, uint64_t a, uint64_t x, uint64_t k, uint64_t p_hash, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    if (p_hash <= ALPHABET_SIZE) {
        errorMessage = QString("Модуль хеширования p_hash = %1 должен быть больше %2").arg(p_hash).arg(ALPHABET_SIZE);
        return false;
    }

    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }

    if (!isPrime(q)) {
        errorMessage = QString("Q = %1 не является простым числом").arg(q);
        return false;
    }

    if (a <= 1 || a >= p - 1) {
        errorMessage = QString("A должно быть в диапазоне 1 < A < P-1 (P=%1)").arg(p);
        return false;
    }

    if (modPow(a, q, p) != 1) {
        errorMessage = QString("Условие a^q mod p = 1 не выполняется. %1^%2 mod %3 = %4")
                           .arg(a).arg(q).arg(p).arg(modPow(a, q, p));
        return false;
    }

    if (x <= 0 || x >= q) {
        errorMessage = QString("X должно быть в диапазоне 0 < X < Q (Q=%1)").arg(q);
        return false;
    }

    if (k <= 0 || k >= q) {
        errorMessage = QString("K должно быть в диапазоне 0 < K < Q (Q=%1)").arg(q);
        return false;
    }

    return true;
}

// ==================== Шифрование (создание подписи) ====================

CipherResult GOST341094Cipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(), "Начало формирования подписи по ГОСТ Р 34.10-94", "Инициализация"));

    // Получаем параметры
    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t q = params.value("q", 0).toULongLong();
    uint64_t a = params.value("a", 0).toULongLong();
    uint64_t x = params.value("x", 0).toULongLong();
    uint64_t k = params.value("k", 0).toULongLong();
    uint64_t p_hash = params.value("p_hash", 101).toULongLong();

    if (p == 0 || q == 0 || a == 0 || x == 0 || k == 0) {
        result.result = "ОШИБКА: Необходимо указать все параметры (p, q, a, x, k)";
        return result;
    }

    // Проверка параметров
    QString validationError;
    if (!validateParameters(p, q, a, x, k, p_hash, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры схемы:\n  p = %1 (простое)\n  q = %2 (простое, делитель p-1)\n  a = %3 (a^q mod p = 1)\n  x = %4 (секретный ключ)\n  k = %5 (случайное число)\n  p_hash = %6 (модуль хеширования)")
            .arg(p).arg(q).arg(a).arg(x).arg(k).arg(p_hash),
        "Параметры схемы"));

    // Фильтруем текст
    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Сообщение: %1").arg(filteredText),
        "Сообщение"));

    // Шаг 1: Вычисляем хеш сообщения H(m)
    uint64_t hash = computeHash(filteredText, p_hash, steps, stepCounter);

    // Коррекция: если H(m) mod q = 0, то H(m) = 1
    uint64_t hm = hash % q;
    if (hm == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("H(m) mod q = 0, устанавливаем H(m) = 1"),
            "Коррекция хеша"));
        hm = 1;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 1: H(m) = %1, H(m) mod q = %2").arg(hash).arg(hm),
        "Вычисление хеша"));

    // Шаг 2: Вычисляем r = (a^k mod p) mod q
    uint64_t ak = modPow(a, k, p);
    uint64_t r = ak % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: r = (a^k mod p) mod q = (%1^%2 mod %3) mod %4 = %5 mod %6 = %7")
            .arg(a).arg(k).arg(p).arg(q).arg(ak).arg(q).arg(r),
        "Вычисление r"));

    // Проверка: если r == 0, нужно выбрать другое k
    if (r == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "r = 0, необходимо выбрать другое k",
            "Ошибка"));
        result.result = "ОШИБКА: r = 0. Выберите другое значение k";
        return result;
    }

    // Шаг 3: Вычисляем s = (x * r + k * H(m)) mod q
    uint64_t xr = (x * r) % q;
    uint64_t khm = (k * hm) % q;
    uint64_t s = (xr + khm) % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: s = (x*r + k*H(m)) mod q = (%1*%2 + %3*%4) mod %5 = (%6 + %7) mod %5 = %8")
            .arg(x).arg(r).arg(k).arg(hm).arg(q).arg(xr).arg(khm).arg(s),
        "Вычисление s"));

    // Проверка: если s == 0, нужно выбрать другое k
    if (s == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "s = 0, необходимо выбрать другое k",
            "Ошибка"));
        result.result = "ОШИБКА: s = 0. Выберите другое значение k";
        return result;
    }

    // Вычисляем y = a^x mod p (открытый ключ)
    uint64_t y = modPow(a, x, p);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Открытый ключ: y = a^x mod p = %1^%2 mod %3 = %4")
            .arg(a).arg(x).arg(p).arg(y),
        "Вычисление y"));

    // Формируем результат: подпись (r, s)
    QString signature = QString("%1 %2").arg(r).arg(s);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Цифровая подпись: (r = %1, s = %2)").arg(r).arg(s),
        "Подпись"));

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Для проверки подписи необходимы: p=%1, q=%2, a=%3, y=%4").arg(p).arg(q).arg(a).arg(y),
        "Информация для проверки"));

    result.result = signature;
    result.steps = steps;

    return result;
}

// ==================== Расшифрование (проверка подписи) ====================

CipherResult GOST341094Cipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(), "Начало проверки подписи по ГОСТ Р 34.10-94", "Инициализация"));

    // Получаем параметры
    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t q = params.value("q", 0).toULongLong();
    uint64_t a = params.value("a", 0).toULongLong();
    uint64_t y = params.value("y", 0).toULongLong();
    uint64_t p_hash = params.value("p_hash", 101).toULongLong();

    // Сообщение для проверки
    QString message = params.value("message", "").toString();

    if (p == 0 || q == 0 || a == 0 || y == 0) {
        result.result = "ОШИБКА: Необходимо указать параметры p, q, a, y";
        return result;
    }

    if (message.isEmpty()) {
        result.result = "ОШИБКА: Для проверки подписи необходимо указать сообщение в поле 'Сообщение для проверки'";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры проверки:\n  p = %1\n  q = %2\n  a = %3\n  y = %4 (открытый ключ)\n  p_hash = %5")
            .arg(p).arg(q).arg(a).arg(y).arg(p_hash),
        "Параметры"));

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Сообщение для проверки: %1").arg(message),
        "Сообщение"));

    // Разбираем подпись (r и s)
    QString sig = text.trimmed();
    QStringList parts = sig.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    if (parts.size() < 2) {
        result.result = "ОШИБКА: Неверный формат подписи. Ожидается: r s";
        return result;
    }

    bool rOk, sOk;
    uint64_t r = parts[0].toULongLong(&rOk);
    uint64_t s = parts[1].toULongLong(&sOk);

    if (!rOk || !sOk) {
        result.result = "ОШИБКА: Не удалось распознать r и s";
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Получена подпись: r = %1, s = %2").arg(r).arg(s),
        "Извлечение подписи"));

    // Шаг 1: Проверка 0 < r < q и 0 < s < q
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 1: Проверка диапазона: 0 < r < q и 0 < s < q"),
        "Проверка диапазона"));

    if (r == 0 || r >= q) {
        result.result = QString("ОШИБКА: r = %1 не удовлетворяет условию 0 < r < q = %2").arg(r).arg(q);
        return result;
    }

    if (s == 0 || s >= q) {
        result.result = QString("ОШИБКА: s = %1 не удовлетворяет условию 0 < s < q = %2").arg(s).arg(q);
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        "Условия выполнены: 0 < r < q и 0 < s < q",
        "Проверка диапазона - OK"));

    // Шаг 2: Вычисляем хеш сообщения H(m)
    uint64_t hash = computeHash(message, p_hash, steps, stepCounter);

    uint64_t hm = hash % q;
    if (hm == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("H(m) mod q = 0, устанавливаем H(m) = 1"),
            "Коррекция хеша"));
        hm = 1;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: H(m) = %1, H(m) mod q = %2").arg(hash).arg(hm),
        "Вычисление хеша"));

    // Шаг 3: Вычисляем v = H(m)^(q-2) mod q
    uint64_t v = modPow(hm, q - 2, q);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: v = H(m)^(q-2) mod q = %1^(%2-2) mod %3 = %4")
            .arg(hm).arg(q).arg(q).arg(v),
        "Вычисление v"));

    // Шаг 4: Вычисляем z1 = s * v mod q
    uint64_t z1 = (s * v) % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 4: z1 = s * v mod q = %1 * %2 mod %3 = %4")
            .arg(s).arg(v).arg(q).arg(z1),
        "Вычисление z1"));

    // Шаг 5: Вычисляем z2 = (q - r) * v mod q
    uint64_t q_minus_r = (q - r) % q;
    uint64_t z2 = (q_minus_r * v) % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 5: z2 = (q - r) * v mod q = (%1 - %2) * %3 mod %4 = %5 * %3 mod %4 = %6")
            .arg(q).arg(r).arg(v).arg(q).arg(q_minus_r).arg(z2),
        "Вычисление z2"));

    // Шаг 6: Вычисляем u = (a^z1 * y^z2 mod p) mod q
    uint64_t a_z1 = modPow(a, z1, p);
    uint64_t y_z2 = modPow(y, z2, p);
    uint64_t product = (a_z1 * y_z2) % p;
    uint64_t u = product % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 6:\n  a^z1 mod p = %1^%2 mod %3 = %4\n  y^z2 mod p = %5^%6 mod %7 = %8\n  (a^z1 * y^z2) mod p = %9\n  u = (%9) mod q = %10")
            .arg(a).arg(z1).arg(p).arg(a_z1)
            .arg(y).arg(z2).arg(p).arg(y_z2)
            .arg(product).arg(u),
        "Вычисление u"));

    // Шаг 7: Проверка u == r
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 7: Сравнение u и r: u = %1, r = %2").arg(u).arg(r),
        "Проверка подписи"));

    if (u == r) {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✓ Подпись ВЕРНА! u (%1) == r (%2)").arg(u).arg(r),
            "Проверка подписи - УСПЕШНО"));
        result.result = QString("✓ ПОДПИСЬ ВЕРНА!\n\nСообщение: %1").arg(message);
    } else {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✗ Подпись НЕВЕРНА! u = %1, r = %2").arg(u).arg(r),
            "Проверка подписи - ОШИБКА"));
        result.result = QString("✗ ПОДПИСЬ НЕВЕРНА!\nu = %1\nr = %2").arg(u).arg(r);
    }

    result.steps = steps;
    return result;
}

// ==================== Регистратор ====================

GOST341094CipherRegister::GOST341094CipherRegister()
{
    CipherFactory::instance().registerCipher(
        26,
        "ГОСТ Р 34.10-94 (ЭЦП)",
        []() -> CipherInterface* { return new GOST341094Cipher(); },
        CipherCategory::DigitalSignature
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        26,
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Заголовок
            QLabel* title = new QLabel("Параметры схемы подписи (ГОСТ Р 34.10-94)");
            title->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(title);

            // Сетка для параметров
            QGridLayout* grid = new QGridLayout();
            grid->setSpacing(8);

            // p - простое число
            QLabel* pLabel = new QLabel("p (простое):");
            pLabel->setFixedWidth(100);
            QLineEdit* pEdit = new QLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("Простое число");
            pEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), pEdit));
            grid->addWidget(pLabel, 0, 0);
            grid->addWidget(pEdit, 0, 1);

            // q - простой делитель p-1
            QLabel* qLabel = new QLabel("q (делитель p-1):");
            qLabel->setFixedWidth(100);
            QLineEdit* qEdit = new QLineEdit();
            qEdit->setObjectName("q");
            qEdit->setPlaceholderText("Простое число");
            qEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), qEdit));
            grid->addWidget(qLabel, 0, 2);
            grid->addWidget(qEdit, 0, 3);

            // a - число, a^q mod p = 1
            QLabel* aLabel = new QLabel("a (основание):");
            aLabel->setFixedWidth(100);
            QLineEdit* aEdit = new QLineEdit();
            aEdit->setObjectName("a");
            aEdit->setPlaceholderText("1 < a < p-1");
            aEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), aEdit));
            grid->addWidget(aLabel, 1, 0);
            grid->addWidget(aEdit, 1, 1);

            // x - секретный ключ
            QLabel* xLabel = new QLabel("x (секретный ключ):");
            xLabel->setFixedWidth(100);
            QLineEdit* xEdit = new QLineEdit();
            xEdit->setObjectName("x");
            xEdit->setPlaceholderText("0 < x < q");
            xEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), xEdit));
            grid->addWidget(xLabel, 1, 2);
            grid->addWidget(xEdit, 1, 3);

            // k - случайное число
            QLabel* kLabel = new QLabel("k (случайное):");
            kLabel->setFixedWidth(100);
            QLineEdit* kEdit = new QLineEdit();
            kEdit->setObjectName("k");
            kEdit->setPlaceholderText("0 < k < q");
            kEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), kEdit));
            grid->addWidget(kLabel, 2, 0);
            grid->addWidget(kEdit, 2, 1);

            // y - открытый ключ (вычисляется)
            QLabel* yLabel = new QLabel("y (открытый ключ):");
            yLabel->setFixedWidth(100);
            QLineEdit* yEdit = new QLineEdit();
            yEdit->setObjectName("y");
            yEdit->setPlaceholderText("y = a^x mod p (для проверки)");
            yEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), yEdit));
            grid->addWidget(yLabel, 2, 2);
            grid->addWidget(yEdit, 2, 3);

            mainLayout->addLayout(grid);

            // Разделитель
            QFrame* line = new QFrame();
            line->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line);

            // Общие параметры
            QLabel* commonTitle = new QLabel("Общие параметры:");
            commonTitle->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(commonTitle);

            QGridLayout* commonGrid = new QGridLayout();
            commonGrid->setSpacing(8);

            // Модуль хеширования
            QLabel* pHashLabel = new QLabel("Модуль p (хеш):");
            pHashLabel->setFixedWidth(100);
            QLineEdit* pHashEdit = new QLineEdit();
            pHashEdit->setObjectName("p_hash");
            pHashEdit->setText("101");
            pHashEdit->setPlaceholderText(">32");
            pHashEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]+$"), pHashEdit));
            commonGrid->addWidget(pHashLabel, 0, 0);
            commonGrid->addWidget(pHashEdit, 0, 1);

            mainLayout->addLayout(commonGrid);

            // Разделитель
            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line2);

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

            // Кнопка генерации ключей
            QPushButton* generateButton = new QPushButton("🎲 Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "ГОСТ Р 34.10-94 — цифровая подпись на основе дискретного логарифмирования:\n"
                "Подписание: r = (a^k mod p) mod q, s = (x·r + k·H(m)) mod q\n"
                "Проверка: v = H(m)^(q-2) mod q, z1 = s·v mod q, z2 = (q-r)·v mod q, u = (a^z1·y^z2 mod p) mod q\n"
                "Подпись верна, если u = r\n"
                "Условия: p и q — простые, q | (p-1), a^q mod p = 1, 0 < x,k < q"
            );
            infoLabel->setStyleSheet("color: #666; font-size: 9px; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["q"] = qEdit;
            widgets["a"] = aEdit;
            widgets["x"] = xEdit;
            widgets["k"] = kEdit;
            widgets["y"] = yEdit;
            widgets["p_hash"] = pHashEdit;
            widgets["message"] = messageEdit;
            widgets["generateButton"] = generateButton;

            // Генерация ключей
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, qEdit, aEdit, xEdit, kEdit, yEdit]() {
                uint64_t p = GOST341094Cipher::generatePrimeStatic(16);
                uint64_t q = GOST341094Cipher::generatePrimeStatic(12);

                // Находим q | (p-1)
                while ((p - 1) % q != 0) {
                    q = GOST341094Cipher::generatePrimeStatic(12);
                }

                // Находим a: a^q mod p = 1
                uint64_t a = 2;
                while (GOST341094Cipher::modPowStatic(a, q, p) != 1) {
                    a++;
                    if (a >= p) break;
                }

                uint64_t x = GOST341094Cipher::generateRandomStatic(q);
                uint64_t k = GOST341094Cipher::generateRandomStatic(q);
                uint64_t y = GOST341094Cipher::modPowStatic(a, x, p);

                pEdit->setText(QString::number(p));
                qEdit->setText(QString::number(q));
                aEdit->setText(QString::number(a));
                xEdit->setText(QString::number(x));
                kEdit->setText(QString::number(k));
                yEdit->setText(QString::number(y));

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("p = %1\nq = %2\na = %3\nx = %4 (секретный)\nk = %5\n\ny = %6 (открытый ключ)\n\nСохраните p, q, a, y для проверки подписи!")
                        .arg(p).arg(q).arg(a).arg(x).arg(k).arg(y));
            });
        }
    );
}

static GOST341094CipherRegister gost341094Register;
