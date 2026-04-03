#include "elgamalsign.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <random>

// ==================== ElGamalSignCipher Implementation ====================

ElGamalSignCipher::ElGamalSignCipher()
{
}

bool ElGamalSignCipher::isPrime(uint64_t n, int k) const
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

uint64_t ElGamalSignCipher::gcd(uint64_t a, uint64_t b) const
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t ElGamalSignCipher::gcdStatic(uint64_t a, uint64_t b)
{
    while (b != 0) {
        uint64_t temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

uint64_t ElGamalSignCipher::modPow(uint64_t base, uint64_t exp, uint64_t mod) const
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

uint64_t ElGamalSignCipher::modPowStatic(uint64_t base, uint64_t exp, uint64_t mod)
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

uint64_t ElGamalSignCipher::modInverse(uint64_t a, uint64_t mod) const
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

bool ElGamalSignCipher::isPrimitiveRoot(uint64_t g, uint64_t p) const
{
    if (g >= p) return false;

    uint64_t phi = p - 1;
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
        if (modPow(g, phi / factor, p) == 1) {
            return false;
        }
    }
    return true;
}

// ==================== Хеш-функция квадратичной свертки ====================
uint64_t ElGamalSignCipher::computeHash(const QString& text, uint64_t p, QVector<CipherStep>& steps, int stepOffset) const
{
    QString filtered = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filtered.isEmpty()) return 0;

    uint64_t h = 0;

    if (steps.size() > 0) {
        steps.append(CipherStep(stepOffset, QChar(),
            QString("Начало вычисления хеша: h0 = 0, модуль p = %1").arg(p),
            "Хеширование"));
    }

    for (int i = 0; i < filtered.length(); ++i) {
        int charIndex = m_alphabet.indexOf(filtered[i]);
        uint64_t Mi = static_cast<uint64_t>(charIndex + 1);

        uint64_t old_h = h;
        uint64_t sum = (h + Mi) % p;
        h = (sum * sum) % p;

        if (steps.size() > 0) {
            steps.append(CipherStep(stepOffset + i + 1, QChar(),
                QString("  h%1 = (h%2 + M%3)^2 mod p = (%4 + %5)^2 mod %6 = %7^2 mod %6 = %8")
                    .arg(i + 1).arg(i).arg(i + 1)
                    .arg(old_h).arg(Mi).arg(p)
                    .arg(sum).arg(h),
                QString("Хеш шаг %1: буква '%2' (№%3)").arg(i + 1).arg(filtered[i]).arg(Mi)));
        }
    }

    if (steps.size() > 0) {
        steps.append(CipherStep(stepOffset + filtered.length() + 1, QChar(),
            QString("Итоговый хеш: H = %1").arg(h),
            "Хеш завершен"));
    }

    return h;
}

bool ElGamalSignCipher::validateParameters(uint64_t p, uint64_t g, uint64_t x, uint64_t p_hash, QString& errorMessage) const
{
    const uint64_t ALPHABET_SIZE = 32;

    // Проверка модуля хеширования
    if (p_hash <= ALPHABET_SIZE) {
        errorMessage = QString("Модуль хеширования p = %1 должен быть больше мощности алфавита (%2)").arg(p_hash).arg(ALPHABET_SIZE);
        return false;
    }

    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }

    if (p <= ALPHABET_SIZE) {
        errorMessage = QString("P = %1 должно быть больше %2 (мощности алфавита)").arg(p).arg(ALPHABET_SIZE);
        return false;
    }

    if (g <= 1 || g >= p) {
        errorMessage = QString("G должно быть в диапазоне 1 < G < P (P=%1)").arg(p);
        return false;
    }

    if (x <= 1 || x >= p - 1) {
        errorMessage = QString("X должно быть в диапазоне 1 < X < P-1 (P=%1)").arg(p);
        return false;
    }

    return true;
}

int ElGamalSignCipher::charToNumber(QChar ch) const
{
    return m_alphabet.indexOf(ch);
}

QChar ElGamalSignCipher::numberToChar(int num) const
{
    if (num >= 0 && num < m_alphabet.length()) {
        return m_alphabet[num];
    }
    return '?';
}

QVector<uint64_t> ElGamalSignCipher::textToNumbers(const QString& text) const
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

QString ElGamalSignCipher::numbersToText(const QVector<uint64_t>& numbers) const
{
    QString result;
    for (uint64_t num : numbers) {
        if (num < static_cast<uint64_t>(m_alphabet.length())) {
            result.append(m_alphabet[static_cast<int>(num)]);
        } else {
            result.append('?');
        }
    }
    return result;
}

// Статические методы
// Статические методы
bool ElGamalSignCipher::isPrimeStatic(uint64_t n, int k)
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

uint64_t ElGamalSignCipher::generatePrimeStatic(int bits)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(1 << (bits - 1), (1 << bits) - 1);

    uint64_t candidate;
    do {
        candidate = dist(gen);
        if (candidate % 2 == 0) candidate++;
    } while (!ElGamalSignCipher::isPrimeStatic(candidate, 10));  // <-- ИСПРАВЛЕНО: добавлен ElGamalSignCipher::

    return candidate;
}

uint64_t ElGamalSignCipher::generatePrimitiveRootStatic(uint64_t p)
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
            if (ElGamalSignCipher::modPowStatic(g, phi / factor, prime) == 1) return false;
        }
        return true;
    };

    uint64_t g;
    do {
        g = dist(gen);
    } while (!isPrimitiveRootStatic(g, p));

    return g;
}

uint64_t ElGamalSignCipher::generateRandomKStatic(uint64_t p)
{
    std::random_device rd;
    std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dist(2, p - 2);

    uint64_t k;
    do {
        k = dist(gen);
    } while (ElGamalSignCipher::gcdStatic(k, p - 1) != 1);  // <-- ИСПРАВЛЕНО: добавлен ElGamalSignCipher::

    return k;
}

// ==================== Шифрование с подписью ====================
CipherResult ElGamalSignCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало подписи ElGamal", "Инициализация"));

    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t g = params.value("g", 0).toULongLong();
    uint64_t x = params.value("x", 0).toULongLong();
    uint64_t p_hash = params.value("p_hash", 0).toULongLong();

    if (p == 0 || g == 0 || x == 0) {
        result.result = "ОШИБКА: Для подписи необходимо ввести P, G и X";
        return result;
    }
    if (p_hash == 0) {
        result.result = "ОШИБКА: Необходимо указать модуль хеширования p (должен быть > 32)";
        return result;
    }

    QString validationError;
    if (!validateParameters(p, g, x, p_hash, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    uint64_t y = modPow(g, x, p);

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, G=%2, X=%3, Y=G^X mod P=%4, p_hash=%5")
            .arg(p).arg(g).arg(x).arg(y).arg(p_hash),
        "Вычисление ключей"));

    QString filteredText = CipherUtils::filterAlphabetOnly(text, m_alphabet);

    if (filteredText.isEmpty()) {
        result.result = "Нет букв для преобразования";
        return result;
    }

    steps.append(CipherStep(2, QChar(),
        QString("Сообщение: %1").arg(filteredText),
        "Подготовка данных"));

    // Вычисляем хеш сообщения
    int stepCounter = 3;
    uint64_t hash = computeHash(filteredText, p_hash, steps, stepCounter);
    stepCounter += filteredText.length() + 2;

    // Генерируем случайное K, взаимно простое с P-1
    uint64_t k = generateRandomKStatic(p);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Сгенерирован K = %1 (взаимно простое с P-1=%2)").arg(k).arg(p - 1),
        "Генерация K"));

    // Вычисляем a = G^K mod P
    uint64_t a = modPow(g, k, p);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("a = G^K mod P = %1^%2 mod %3 = %4").arg(g).arg(k).arg(p).arg(a),
        "Вычисление a"));

    // Решаем уравнение m = X*a + K*b (mod P-1)
    // b = (m - X*a) * K^(-1) mod (P-1)
    uint64_t phi = p - 1;

    // Вычисляем K^(-1) mod phi
    uint64_t k_inv = modInverse(k, phi);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("K⁻¹ mod (P-1) = %1⁻¹ mod %2 = %3").arg(k).arg(phi).arg(k_inv),
        "Вычисление обратного K"));

    // Вычисляем b
    uint64_t term = (hash + phi - (x * a) % phi) % phi;
    uint64_t b = (term * k_inv) % phi;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("b = (H - X*a) * K⁻¹ mod (P-1) = (%1 - %2*%3) * %4 mod %5 = %6")
            .arg(hash).arg(x).arg(a).arg(k_inv).arg(phi).arg(b),
        "Вычисление b"));

    // Формируем результат: исходный текст | a b
    QString signature = QString("%1 | %2 %3").arg(filteredText).arg(a).arg(b);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Подпись: (a=%1, b=%2)").arg(a).arg(b),
        "Создание подписи"));

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Результат: %1 | %2 %3").arg(filteredText).arg(a).arg(b),
        "Завершение"));

    result.result = signature;
    result.steps = steps;

    return result;
}

// ==================== Расшифрование с проверкой подписи ====================
CipherResult ElGamalSignCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало проверки подписи ElGamal", "Инициализация"));

    uint64_t p = params.value("p", 0).toULongLong();
    uint64_t g = params.value("g", 0).toULongLong();
    uint64_t y = params.value("y", 0).toULongLong();
    uint64_t p_hash = params.value("p_hash", 0).toULongLong();

    if (p == 0 || g == 0 || y == 0) {
        result.result = "ОШИБКА: Не указаны P, G и открытый ключ Y";
        return result;
    }
    if (p_hash == 0) {
        result.result = "ОШИБКА: Необходимо указать модуль хеширования p (должен быть > 32)";
        return result;
    }

    const uint64_t ALPHABET_SIZE = 32;
    if (p_hash <= ALPHABET_SIZE) {
        result.result = QString("ОШИБКА: Модуль хеширования p = %1 должен быть больше %2")
                            .arg(p_hash).arg(ALPHABET_SIZE);
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: P=%1, G=%2, Y=%3, p_hash=%4").arg(p).arg(g).arg(y).arg(p_hash),
        "Проверка параметров"));

    // Разбираем входные данные: сообщение | a b
    QString inputText = text.trimmed();
    int separatorPos = inputText.indexOf("|");

    if (separatorPos == -1) {
        result.result = "ОШИБКА: Неверный формат. Ожидается: 'сообщение | a b'";
        return result;
    }

    QString message = inputText.left(separatorPos).trimmed();
    QString signaturePart = inputText.mid(separatorPos + 1).trimmed();

    QStringList parts = signaturePart.split(QRegularExpression("\\s+"), Qt::SkipEmptyParts);

    if (parts.size() < 2) {
        result.result = "ОШИБКА: Не удалось распознать подпись (ожидается a b)";
        return result;
    }

    bool aOk, bOk;
    uint64_t a = parts[0].toULongLong(&aOk);
    uint64_t b = parts[1].toULongLong(&bOk);

    if (!aOk || !bOk) {
        result.result = "ОШИБКА: Не удалось распознать числа a и b";
        return result;
    }

    steps.append(CipherStep(2, QChar(),
        QString("Получена подпись: a=%1, b=%2").arg(a).arg(b),
        "Извлечение подписи"));

    steps.append(CipherStep(3, QChar(),
        QString("Сообщение: %1").arg(message),
        "Извлечение сообщения"));

    // Вычисляем хеш сообщения
    int stepCounter = 4;
    uint64_t hash = computeHash(message, p_hash, steps, stepCounter);
    stepCounter += message.length() + 2;

    // Вычисляем A1 = Y^a * a^b mod P
    uint64_t ya = modPow(y, a, p);
    uint64_t ab = modPow(a, b, p);
    uint64_t A1 = (ya * ab) % p;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("A1 = Y^a * a^b mod P = %1^%2 * %3^%4 mod %5 = %6 * %7 mod %5 = %8")
            .arg(y).arg(a).arg(a).arg(b).arg(p).arg(ya).arg(ab).arg(A1),
        "Вычисление A1"));

    // Вычисляем A2 = G^m mod P
    uint64_t A2 = modPow(g, hash, p);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("A2 = G^H mod P = %1^%2 mod %3 = %4")
            .arg(g).arg(hash).arg(p).arg(A2),
        "Вычисление A2"));

    // Проверка
    if (A1 == A2) {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✓ Подпись ВЕРНА! A1 (%1) == A2 (%2)").arg(A1).arg(A2),
            "Проверка подписи - УСПЕШНО"));
        result.result = QString("%1").arg(message);
    } else {
        steps.append(CipherStep(stepCounter++, QChar(),
            QString("✗ Подпись НЕВЕРНА! A1 = %1 != A2 = %2").arg(A1).arg(A2),
            "Проверка подписи - ОШИБКА"));
        result.result = QString("ОШИБКА ПОДПИСИ: A1 = %1 != A2 = %2").arg(A1).arg(A2);
    }

    result.steps = steps;
    return result;
}

// ==================== ElGamalSignCipherRegister Implementation ====================

ElGamalSignCipherRegister::ElGamalSignCipherRegister()
{
    CipherFactory::instance().registerCipher(
        25,
        "ElGamal с цифровой подписью",
        []() -> CipherInterface* { return new ElGamalSignCipher(); }
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "elgamal_sign",
        [](QWidget*, QVBoxLayout*, QMap<QString, QWidget*>&) {},
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Заголовок для подписи
            QLabel* signTitle = new QLabel("Для ПОДПИСАНИЯ (создание подписи):");
            signTitle->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(signTitle);

            // Сетка для P, G, X (2x2)
            QGridLayout* gridLayout = new QGridLayout();
            gridLayout->setSpacing(8);

            // Строка 0: P и G
            QLabel* pLabel = new QLabel("P (простое):");
            pLabel->setFixedWidth(100);
            QLineEdit* pEdit = new QLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("257");
            pEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), pEdit));

            QLabel* gLabel = new QLabel("G (генератор):");
            gLabel->setFixedWidth(100);
            QLineEdit* gEdit = new QLineEdit();
            gEdit->setObjectName("g");
            gEdit->setPlaceholderText("2");
            gEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), gEdit));

            gridLayout->addWidget(pLabel, 0, 0);
            gridLayout->addWidget(pEdit, 0, 1);
            gridLayout->addWidget(gLabel, 0, 2);
            gridLayout->addWidget(gEdit, 0, 3);

            // Строка 1: X
            QLabel* xLabel = new QLabel("X (секретный):");
            xLabel->setFixedWidth(100);
            QLineEdit* xEdit = new QLineEdit();
            xEdit->setObjectName("x");
            xEdit->setPlaceholderText("1 < X < P-1");
            xEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), xEdit));

            gridLayout->addWidget(xLabel, 1, 0);
            gridLayout->addWidget(xEdit, 1, 1);

            mainLayout->addLayout(gridLayout);

            // Разделитель
            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line1);

            // Общие параметры (единые для подписи и проверки)
            QLabel* commonTitle = new QLabel("Общие параметры:");
            commonTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(commonTitle);

            // Сетка для общих параметров
            QGridLayout* commonLayout = new QGridLayout();
            commonLayout->setSpacing(8);

            // Строка 0: Модуль p (единый)
            QLabel* pHashLabel = new QLabel("Модуль p (хеш):");
            pHashLabel->setFixedWidth(100);
            QLineEdit* pHashEdit = new QLineEdit();
            pHashEdit->setObjectName("p_hash");
            pHashEdit->setPlaceholderText(">32 (напр. 101)");
            pHashEdit->setText("101");
            pHashEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), pHashEdit));

            commonLayout->addWidget(pHashLabel, 0, 0);
            commonLayout->addWidget(pHashEdit, 0, 1);

            mainLayout->addLayout(commonLayout);

            // Разделитель
            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line2);

            // Заголовок для проверки
            QLabel* verifyTitle = new QLabel("Для ПРОВЕРКИ подписи:");
            verifyTitle->setStyleSheet("font-weight: bold; color: #2c3e50; margin-top: 5px;");
            mainLayout->addWidget(verifyTitle);

            // Сетка для Y
            QGridLayout* gridLayout2 = new QGridLayout();
            gridLayout2->setSpacing(8);

            QLabel* yLabel = new QLabel("Y (открытый ключ):");
            yLabel->setFixedWidth(100);
            QLineEdit* yEdit = new QLineEdit();
            yEdit->setObjectName("y");
            yEdit->setPlaceholderText("Y = G^X mod P");
            yEdit->setValidator(new QRegularExpressionValidator(QRegularExpression("^[0-9]{1,20}$"), yEdit));

            gridLayout2->addWidget(yLabel, 0, 0);
            gridLayout2->addWidget(yEdit, 0, 1);

            mainLayout->addLayout(gridLayout2);

            // Кнопка генерации ключей
            QPushButton* generateButton = new QPushButton("Сгенерировать ключи (16 бит)");
            generateButton->setObjectName("generateButton");
            generateButton->setCursor(Qt::PointingHandCursor);
            mainLayout->addWidget(generateButton);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "ElGamal с цифровой подписью:\n"
                "Подписание: a = G^K mod P, b = (H - X*a) * K⁻¹ mod (P-1)\n"
                "Проверка: Y^a * a^b mod P == G^H mod P\n"
                "Хеш: hᵢ = (hᵢ₋₁ + Mᵢ)² mod p (А=1...Я=32)\n"
                "P - простое число, G - генератор, X - секретный ключ, Y - открытый ключ"
            );
            infoLabel->setStyleSheet("color: #666; font-size: 9px; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["p"] = pEdit;
            widgets["g"] = gEdit;
            widgets["x"] = xEdit;
            widgets["p_hash"] = pHashEdit;
            widgets["y"] = yEdit;
            widgets["generateButton"] = generateButton;

            // Подключаем генерацию ключей
            QObject::connect(generateButton, &QPushButton::clicked, [pEdit, gEdit, xEdit, yEdit, pHashEdit]() {
                uint64_t p = ElGamalSignCipher::generatePrimeStatic(16);
                uint64_t g = ElGamalSignCipher::generatePrimitiveRootStatic(p);
                uint64_t x = ElGamalSignCipher::generateRandomKStatic(p);
                uint64_t y = ElGamalSignCipher::modPowStatic(g, x, p);

                pEdit->setText(QString::number(p));
                gEdit->setText(QString::number(g));
                xEdit->setText(QString::number(x));
                yEdit->setText(QString::number(y));

                QMessageBox::information(nullptr, "Ключи сгенерированы",
                    QString("P = %1 (простое)\n"
                            "G = %2 (генератор)\n"
                            "X = %3 (секретный ключ)\n"
                            "Y = %4 (открытый ключ)\n\n"
                            "Модуль хеширования p должен быть > 32\n"
                            "Рекомендуемое значение: 101 или больше")
                        .arg(p).arg(g).arg(x).arg(y));
            });
        }
    );
}

static ElGamalSignCipherRegister elgamalSignRegister;
