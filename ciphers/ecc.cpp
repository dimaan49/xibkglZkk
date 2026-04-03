#include "ecc.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QComboBox>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <random>

// ==================== ECCNumberEdit Implementation ====================

ECCNumberEdit::ECCNumberEdit(QWidget* parent)
    : QLineEdit(parent)
{
    m_originalStyle = styleSheet();

    QRegularExpression numRegex("^[0-9]{0,20}$");
    QRegularExpressionValidator* validator = new QRegularExpressionValidator(numRegex, this);
    setValidator(validator);

    setPlaceholderText("Введите число");
}

void ECCNumberEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("ECCNumberEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet(m_originalStyle);
    }
}

void ECCNumberEdit::focusInEvent(QFocusEvent* event)
{
    if (!m_valid) {
        setValid(true);
    }
    QLineEdit::focusInEvent(event);
}

uint64_t ECCNumberEdit::getValue() const
{
    QString text = this->text();
    if (text.isEmpty()) return 0;
    bool ok;
    uint64_t value = text.toULongLong(&ok);
    return ok ? value : 0;
}

void ECCNumberEdit::setValue(uint64_t value)
{
    setText(QString::number(value));
}

// ==================== ECCPointEdit Implementation ====================

ECCPointEdit::ECCPointEdit(QWidget* parent)
    : QWidget(parent)
{
    QHBoxLayout* layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(5);

    QLabel* openLabel = new QLabel("(");
    m_xEdit = new ECCNumberEdit();
    m_xEdit->setFixedWidth(80);
    m_xEdit->setPlaceholderText("x");
    QLabel* commaLabel = new QLabel(",");
    m_yEdit = new ECCNumberEdit();
    m_yEdit->setFixedWidth(80);
    m_yEdit->setPlaceholderText("y");
    QLabel* closeLabel = new QLabel(")");

    layout->addWidget(openLabel);
    layout->addWidget(m_xEdit);
    layout->addWidget(commaLabel);
    layout->addWidget(m_yEdit);
    layout->addWidget(closeLabel);
    layout->addStretch();
}

ECPoint ECCPointEdit::getPoint() const
{
    return ECPoint(m_xEdit->getValue(), m_yEdit->getValue());
}

void ECCPointEdit::setPoint(const ECPoint& point)
{
    if (point.isInfinity) {
        m_xEdit->clear();
        m_yEdit->clear();
    } else {
        m_xEdit->setValue(point.x);
        m_yEdit->setValue(point.y);
    }
}

void ECCPointEdit::setValid(bool valid)
{
    m_valid = valid;
    if (!valid) {
        setStyleSheet("ECCPointEdit { border: 2px solid red; background-color: #ffeeee; }");
    } else {
        setStyleSheet("");
    }
}

// ==================== ECCCipher Implementation ====================

ECCCipher::ECCCipher()
{
}

uint64_t ECCCipher::modAdd(uint64_t a, uint64_t b, uint64_t p)
{
    return (a + b) % p;
}

uint64_t ECCCipher::modSub(uint64_t a, uint64_t b, uint64_t p)
{
    return (a + p - (b % p)) % p;
}

uint64_t ECCCipher::modMul(uint64_t a, uint64_t b, uint64_t p)
{
    return (a * b) % p;
}

uint64_t ECCCipher::modPow(uint64_t base, uint64_t exp, uint64_t mod)
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

uint64_t ECCCipher::modInverse(uint64_t a, uint64_t p)
{
    // Расширенный алгоритм Евклида
    int64_t t = 0, new_t = 1;
    int64_t r = p, new_r = a;

    while (new_r != 0) {
        int64_t quotient = r / new_r;
        int64_t temp_t = t;
        t = new_t;
        new_t = temp_t - quotient * new_t;

        int64_t temp_r = r;
        r = new_r;
        new_r = temp_r - quotient * new_r;
    }

    if (r > 1) return 0; // Нет обратного
    if (t < 0) t += p;
    return static_cast<uint64_t>(t);
}

ECPoint ECCCipher::pointAdd(const ECPoint& P, const ECPoint& Q, uint64_t a, uint64_t p)
{
    // Если P - бесконечная точка
    if (P.isInfinity) return Q;
    if (Q.isInfinity) return P;

    // Если точки совпадают по x
    if (P.x == Q.x) {
        // Если y тоже совпадают (P = Q)
        if (P.y == Q.y) {
            return pointDouble(P, a, p);
        }
        // Иначе P = -Q (P + (-P) = бесконечность)
        return ECPoint(); // бесконечная точка
    }

    // λ = (y2 - y1) * (x2 - x1)^(-1) mod p
    uint64_t dx = modSub(Q.x, P.x, p);
    uint64_t dy = modSub(Q.y, P.y, p);
    uint64_t lambda = modMul(dy, modInverse(dx, p), p);

    // x3 = λ^2 - x1 - x2 mod p
    uint64_t x3 = modSub(modSub(modMul(lambda, lambda, p), P.x, p), Q.x, p);
    // y3 = λ(x1 - x3) - y1 mod p
    uint64_t y3 = modSub(modMul(lambda, modSub(P.x, x3, p), p), P.y, p);

    return ECPoint(x3, y3);
}

ECPoint ECCCipher::pointDouble(const ECPoint& P, uint64_t a, uint64_t p)
{
    if (P.isInfinity || P.y == 0) {
        return ECPoint(); // бесконечная точка
    }

    // λ = (3*x1^2 + a) * (2*y1)^(-1) mod p
    uint64_t threeX2 = modMul(3, modMul(P.x, P.x, p), p);
    uint64_t numerator = modAdd(threeX2, a, p);
    uint64_t denominator = modMul(2, P.y, p);
    uint64_t lambda = modMul(numerator, modInverse(denominator, p), p);

    // x3 = λ^2 - 2*x1 mod p
    uint64_t x3 = modSub(modMul(lambda, lambda, p), modMul(2, P.x, p), p);
    // y3 = λ(x1 - x3) - y1 mod p
    uint64_t y3 = modSub(modMul(lambda, modSub(P.x, x3, p), p), P.y, p);

    return ECPoint(x3, y3);
}

ECPoint ECCCipher::pointMultiply(const ECPoint& P, uint64_t k, uint64_t a, uint64_t p)
{
    ECPoint result; // бесконечная точка
    ECPoint base = P;
    uint64_t multiplier = k;

    while (multiplier > 0) {
        if (multiplier & 1) {
            result = pointAdd(result, base, a, p);
        }
        base = pointDouble(base, a, p);
        multiplier >>= 1;
    }

    return result;
}

bool ECCCipher::isPointOnCurve(const ECPoint& P, uint64_t a, uint64_t b, uint64_t p)
{
    if (P.isInfinity) return true;

    // y^2 mod p = (x^3 + a*x + b) mod p
    uint64_t left = modMul(P.y, P.y, p);
    uint64_t right = modAdd(modAdd(modMul(modMul(P.x, P.x, p), P.x, p), modMul(a, P.x, p), p), b, p);

    return left == right;
}

bool ECCCipher::validateParameters(uint64_t a, uint64_t b, uint64_t p,
                                   const ECPoint& G, uint64_t cB,
                                   QString& errorMessage)
{
    // Проверка 1: p должно быть простым
    auto isPrime = [](uint64_t n) -> bool {
        if (n <= 1) return false;
        if (n <= 3) return true;
        if (n % 2 == 0) return false;
        for (uint64_t i = 3; i * i <= n; i += 2) {
            if (n % i == 0) return false;
        }
        return true;
    };

    if (!isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }

    // Проверка 2: дискриминант 4a^3 + 27b^2 ≠ 0 mod p
    uint64_t a3 = modMul(modMul(a, a, p), a, p);
    uint64_t b2 = modMul(b, b, p);
    uint64_t discriminant = modAdd(modMul(4, a3, p), modMul(27, b2, p), p);
    if (discriminant == 0) {
        errorMessage = "Дискриминант кривой равен 0 (кривая сингулярна)";
        return false;
    }

    // Проверка 3: G лежит на кривой
    if (!isPointOnCurve(G, a, b, p)) {
        errorMessage = QString("Точка G(%1, %2) не лежит на кривой").arg(G.x).arg(G.y);
        return false;
    }

    // Проверка 4: 1 < cB < p
    if (cB <= 1 || cB >= p) {
        errorMessage = QString("Cb должно быть в диапазоне 1 < Cb < P (P=%1)").arg(p);
        return false;
    }

    return true;
}

QString ECCCipher::pointToString(const ECPoint& P)
{
    if (P.isInfinity) return "inf";
    return QString("(%1,%2)").arg(P.x).arg(P.y);
}

ECPoint ECCCipher::stringToPoint(const QString& str)
{
    if (str.trimmed() == "inf") return ECPoint();

    // Формат: (x,y)
    QRegularExpression regex("\\((\\d+),(\\d+)\\)");
    QRegularExpressionMatch match = regex.match(str.trimmed());
    if (match.hasMatch()) {
        return ECPoint(match.captured(1).toULongLong(),
                       match.captured(2).toULongLong());
    }
    return ECPoint();
}

CipherResult ECCCipher::encrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = "Числа";
    result.isNumeric = true;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало шифрования ECC (Эль-Гамаль)", "Инициализация"));

    // Получаем параметры
    uint64_t a = params.value("a", 0).toULongLong();
    uint64_t b = params.value("b", 0).toULongLong();
    uint64_t p = params.value("p", 0).toULongLong();
    QString gStr = params.value("g", "").toString();
    uint64_t cB = params.value("cB", 0).toULongLong();
    uint64_t k = params.value("k", 0).toULongLong();

    ECPoint G = stringToPoint(gStr);

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(a, b, p, G, cB, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: a=%1, b=%2, p=%3, G=%4, Cb=%5, k=%6")
            .arg(a).arg(b).arg(p).arg(pointToString(G)).arg(cB).arg(k),
        "Проверка параметров"));

    // Получаем сообщение M (число)
    uint64_t M = text.trimmed().toULongLong();
    if (M == 0 && text.trimmed() != "0") {
        result.result = "ОШИБКА: Введите число для шифрования";
        return result;
    }

    steps.append(CipherStep(2, QChar(),
        QString("Сообщение M = %1").arg(M),
        "Подготовка данных"));

    // Проверяем, что M < p
    if (M >= p) {
        result.result = QString("ОШИБКА: M = %1 >= P = %2").arg(M).arg(p);
        return result;
    }

    // Вычисляем открытый ключ: DB = [Cb]G
    ECPoint DB = pointMultiply(G, cB, a, p);
    steps.append(CipherStep(3, QChar(),
        QString("Открытый ключ DB = [Cb]G = [%1]%2 = %3")
            .arg(cB).arg(pointToString(G)).arg(pointToString(DB)),
        "Вычисление открытого ключа"));

    // Шифрование:
    // R = [k]G
    ECPoint R = pointMultiply(G, k, a, p);
    // P = [k]DB = (x, y)
    ECPoint P = pointMultiply(DB, k, a, p);
    // e = M * x mod p (где x - координата x точки P)
    uint64_t e = modMul(M, P.x, p);

    steps.append(CipherStep(4, QChar(),
        QString("Шифрование:\n  R = [k]G = [%1]%2 = %3\n  P = [k]DB = %4\n  e = M * x_P = %1 * %5 mod %6 = %7")
            .arg(k).arg(pointToString(G)).arg(pointToString(R))
            .arg(pointToString(P)).arg(P.x).arg(p).arg(e),
        "Шифрование"));

    // Формируем результат: R(x,y) и e
    QString resultStr = QString("%1 %2").arg(pointToString(R)).arg(e);

    steps.append(CipherStep(5, QChar(),
        QString("Результат: %1").arg(resultStr),
        "Завершение"));

    result.result = resultStr;
    result.steps = steps;

    return result;
}

CipherResult ECCCipher::decrypt(const QString& text, const QVariantMap& params)
{
    CipherResult result;
    result.cipherName = name();
    result.alphabet = "Числа";
    result.isNumeric = false;

    QVector<CipherStep> steps;
    steps.append(CipherStep(0, QChar(), "Начало расшифрования ECC (Эль-Гамаль)", "Инициализация"));

    // Получаем параметры
    uint64_t a = params.value("a", 0).toULongLong();
    uint64_t b = params.value("b", 0).toULongLong();
    uint64_t p = params.value("p", 0).toULongLong();
    QString gStr = params.value("g", "").toString();
    uint64_t cB = params.value("cB", 0).toULongLong();

    ECPoint G = stringToPoint(gStr);

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(a, b, p, G, cB, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: a=%1, b=%2, p=%3, G=%4, Cb=%5")
            .arg(a).arg(b).arg(p).arg(pointToString(G)).arg(cB),
        "Проверка параметров"));

    // Разбираем шифртекст: R(x,y) и e
    QString inputText = text.trimmed();
    QRegularExpression regex("\\((\\d+),(\\d+)\\)\\s+(\\d+)");
    QRegularExpressionMatch match = regex.match(inputText);

    if (!match.hasMatch()) {
        result.result = "ОШИБКА: Неверный формат шифртекста. Ожидается: (x,y) e";
        return result;
    }

    ECPoint R(match.captured(1).toULongLong(), match.captured(2).toULongLong());
    uint64_t e = match.captured(3).toULongLong();

    steps.append(CipherStep(2, QChar(),
        QString("Получен шифртекст: R=%1, e=%2").arg(pointToString(R)).arg(e),
        "Подготовка данных"));

    // Проверяем, что R лежит на кривой
    if (!isPointOnCurve(R, a, b, p)) {
        result.result = QString("ОШИБКА: Точка R(%1, %2) не лежит на кривой").arg(R.x).arg(R.y);
        return result;
    }

    // расшифрование:
    // Q = [Cb]R = (x, y)
    ECPoint Q = pointMultiply(R, cB, a, p);
    // M = e * x^(-1) mod p
    uint64_t xInv = modInverse(Q.x, p);
    uint64_t M = modMul(e, xInv, p);

    steps.append(CipherStep(3, QChar(),
        QString("расшифрование:\n  Q = [Cb]R = [%1]%2 = %3\n  x^(-1) = %4^(-1) mod %5 = %6\n  M = e * x^(-1) mod p = %7 * %8 mod %9 = %10")
            .arg(cB).arg(pointToString(R)).arg(pointToString(Q))
            .arg(Q.x).arg(p).arg(xInv)
            .arg(e).arg(xInv).arg(p).arg(M),
        "расшифрование"));

    steps.append(CipherStep(4, QChar(),
        QString("Результат: M = %1").arg(M),
        "Завершение"));

    result.result = QString::number(M);
    result.steps = steps;

    return result;
}

// ==================== ECCCipherRegister Implementation ====================

ECCCipherRegister::ECCCipherRegister()
{
    CipherFactory::instance().registerCipher(
        23,
        "ECC (Эль-Гамаль)",
        []() -> CipherInterface* { return new ECCCipher(); },
        CipherCategory::Asymmetric
    );

    CipherWidgetFactory::instance().registerCipherWidgets(
        "ecc",
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            // Пустые основные виджеты
            Q_UNUSED(parent);
            Q_UNUSED(layout);
            Q_UNUSED(widgets);
        },
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
            QWidget* paramsContainer = new QWidget(parent);
            QVBoxLayout* mainLayout = new QVBoxLayout(paramsContainer);
            mainLayout->setSpacing(8);
            mainLayout->setContentsMargins(0, 5, 0, 5);

            // Параметры кривой: a, b, p
            QHBoxLayout* aRow = new QHBoxLayout();
            QLabel* aLabel = new QLabel("a:");
            aLabel->setFixedWidth(50);
            ECCNumberEdit* aEdit = new ECCNumberEdit();
            aEdit->setObjectName("a");
            aEdit->setPlaceholderText("коэффициент a");
            aRow->addWidget(aLabel);
            aRow->addWidget(aEdit);
            aRow->addStretch();
            mainLayout->addLayout(aRow);

            QHBoxLayout* bRow = new QHBoxLayout();
            QLabel* bLabel = new QLabel("b:");
            bLabel->setFixedWidth(50);
            ECCNumberEdit* bEdit = new ECCNumberEdit();
            bEdit->setObjectName("b");
            bEdit->setPlaceholderText("коэффициент b");
            bRow->addWidget(bLabel);
            bRow->addWidget(bEdit);
            bRow->addStretch();
            mainLayout->addLayout(bRow);

            QHBoxLayout* pRow = new QHBoxLayout();
            QLabel* pLabel = new QLabel("p (простое):");
            pLabel->setFixedWidth(50);
            ECCNumberEdit* pEdit = new ECCNumberEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("модуль поля");
            pRow->addWidget(pLabel);
            pRow->addWidget(pEdit);
            pRow->addStretch();
            mainLayout->addLayout(pRow);

            // Точка G
            QHBoxLayout* gLabelRow = new QHBoxLayout();
            QLabel* gLabel = new QLabel("G (генератор):");
            gLabel->setFixedWidth(50);
            gLabelRow->addWidget(gLabel);
            gLabelRow->addStretch();
            mainLayout->addLayout(gLabelRow);

            ECCPointEdit* gEdit = new ECCPointEdit();
            gEdit->setObjectName("g");
            mainLayout->addWidget(gEdit);

            // Секретный ключ Cb
            QHBoxLayout* cbRow = new QHBoxLayout();
            QLabel* cbLabel = new QLabel("Cb (секретный ключ):");
            cbLabel->setFixedWidth(120);
            ECCNumberEdit* cbEdit = new ECCNumberEdit();
            cbEdit->setObjectName("cB");
            cbEdit->setPlaceholderText("секретный ключ (1 < Cb < p)");
            cbRow->addWidget(cbLabel);
            cbRow->addWidget(cbEdit);
            cbRow->addStretch();
            mainLayout->addLayout(cbRow);

            // Рандомизатор k
            QHBoxLayout* kRow = new QHBoxLayout();
            QLabel* kLabel = new QLabel("k (рандомизатор):");
            kLabel->setFixedWidth(120);
            ECCNumberEdit* kEdit = new ECCNumberEdit();
            kEdit->setObjectName("k");
            kEdit->setPlaceholderText("случайное число");
            kRow->addWidget(kLabel);
            kRow->addWidget(kEdit);
            kRow->addStretch();
            mainLayout->addLayout(kRow);

            // Информационная панель
            QLabel* infoLabel = new QLabel(
                "ECC (Эль-Гамаль) — шифрование на эллиптических кривых:\n"
                "• Кривая: y² = x³ + a·x + b mod p\n"
                "• Открытый ключ: DB = [Cb]G\n"
                "• Шифрование: R = [k]G, P = [k]DB, e = M·x_P mod p\n"
                "• расшифрование: M = e·(x_Q)⁻¹ mod p, где Q = [Cb]R\n"
                "• Вход/выход: одно число"
            );
            infoLabel->setStyleSheet("color: #666; font-style: italic; padding: 5px; background-color: #f5f5f5; border-radius: 3px;");
            infoLabel->setWordWrap(true);
            mainLayout->addWidget(infoLabel);

            layout->addWidget(paramsContainer);

            widgets["a"] = aEdit;
            widgets["b"] = bEdit;
            widgets["p"] = pEdit;
            widgets["g"] = gEdit;
            widgets["cB"] = cbEdit;
            widgets["k"] = kEdit;
        }
    );
}

static ECCCipherRegister eccRegister;
