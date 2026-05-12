#include "ecc.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "texttransformer.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QRegularExpression>
#include <QRegularExpressionValidator>
#include <QDebug>
#include <random>

// ==================== ECCPointEdit Implementation ====================

ECCPointEdit::ECCPointEdit(QWidget* parent)
    : QWidget(parent)
{
    QHBoxLayout* layout = new QHBoxLayout(this);
    layout->setContentsMargins(0, 0, 0, 0);
    layout->setSpacing(5);

    QLabel* openLabel = new QLabel("(");
    m_xEdit = new NumberLineEdit();
    m_xEdit->setFixedWidth(80);
    m_xEdit->setPlaceholderText("x");
    QLabel* commaLabel = new QLabel(",");
    m_yEdit = new NumberLineEdit();
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

ECC_Point ECCPointEdit::getPoint() const
{
    return ECC_Point(m_xEdit->getValue(), m_yEdit->getValue());
}

void ECCPointEdit::setPoint(const ECC_Point& point)
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

bool ECCCipher::validateParameters(uint64_t a, uint64_t b, uint64_t p,
                                   const ECC_Point& G, uint64_t cB,
                                   QString& errorMessage)
{
    // p должно быть простым
    if (!CoreMath::isPrime(p)) {
        errorMessage = QString("P = %1 не является простым числом").arg(p);
        return false;
    }

    // Дискриминант 4a³ + 27b² ≠ 0 mod p
    uint64_t a3 = CoreMath::modMul(CoreMath::modMul(a, a, p), a, p);
    uint64_t b2 = CoreMath::modMul(b, b, p);
    uint64_t discriminant = (4 * a3 + 27 * b2) % p;
    if (discriminant == 0) {
        errorMessage = "Дискриминант кривой равен 0 (кривая сингулярна)";
        return false;
    }

    // G лежит на кривой
    if (!CoreCurves::isPointOnCurve(G, p, a, b)) {
        errorMessage = QString("Точка G(%1, %2) не лежит на кривой").arg(G.x).arg(G.y);
        return false;
    }

    // 1 < cB < p
    if (cB <= 1 || cB >= p) {
        errorMessage = QString("Cb должно быть в диапазоне 1 < Cb < P (P=%1)").arg(p);
        return false;
    }

    return true;
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

    ECC_Point G = CoreCurves::parsePoint(gStr);

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(a, b, p, G, cB, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: a=%1, b=%2, p=%3, G=%4, Cb=%5, k=%6")
            .arg(a).arg(b).arg(p).arg(G.toString()).arg(cB).arg(k),
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
    ECC_Point DB = CoreCurves::pointMultiply(G, cB, p, a);
    steps.append(CipherStep(3, QChar(),
        QString("Открытый ключ DB = [Cb]G = [%1]%2 = %3")
            .arg(cB).arg(G.toString()).arg(DB.toString()),
        "Вычисление открытого ключа"));

    // Шифрование:
    // R = [k]G
    ECC_Point R = CoreCurves::pointMultiply(G, k, p, a);
    // P = [k]DB = (x, y)
    ECC_Point P = CoreCurves::pointMultiply(DB, k, p, a);
    // e = M * x mod p
    uint64_t e = CoreMath::modMul(M, P.x, p);

    steps.append(CipherStep(4, QChar(),
        QString("Шифрование:\n  R = [k]G = [%1]%2 = %3\n  P = [k]DB = %4\n  e = M * x_P = %5 * %6 mod %7 = %8")
            .arg(k).arg(G.toString()).arg(R.toString())
            .arg(P.toString()).arg(M).arg(P.x).arg(p).arg(e),
        "Шифрование"));

    // Формируем результат: R(x,y) и e
    QString resultStr = QString("%1 %2").arg(R.toString()).arg(e);

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

    ECC_Point G = CoreCurves::parsePoint(gStr);

    // Проверяем параметры
    QString validationError;
    if (!validateParameters(a, b, p, G, cB, validationError)) {
        result.result = "ОШИБКА: " + validationError;
        return result;
    }

    steps.append(CipherStep(1, QChar(),
        QString("Параметры: a=%1, b=%2, p=%3, G=%4, Cb=%5")
            .arg(a).arg(b).arg(p).arg(G.toString()).arg(cB),
        "Проверка параметров"));

    // Разбираем шифртекст: R(x,y) и e
    QString inputText = text.trimmed();
    inputText = TextTransformer::fromLetterCodes(inputText);

    // Извлекаем все числа из строки
    QVector<uint64_t> numbers;
    QString current;
    for (const QChar& ch : inputText) {
        if (ch.isDigit()) {
            current += ch;
        } else if (!current.isEmpty()) {
            numbers.append(current.toULongLong());
            current.clear();
        }
    }
    if (!current.isEmpty()) {
        numbers.append(current.toULongLong());
    }

    if (numbers.size() != 3) {
        result.result = "ОШИБКА: Неверный формат шифртекста. Ожидается: (x,y) e\nПолучено: " + inputText;
        result.steps = steps;
        return result;
    }

    ECC_Point R(numbers[0], numbers[1]);
    uint64_t e = numbers[2];

    steps.append(CipherStep(2, QChar(),
        QString("Получен шифртекст: R=%1, e=%2").arg(R.toString()).arg(e),
        "Подготовка данных"));

    // Проверяем, что R лежит на кривой
    if (!CoreCurves::isPointOnCurve(R, p, a, b)) {
        result.result = QString("ОШИБКА: Точка R(%1, %2) не лежит на кривой").arg(R.x).arg(R.y);
        result.steps = steps;
        return result;
    }

    // Расшифрование:
    // Q = [Cb]R = (x, y)
    ECC_Point Q = CoreCurves::pointMultiply(R, cB, p, a);
    // M = e * x^(-1) mod p
    uint64_t xInv = CoreMath::modInverse(Q.x, p);
    uint64_t M = CoreMath::modMul(e, xInv, p);

    steps.append(CipherStep(3, QChar(),
        QString("Расшифрование:\n  Q = [Cb]R = [%1]%2 = %3\n  x^(-1) = %4^(-1) mod %5 = %6\n  M = e * x^(-1) mod p = %7 * %8 mod %9 = %10")
            .arg(cB).arg(R.toString()).arg(Q.toString())
            .arg(Q.x).arg(p).arg(xInv)
            .arg(e).arg(xInv).arg(p).arg(M),
        "Расшифрование"));

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
        23,
        [](QWidget* parent, QVBoxLayout* layout, QMap<QString, QWidget*>& widgets) {
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
            NumberLineEdit* aEdit = new NumberLineEdit();
            aEdit->setObjectName("a");
            aEdit->setPlaceholderText("коэффициент a");
            aRow->addWidget(aLabel);
            aRow->addWidget(aEdit);
            aRow->addStretch();
            mainLayout->addLayout(aRow);

            QHBoxLayout* bRow = new QHBoxLayout();
            QLabel* bLabel = new QLabel("b:");
            bLabel->setFixedWidth(50);
            NumberLineEdit* bEdit = new NumberLineEdit();
            bEdit->setObjectName("b");
            bEdit->setPlaceholderText("коэффициент b");
            bRow->addWidget(bLabel);
            bRow->addWidget(bEdit);
            bRow->addStretch();
            mainLayout->addLayout(bRow);

            QHBoxLayout* pRow = new QHBoxLayout();
            QLabel* pLabel = new QLabel("p (простое):");
            pLabel->setFixedWidth(50);
            NumberLineEdit* pEdit = new NumberLineEdit();
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
            NumberLineEdit* cbEdit = new NumberLineEdit();
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
            NumberLineEdit* kEdit = new NumberLineEdit();
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
                "• Расшифрование: M = e·(x_Q)⁻¹ mod p, где Q = [Cb]R\n"
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
