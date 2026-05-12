#include "gost34102012.h"
#include "cipherfactory.h"
#include "cipherwidgetfactory.h"
#include "texttransformer.h"
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QGridLayout>
#include <QLabel>
#include <QPushButton>
#include <QMessageBox>
#include <QLineEdit>
#include <QTextEdit>
#include <QFrame>
#include <cstdint>

// ==================== Парсинг чисел ====================

uint64_t GOST34102012Cipher::parseUint64(const QString& str) const {
    QString s = str.trimmed();
    if (s.isEmpty()) return 0;

    // HEX
    if (s.startsWith("0x", Qt::CaseInsensitive)) {
        s = s.mid(2);
        bool ok;
        uint64_t val = s.toULongLong(&ok, 16);
        return ok ? val : 0;
    }

    // DEC
    bool ok;
    uint64_t val = s.toULongLong(&ok, 10);
    return ok ? val : 0;
}

// ==================== Формирование подписи ====================

CipherResult GOST34102012Cipher::encrypt(const QString& text, const QVariantMap& params) {
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = true;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(),
        "Начало формирования подписи по ГОСТ Р 34.10-2012", "Инициализация"));

    // Получаем параметры
    uint64_t p = parseUint64(params.value("p", "").toString());
    uint64_t a = parseUint64(params.value("a", "").toString());
    uint64_t b = parseUint64(params.value("b", "").toString());
    uint64_t q = parseUint64(params.value("q", "").toString());
    uint64_t xp = parseUint64(params.value("xp", "").toString());
    uint64_t yp = parseUint64(params.value("yp", "").toString());
    uint64_t d = parseUint64(params.value("d", "").toString());
    uint64_t k = parseUint64(params.value("k", "").toString());

    // Проверка наличия параметров
    QString sp = params.value("p", "").toString().trimmed();
    QString sq = params.value("q", "").toString().trimmed();
    QString sxp = params.value("xp", "").toString().trimmed();
    QString syp = params.value("yp", "").toString().trimmed();
    QString sd = params.value("d", "").toString().trimmed();
    QString sk = params.value("k", "").toString().trimmed();

    if (sp.isEmpty() || sq.isEmpty() || sxp.isEmpty() || syp.isEmpty() || sd.isEmpty() || sk.isEmpty()) {
        result.result = "ОШИБКА: Необходимо указать все параметры (p, a, b, q, xp, yp, d, k)";
        result.steps = steps;
        return result;
    }

    ECC_Point G(xp, yp);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры: p=%1, a=%2, b=%3, q=%4, G=%5, d=%6, k=%7")
            .arg(p).arg(a).arg(b).arg(q).arg(G.toString()).arg(d).arg(k),
        "Параметры схемы"));

    // Вычисление открытого ключа Q = d·G
    ECC_Point Q = CoreCurves::pointMultiply(G, d, p, a);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Открытый ключ: Q = d·G = %1·%2 = %3")
            .arg(d).arg(G.toString()).arg(Q.toString()),
        "Вычисление открытого ключа Q"));

    // Хеш сообщения
    uint64_t hash = CoreHash::quadraticHash(text, q, &steps, stepCounter);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 1: h(M) = %1").arg(hash),
        "Хеширование сообщения"));

    // Точка C = k·G
    ECC_Point C = CoreCurves::pointMultiply(G, k, p, a);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: C = k·G = %1·%2 = %3")
            .arg(k).arg(G.toString()).arg(C.toString()),
        "Вычисление точки C"));

    // r = x_C mod q
    uint64_t r = C.x % q;
    if (r == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "r = 0, необходимо выбрать другое k", "Ошибка: r = 0"));
        result.result = "ОШИБКА: r = 0, выберите другое k";
        result.steps = steps;
        return result;
    }
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: r = x_C mod q = %1 mod %2 = %3").arg(C.x).arg(q).arg(r),
        "Вычисление r"));

    // s = (k·h + r·d) mod q
    uint64_t kh = CoreMath::modMul(k, hash, q);
    uint64_t rd = CoreMath::modMul(r, d, q);
    uint64_t s = (kh + rd) % q;

    if (s == 0) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "s = 0, необходимо выбрать другое k", "Ошибка: s = 0"));
        result.result = "ОШИБКА: s = 0, выберите другое k";
        result.steps = steps;
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 4: s = (k·h + r·d) mod q = (%1·%2 + %3·%4) mod %5 = %6")
            .arg(k).arg(hash).arg(r).arg(d).arg(q).arg(s),
        "Вычисление s"));

    QString signature = QString("(%1, %2)").arg(r).arg(s);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Цифровая подпись: (r, s) = %1").arg(signature),
        "Завершение"));

    result.result = signature;
    result.steps = steps;
    return result;
}

// ==================== Проверка подписи ====================

CipherResult GOST34102012Cipher::decrypt(const QString& text, const QVariantMap& params) {
    CipherResult result;
    result.cipherName = name();
    result.alphabet = m_alphabet;
    result.isNumeric = false;

    QVector<CipherStep> steps;
    int stepCounter = 0;
    steps.append(CipherStep(stepCounter++, QChar(),
        "Начало проверки подписи по ГОСТ Р 34.10-2012", "Инициализация"));

    // Получаем параметры
    uint64_t p = parseUint64(params.value("p", "").toString());
    uint64_t a = parseUint64(params.value("a", "").toString());
    uint64_t b = parseUint64(params.value("b", "").toString());
    uint64_t q = parseUint64(params.value("q", "").toString());
    uint64_t xp = parseUint64(params.value("xp", "").toString());
    uint64_t yp = parseUint64(params.value("yp", "").toString());
    uint64_t xq = parseUint64(params.value("xq", "").toString());
    uint64_t yq = parseUint64(params.value("yq", "").toString());
    QString message = params.value("message", "").toString();

    QString sp = params.value("p", "").toString().trimmed();
    QString sq = params.value("q", "").toString().trimmed();
    QString sxp = params.value("xp", "").toString().trimmed();
    QString syp = params.value("yp", "").toString().trimmed();
    QString sxq = params.value("xq", "").toString().trimmed();
    QString syq = params.value("yq", "").toString().trimmed();

    if (sp.isEmpty() || sq.isEmpty() || sxp.isEmpty() || syp.isEmpty() || sxq.isEmpty() || syq.isEmpty()) {
        result.result = "ОШИБКА: Необходимо указать все параметры (p, a, b, q, xp, yp, xq, yq)";
        result.steps = steps;
        return result;
    }

    if (message.isEmpty()) {
        result.result = "ОШИБКА: Укажите сообщение для проверки подписи";
        result.steps = steps;
        return result;
    }

    ECC_Point G(xp, yp);
    ECC_Point Q(xq, yq);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Параметры: p=%1, q=%2, G=%3, Q=%4")
            .arg(p).arg(q).arg(G.toString()).arg(Q.toString()),
        "Параметры схемы"));

    // Парсим подпись
    QString decodedText = TextTransformer::fromLetterCodes(text);
    QString sig = decodedText.trimmed();
    sig.remove('(').remove(')').remove(' ');
    QStringList parts = sig.split(',');

    if (parts.size() != 2) {
        result.result = "ОШИБКА: Неверный формат подписи (ожидается r,s)";
        result.steps = steps;
        return result;
    }

    uint64_t r = parseUint64(parts[0].trimmed());
    uint64_t s = parseUint64(parts[1].trimmed());

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Подпись: r = %1, s = %2").arg(r).arg(s),
        "Извлечение подписи"));

    // Проверка диапазона
    if (r == 0 || r >= q || s == 0 || s >= q) {
        result.result = "ОШИБКА: Неверные значения подписи (0 < r,s < q)";
        result.steps = steps;
        return result;
    }

    steps.append(CipherStep(stepCounter++, QChar(),
        "Шаг 1: 0 < r < q и 0 < s < q — выполнено", "Проверка диапазона"));

    // Хеш сообщения
    uint64_t hash = CoreHash::quadraticHash(message, q, &steps, stepCounter);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 2: h(M) = %1").arg(hash), "Хеширование"));

    // h⁻¹ mod q
    uint64_t h_inv = CoreMath::modInverse(hash % q, q);
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 3: h⁻¹ mod q = %1").arg(h_inv), "Обратный элемент"));

    // u1 = s·h⁻¹ mod q, u2 = -r·h⁻¹ mod q
    uint64_t u1 = CoreMath::modMul(s, h_inv, q);
    uint64_t u2 = (q - CoreMath::modMul(r, h_inv, q)) % q;

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 4: u1 = %1, u2 = %2").arg(u1).arg(u2),
        "Вычисление u1, u2"));

    // P = u1·G + u2·Q
    ECC_Point P1 = CoreCurves::pointMultiply(G, u1, p, a);
    ECC_Point P2 = CoreCurves::pointMultiply(Q, u2, p, a);
    ECC_Point P = CoreCurves::pointAdd(P1, P2, p, a);

    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 5: P = %1").arg(P.toString()),
        "Вычисление точки P"));

    // R = x_P mod q
    uint64_t R = P.x % q;
    steps.append(CipherStep(stepCounter++, QChar(),
        QString("Шаг 6: R = %1").arg(R), "Вычисление R"));

    // Проверка подписи
    if (R == r) {
        steps.append(CipherStep(stepCounter++, QChar(),
            "✓ Подпись ВЕРНА!", "Успех"));
        result.result = QString("✓ ПОДПИСЬ ВЕРНА!\n\nСообщение: %1\nr = %2\ns = %3")
            .arg(message).arg(r).arg(s);
    } else {
        steps.append(CipherStep(stepCounter++, QChar(),
            "✗ Подпись НЕВЕРНА!", "Ошибка"));
        result.result = QString("✗ ПОДПИСЬ НЕВЕРНА!\nR = %1\nr = %2").arg(R).arg(r);
    }

    result.steps = steps;
    return result;
}

// ==================== Вычисление порядка кривой (делегирует в CoreCurves) ====================

void GOST34102012Cipher::computeCurveOrder(uint64_t p, uint64_t a, uint64_t b,
                                           uint64_t& curveOrder, uint64_t& subgroupOrder,
                                           uint64_t& cofactor, QString& log) {
    CoreCurves::computeCurveOrder(p, a, b, curveOrder, subgroupOrder, cofactor, log);
}

// ==================== Конструктор ====================

GOST34102012Cipher::GOST34102012Cipher() {
}

// ==================== Регистратор ====================

GOST34102012CipherRegister::GOST34102012CipherRegister() {
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

            QLabel* title = new QLabel("Параметры эллиптической кривой (ГОСТ Р 34.10-2012)");
            title->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(title);

            QGridLayout* grid = new QGridLayout();
            grid->setSpacing(8);

            // p
            QLabel* pLabel = new QLabel("p (модуль):");
            QLineEdit* pEdit = new QLineEdit();
            pEdit->setObjectName("p");
            pEdit->setPlaceholderText("Простое число");
            grid->addWidget(pLabel, 0, 0);
            grid->addWidget(pEdit, 0, 1);

            // a
            QLabel* aLabel = new QLabel("a:");
            QLineEdit* aEdit = new QLineEdit();
            aEdit->setObjectName("a");
            aEdit->setText("7");
            grid->addWidget(aLabel, 0, 2);
            grid->addWidget(aEdit, 0, 3);

            // b
            QLabel* bLabel = new QLabel("b:");
            QLineEdit* bEdit = new QLineEdit();
            bEdit->setObjectName("b");
            grid->addWidget(bLabel, 1, 0);
            grid->addWidget(bEdit, 1, 1);

            // q + кнопка вычисления
            QLabel* qLabel = new QLabel("q (порядок):");
            QLineEdit* qEdit = new QLineEdit();
            qEdit->setObjectName("q");
            qEdit->setReadOnly(true);
            QPushButton* calcQButton = new QPushButton("Вычислить q");
            calcQButton->setObjectName("calcQButton");
            QHBoxLayout* qLayout = new QHBoxLayout();
            qLayout->addWidget(qEdit);
            qLayout->addWidget(calcQButton);
            grid->addWidget(qLabel, 1, 2);
            grid->addLayout(qLayout, 1, 3);

            // xp, yp
            QLabel* xpLabel = new QLabel("xp (G):");
            QLineEdit* xpEdit = new QLineEdit();
            xpEdit->setObjectName("xp");
            grid->addWidget(xpLabel, 2, 0);
            grid->addWidget(xpEdit, 2, 1);

            QLabel* ypLabel = new QLabel("yp (G):");
            QLineEdit* ypEdit = new QLineEdit();
            ypEdit->setObjectName("yp");
            grid->addWidget(ypLabel, 2, 2);
            grid->addWidget(ypEdit, 2, 3);

            mainLayout->addLayout(grid);

            QFrame* line1 = new QFrame();
            line1->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line1);

            QLabel* keyTitle = new QLabel("Ключи пользователя:");
            keyTitle->setStyleSheet("font-weight: bold; color: #2c3e50;");
            mainLayout->addWidget(keyTitle);

            QGridLayout* keyGrid = new QGridLayout();
            keyGrid->setSpacing(8);

            // d
            QLabel* dLabel = new QLabel("d (секретный):");
            QLineEdit* dEdit = new QLineEdit();
            dEdit->setObjectName("d");
            keyGrid->addWidget(dLabel, 0, 0);
            keyGrid->addWidget(dEdit, 0, 1);

            // xq, yq
            QLabel* xqLabel = new QLabel("xq (Q):");
            QLineEdit* xqEdit = new QLineEdit();
            xqEdit->setObjectName("xq");
            keyGrid->addWidget(xqLabel, 0, 2);
            keyGrid->addWidget(xqEdit, 0, 3);

            QLabel* yqLabel = new QLabel("yq (Q):");
            QLineEdit* yqEdit = new QLineEdit();
            yqEdit->setObjectName("yq");
            keyGrid->addWidget(yqLabel, 1, 0);
            keyGrid->addWidget(yqEdit, 1, 1);

            // k
            QLabel* kLabel = new QLabel("k (случайное):");
            QLineEdit* kEdit = new QLineEdit();
            kEdit->setObjectName("k");
            kEdit->setText("5");
            keyGrid->addWidget(kLabel, 2, 0);
            keyGrid->addWidget(kEdit, 2, 1);

            mainLayout->addLayout(keyGrid);

            QFrame* line2 = new QFrame();
            line2->setFrameShape(QFrame::HLine);
            mainLayout->addWidget(line2);

            // Сообщение для проверки
            QLabel* messageTitle = new QLabel("Сообщение для проверки подписи:");
            QTextEdit* messageEdit = new QTextEdit();
            messageEdit->setObjectName("message");
            messageEdit->setMaximumHeight(60);
            mainLayout->addWidget(messageTitle);
            mainLayout->addWidget(messageEdit);

            // Кнопка загрузки примера
            QPushButton* loadExampleButton = new QPushButton("Загрузить контрольный пример");
            loadExampleButton->setObjectName("loadExampleButton");
            mainLayout->addWidget(loadExampleButton);

            layout->addWidget(paramsContainer);

            // Сохраняем указатели
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
            QObject::connect(loadExampleButton, &QPushButton::clicked,
                [pEdit, aEdit, bEdit, qEdit, xpEdit, ypEdit, dEdit, xqEdit, yqEdit, kEdit]() {
                    pEdit->setText("11");
                    aEdit->setText("1");
                    bEdit->setText("1");
                    qEdit->setText("7");
                    xpEdit->setText("6");
                    ypEdit->setText("5");
                    dEdit->setText("5");
                    xqEdit->setText("17");
                    yqEdit->setText("20");
                    kEdit->setText("4");
                    QMessageBox::information(nullptr, "Загружено",
                        "Загружен контрольный пример с малыми числами");
                });

            // Вычисление порядка кривой
            QObject::connect(calcQButton, &QPushButton::clicked,
                [pEdit, aEdit, bEdit, qEdit]() {
                    uint64_t p = pEdit->text().trimmed().toULongLong();
                    uint64_t a = aEdit->text().trimmed().toULongLong();
                    uint64_t b = bEdit->text().trimmed().toULongLong();

                    if (p == 0) {
                        QMessageBox::warning(nullptr, "Ошибка", "Заполните поле p");
                        return;
                    }

                    uint64_t curveOrder, subgroupOrder, cofactor;
                    QString log;
                    GOST34102012Cipher::computeCurveOrder(p, a, b,
                        curveOrder, subgroupOrder, cofactor, log);

                    qEdit->setText(QString::number(subgroupOrder));

                    QMessageBox msgBox;
                    msgBox.setWindowTitle("Порядок кривой");
                    msgBox.setText(QString("#E = %1\nq = %2\nh = %3")
                        .arg(curveOrder).arg(subgroupOrder).arg(cofactor));
                    msgBox.setDetailedText(log);
                    msgBox.setIcon(QMessageBox::Information);
                    msgBox.exec();
                });
        }
    );
}

static GOST34102012CipherRegister gost34102012Register;
