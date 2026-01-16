#include <QCoreApplication>
#include <iostream>
#include "atbash.h"
#include "caesar.h"
#include "trithemius.h"
#include "belazo.h"
#include "vigenere_auto.h"
#include "vigenere_ciphertext.h"
#include "cardano.h"
#include "routecipher.h"
#include "columnarcipher.h"
#include "matrixcipher.h"
#include "formatter.h"

int main(int argc, char *argv[]) {
    QCoreApplication app(argc, argv);

#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    QString testPhrase = QStringLiteral(u"ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК");

    std::cout << "Тестовая фраза: \"" << testPhrase.toUtf8().constData() << "\"\n\n";

    // АТБАШ
    AtbashCipher atbash;
    CipherResult atbashResult = atbash.encrypt(testPhrase);
    std::cout << StepFormatter::formatResultOnly(atbashResult, 5).toUtf8().constData() << "\n\n";

    // ШИФР ЦЕЗАРЯ
    CaesarCipher caesar;
    CipherResult caesarResult = caesar.encrypt(testPhrase, 17);
    std::cout << StepFormatter::formatResultOnly(caesarResult, 5).toUtf8().constData() << "\n\n";

    // ТРИТЕМИЯ
    TrithemiusCipher trithemius;
    CipherResult trithemiusResult = trithemius.encrypt(testPhrase, 0, 1);
    std::cout << StepFormatter::formatResultOnly(trithemiusResult, 5).toUtf8().constData() << "\n\n";

    // БЕЛАЗО
    BelazoCipher belazo;
    CipherResult belazoResult = belazo.encrypt(testPhrase, QStringLiteral(u"ЗОНД"));
    std::cout << StepFormatter::formatResultOnly(belazoResult, 5).toUtf8().constData() << "\n\n";

    // ВИЖЕНЕР С САМОКЛЮЧОМ (пример из задания)
    VigenereAutoCipher vigenereAuto;
    CipherResult vigenereAutoResult = vigenereAuto.encrypt(QStringLiteral(u"ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК"), QChar(u'Ю'));
    std::cout << StepFormatter::formatResultOnly(vigenereAutoResult, 5).toUtf8().constData() << "\n\n";


    // ВИЖЕНЕР С КЛЮЧОМ-ШИФРОТЕКСТОМ
    VigenereCiphertextCipher vigenereCiphertext;
    CipherResult vigenereCiphertextResult = vigenereCiphertext.encrypt(testPhrase, QChar(u'Ю'));
    std::cout << StepFormatter::formatResultOnly(vigenereCiphertextResult, 5).toUtf8().constData() << "\n\n";

    std::vector<std::vector<bool>> holePattern = {
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {1,0,0,0,1,0,1,1,0,0},  // 1000101100
        {0,1,0,0,0,1,0,0,0,1},  // 0100010001
        {0,0,0,1,0,0,0,1,0,0},  // 0001000100
        {0,1,0,0,0,0,0,0,0,0},  // 0100000000
        {0,0,1,0,0,1,1,0,0,1}   // 0010011001
    };

    CardanoCipher cardano(holePattern);

    // Тестовый текст
    QString testText = QStringLiteral(u"ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК");

    CipherResult cardanoResult = cardano.encrypt(testText);
    std::cout << StepFormatter::formatResult(cardanoResult, true, 10, QString("\n")).toUtf8().constData() << "\n";

    // Дешифрование для проверки
    CipherResult decryptedResult = cardano.decrypt(cardanoResult.result);
    std::cout << "Дешифровано: " << decryptedResult.result.toUtf8().constData() << "\n";

    // Пример 1: RouteCipher с параметрами (старый интерфейс)
    RouteCipher route1;
    QVector<Direction> writeDirs1 = {LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT,
                                    LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT};
    QVector<Direction> readDirs1 = {TOP_TO_BOTTOM, TOP_TO_BOTTOM, TOP_TO_BOTTOM,
                                   TOP_TO_BOTTOM, TOP_TO_BOTTOM, TOP_TO_BOTTOM};

    CipherResult result1 = route1.encrypt(
        QStringLiteral(u"ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК"),
        writeDirs1,
        readDirs1,
        10, 6
    );
    std::cout << StepFormatter::formatResult(result1, true, 10, QString(" ")).toUtf8().constData() << "\n";


    // Пример 2: RouteCipher с конфигурацией (новый интерфейс)
    RouteCipher route2;
    RouteCipherConfig config2 = RouteCipherConfig::createSnake(10, 6, TOP_TO_BOTTOM);
    CipherResult result2 = route2.encrypt(
        QStringLiteral(u"ПРИМЕРМАРШРУТНОЙПЕРЕСТАНОВКИ"),
        config2
    );

    // Пример 3: Змейка при записи и чтении
    ColumnarCipher cipherCOL;
    std::cout << "\n=== Пример 3: Вертикальная перестановка с змейкой в обе стороны ===\n";
    QVector<Direction> writeDirs3 = {LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT, LEFT_TO_RIGHT,
                                    RIGHT_TO_LEFT,  RIGHT_TO_LEFT,  RIGHT_TO_LEFT,  RIGHT_TO_LEFT,  RIGHT_TO_LEFT,  RIGHT_TO_LEFT};
    QVector<Direction> readDirs3 = {};
    CipherResult result3 = cipherCOL.encrypt(
        QStringLiteral(u"ОДИН ДУРАК МОЖЕТ БОЛЬШЕ СПРАШИВАТЬ ЗПТ ЧЕМ ДЕСЯТЬ УМНЫХ ОТВЕТИТЬ ТЧК"),
        QStringLiteral(u"СТРУНА"),
        writeDirs3,  // Змейка по строкам
        QVector<Direction>(),   // Змейка по столбцам
        10, 6
    );
    std::cout << StepFormatter::formatResult(result3, true, 10).toUtf8().constData() << "\n";


        return 0;
    }
