// main.cpp - отдельный файл
#include <QApplication>
#include <iostream>
#include "mainwindow.h"
#include "atbash.h"
#include "formatter.h"

// Функция для консольных тестов
void runConsoleTests() {
#ifdef _WIN32
    system("chcp 65001 > nul");
#endif

    std::cout << "=== КОНСОЛЬНЫЙ РЕЖИМ ===" << std::endl;
    std::cout << "Для запуска GUI используйте: cryptoApp --gui" << std::endl;
    std::cout << std::endl;

    // Простой тест Atbash
    AtbashCipher cipher;

    std::cout << "Быстрый тест Atbash:" << std::endl;
    std::cout << "====================" << std::endl;

    QString testText = "ПРИВЕТМИР";
    CipherResult result = cipher.encrypt(testText);

    std::cout << "Вход:  " << testText.toUtf8().constData() << std::endl;
    std::cout << "Выход: " << result.result.toUtf8().constData() << std::endl;

    // Используем ваш formatter
    QString formatted = StepFormatter::formatResultOnly(result, 5);
    std::cout << "Форматированный: " << formatted.toUtf8().constData() << std::endl;

    std::cout << std::endl << "=== ТЕСТ ЗАВЕРШЕН ===" << std::endl;
}

int main(int argc, char *argv[]) {
    // Проверяем аргументы командной строки
    bool guiMode = false;

    if (argc > 1) {
        QString arg = QString(argv[1]).toLower();
        if (arg == "--gui" || arg == "-g" || arg == "/gui") {
            guiMode = true;
        }
    }

    if (!guiMode) {
        // Консольный режим
        runConsoleTests();
        return 0;
    }

    // GUI режим
    QApplication app(argc, argv);
    app.setStyle("Fusion");

    MainWindow window;
    window.show();

    return app.exec();
}
