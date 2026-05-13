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
