#include "logger.h"

Logger& Logger::instance() {
    static Logger instance;
    return instance;
}

void Logger::setConsoleWidget(QTextEdit *widget) {
    consoleWidget = widget;
    if (consoleWidget) {
        connect(this, &Logger::newMessage,
                consoleWidget, &QTextEdit::append);
    }
}

void Logger::log(const QString& message) {
    // 1. Вывод в системную консоль (терминал)
    std::cout << message.toStdString() << std::endl;

    // 2. Вывод в GUI консоль (если есть виджет)
    if (consoleWidget) {
        consoleWidget->append(message);
    } else {
        // Если виджет еще не установлен, сохраняем в буфер
        emit newMessage(message);
    }
}

void Logger::clear() {
    if (consoleWidget) {
        consoleWidget->clear();
    }
}
