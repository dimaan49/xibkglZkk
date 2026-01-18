#ifndef LOGGER_H
#define LOGGER_H

#include <QObject>
#include <QString>
#include <QTextEdit>
#include <iostream>

class Logger : public QObject {
    Q_OBJECT

public:
    static Logger& instance();

    void setConsoleWidget(QTextEdit *widget);
    void log(const QString& message);
    void clear();

signals:
    void newMessage(const QString& message);

private:
    Logger() = default;
    QTextEdit *consoleWidget = nullptr;
};

// Макрос для удобного логирования
#define LOG(msg) Logger::instance().log(msg)

#endif // LOGGER_H
