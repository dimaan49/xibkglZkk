#include "logwindow.h"
#include <QFileDialog>
#include <QMessageBox>
#include <QDateTime>

LogWindow::LogWindow(QWidget *parent)
    : QDialog(parent)
{
    setObjectName("LogWindow");
    setWindowTitle("Детальный журнал операций");
    setMinimumSize(800, 600);

    QVBoxLayout *mainLayout = new QVBoxLayout(this);

    // Заголовок
    QLabel *titleLabel = new QLabel("📋 Детальный журнал операций");
    titleLabel->setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;");
    mainLayout->addWidget(titleLabel);

    // Текстовое поле
    textEdit = new QTextEdit();
    textEdit->setReadOnly(true);
    textEdit->setFont(QFont("Courier New", 10));
    textEdit->setLineWrapMode(QTextEdit::NoWrap);
    mainLayout->addWidget(textEdit);

    // Панель кнопок
    QHBoxLayout *buttonLayout = new QHBoxLayout();

    clearButton = new QPushButton("🗑️ Очистить");
    saveButton = new QPushButton("💾 Сохранить");
    closeButton = new QPushButton("✖ Закрыть");

    buttonLayout->addWidget(clearButton);
    buttonLayout->addWidget(saveButton);
    buttonLayout->addStretch();
    buttonLayout->addWidget(closeButton);

    mainLayout->addLayout(buttonLayout);

    // Подключение сигналов
    connect(clearButton, &QPushButton::clicked, this, &LogWindow::onClearClicked);
    connect(saveButton, &QPushButton::clicked, this, &LogWindow::onSaveClicked);
    connect(closeButton, &QPushButton::clicked, this, &QDialog::accept);
}

void LogWindow::setLogContent(const QString &content)
{
    textEdit->setText(content);
    // Автоскролл в конец
    QTextCursor cursor = textEdit->textCursor();
    cursor.movePosition(QTextCursor::End);
    textEdit->setTextCursor(cursor);
}

void LogWindow::appendLog(const QString &text)
{
    textEdit->append(text);
    // Автоскролл в конец
    QTextCursor cursor = textEdit->textCursor();
    cursor.movePosition(QTextCursor::End);
    textEdit->setTextCursor(cursor);
}

void LogWindow::onClearClicked()
{
    textEdit->clear();
}

void LogWindow::onSaveClicked()
{
    QString fileName = QFileDialog::getSaveFileName(this,
        "Сохранить журнал операций",
        QString("cryptoguard_log_%1.txt").arg(QDateTime::currentDateTime().toString("yyyyMMdd_hhmmss")),
        "Текстовые файлы (*.txt);;Все файлы (*)");

    if (!fileName.isEmpty()) {
        QFile file(fileName);
        if (file.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream stream(&file);
            stream << textEdit->toPlainText();
            file.close();
            QMessageBox::information(this, "Успех", "Журнал успешно сохранен!");
        } else {
            QMessageBox::warning(this, "Ошибка", "Не удалось сохранить файл!");
        }
    }
}
