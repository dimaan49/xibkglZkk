#ifndef LOGWINDOW_H
#define LOGWINDOW_H

#include <QDialog>
#include <QTextEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>

class LogWindow : public QDialog
{
    Q_OBJECT

public:
    explicit LogWindow(QWidget *parent = nullptr);
    void setLogContent(const QString &content);
    void appendLog(const QString &text);

private slots:
    void onClearClicked();
    void onSaveClicked();

private:
    QTextEdit *textEdit;
    QPushButton *clearButton;
    QPushButton *saveButton;
    QPushButton *closeButton;
};

#endif // LOGWINDOW_H
