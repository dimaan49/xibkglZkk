#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <memory>
#include "cipherinterface.h"


class QComboBox;
class QTextEdit;
class QPushButton;
class QGroupBox;
class QVBoxLayout;
class QLabel;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onCipherChanged(int index);
    void onEncryptClicked();
    void onDecryptClicked();
    void onClearClicked();

private:
    void setupUI();
    void setupCiphers();
    void clearParameters();
    void logToConsole(const QString& message);
    void createCipherWidgets(const QString& cipherId);
    QVariantMap collectParameters() const;

    // Хранилище виджетов параметров
    QMap<QString, QWidget*> m_paramWidgets;
    QMap<QString, CipherParameter> m_currentParams;

    // UI элементы
    QComboBox *cipherComboBox;
    QTextEdit *inputTextEdit;
    QTextEdit *outputTextEdit;
    QTextEdit *debugConsole;
    QPushButton *encryptButton;
    QPushButton *decryptButton;
    QPushButton *clearButton;
    QLabel *statusLabel;
    QGroupBox *parametersGroup;
    QVBoxLayout *parametersLayout;

    // Текущий шифр
    std::unique_ptr<CipherInterface> m_currentCipher;
};

#endif // MAINWINDOW_H
