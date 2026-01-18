#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QMap>
#include <QString>
#include <functional>
#include "ciphercore.h"

class QComboBox;
class QTextEdit;
class QPushButton;
class QLabel;
class QGroupBox;
class QVBoxLayout;
class QSpinBox;
class QLineEdit;

class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onCipherChanged();
    void onEncryptClicked();
    void onDecryptClicked();
    void onClearClicked();

private:
    void setupUI();
    void setupCiphers();
    void logToConsole(const QString& message);

    // UI элементы
    QComboBox* cipherComboBox;
    QTextEdit* inputTextEdit;
    QTextEdit* outputTextEdit;
    QTextEdit* debugConsole;
    QPushButton* encryptButton;
    QPushButton* decryptButton;
    QPushButton* clearButton;
    QLabel* statusLabel;

    // Динамическая панель параметров
    QGroupBox* parametersGroup;
    QVBoxLayout* parametersLayout;

    // Элементы управления параметрами
    QSpinBox* shiftSpinBox;
    QLineEdit* keyLineEdit;
    QLineEdit* startCharLineEdit;

    // Карты для шифрования/дешифрования
    QMap<QString, std::function<CipherResult(const QString&)>> encryptors;
    QMap<QString, std::function<CipherResult(const QString&)>> decryptors;

    // Вспомогательные функции
    void clearParameters();
    void setupAtbashParameters();
    void setupCaesarParameters();
    void setupVigenereParameters();
    void setupTrithemiusParameters();
    void setupBelazoParameters();
    void setupMatrixParameters();
    void setupRouteParameters();
    void setupCardanoParameters();

    // Получение параметров
    int getCaesarShift() const;
    QString getVigenereKey() const;
    QChar getVigenereStartChar() const;
};

#endif // MAINWINDOW_H
