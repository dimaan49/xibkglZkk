#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <memory>
#include "cipherinterface.h"
#include "logwindow.h"
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QGroupBox>
#include <QComboBox>
#include <QTextEdit>
#include <QPushButton>
#include <QLabel>
#include <QMessageBox>
#include <QDebug>
#include <QSpinBox>
#include <QLineEdit>
#include <QPropertyAnimation>
#include <QGraphicsDropShadowEffect>
#include <QSequentialAnimationGroup>
#include <QParallelAnimationGroup>
#include <QPlainTextEdit>


class AnimatedButton : public QPushButton {
    Q_OBJECT
    Q_PROPERTY(int borderRadius READ borderRadius WRITE setBorderRadius)

public:
    explicit AnimatedButton(const QString& text, QWidget* parent = nullptr);
    ~AnimatedButton() override;

    int borderRadius() const { return m_borderRadius; }
    void setBorderRadius(int radius);

protected:
    void enterEvent(QEnterEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    int m_borderRadius = 6;
    QPropertyAnimation* m_hoverAnimation;
};

// Основной класс MainWindow
class MainWindow : public QMainWindow {
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onThemeChanged();
    void onClearInputClicked();
    void onClearOutputClicked();
    void onClearLogClicked();
    void onSwapClicked();
    void onDefaultTextClicked();
    void onShowLogClicked();

private:
    // UI элементы
    //clear
    QPushButton *clearInputButton;
    QPushButton *clearOutputButton;
    QPushButton *clearLogButton;
    //
    QComboBox *cipherComboBox;
    QComboBox *themeComboBox;  // Для выбора темы
    QTextEdit *inputTextEdit;
    QTextEdit *outputTextEdit;
    QTextEdit *debugConsole;
    AnimatedButton *encryptButton;
    AnimatedButton *decryptButton;
    AnimatedButton *clearButton;
    QLabel *statusLabel;
    QGroupBox *parametersGroup;
    QVBoxLayout *parametersLayout;

    //log
    LogWindow *logWindow;
    QPushButton *showLogButton;

    // Текущий шифр
    std::unique_ptr<CipherInterface> m_currentCipher;

    // Хранилище виджетов параметров
    QMap<QString, QWidget*> m_paramWidgets;

    void onCipherChanged(int index);
    void onEncryptClicked();
    void onDecryptClicked();
    void onClearClicked();
    void setupUI();
    void setupCiphers();
    void setupThemeSelector();
    void clearParameters();
    void createCipherWidgets(const QString& cipherId);
    QVariantMap collectParameters() const;
    void logToConsole(const QString& message);

    // Анимации
    void showSuccessAnimation();
    void showErrorAnimation();
};

#endif // MAINWINDOW_H
