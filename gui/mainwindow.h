#ifndef MAINWINDOW_H
#define MAINWINDOW_H
#include "cipherinterface.h"
#include <categoryfilterdialog.h>
#include "texttransformer.h"
#include "logwindow.h"
#include "analysiswindow.h"
#include "librarywindow.h"
#include "popupcombobox.h"


#include <QMainWindow>
#include <memory>
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
#include <QRadioButton>
#include <QHBoxLayout>
#include <QPlainTextEdit>
#include <QTimer>


class CategoryFilterDialog;
class RouteCipherAdvancedWidget;

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void onCipherChanged(int index);
    void onThemeChanged();
    void onEncryptClicked();
    void onDecryptClicked();
    void onClearClicked();
    void onClearInputClicked();
    void onClearOutputClicked();
    void onClearLogClicked();
    void onSwapClicked();
    void onDefaultTextClicked();
    void onShowLogClicked();
    void onAdvancedSettingsClicked();
    void onFilterButtonClicked();      // Добавить
    void onInputTextChanged();
    void onAnalysisWindowOpen();
    void onLibraryWindowOpen();
    void updateOutputFormatVisibility();
    void onTransformToggled(bool checked);
    void onActionsSelected(int index);

private:
    void setupUI();
    void setupCiphers();
    void setupThemeSelector();
    void clearParameters();
    void logToConsole(const QString& message);
    void setStatusText(const QString& text, const QString& type = "info");
    void flashWindow(const QColor& color, int duration);
    void handleError(const QString& errorMessage);
    void handleSuccess(const QString& successMessage);
    void showSuccessAnimation();
    void showErrorAnimation();
    void updateAdvancedSettingsButton();
    void createCipherWidgets(int cipherId);
    QVariantMap collectParameters() const;
    void applyFilter();                // Добавить

    // UI Elements
    PopupComboBox* m_cipherComboBox;
    PopupComboBox* themeComboBox;
    QTextEdit* inputTextEdit;
    QTextEdit* outputTextEdit;
    QTextEdit* debugConsole;
    QPushButton* encryptButton;
    QPushButton* decryptButton;
    QPushButton* clearButton;
    QRadioButton* m_outputFormatRusRadio;
    QRadioButton* m_outputFormatHexRadio;
    QPushButton* clearInputButton;
    QPushButton* clearOutputButton;
    QPushButton* clearLogButton;
    QPushButton* showLogButton;
    QLabel* statusLabel;
    QGroupBox* parametersGroup;
    QVBoxLayout* parametersLayout;
    QPushButton* m_advancedSettingsButton;
    QPushButton* m_filterButton;           // Добавить
    AnalysisWindow* m_analysisWindow;
    LibraryWindow* m_libraryWindow;
    QMenuBar* m_menuBar;
    PopupComboBox* m_actionsComboBox;
    QString m_originalInputText;      // всегда оригинал (со знаками)
    QCheckBox* m_transformCheckBox;

    // Filter dialog
    CategoryFilterDialog* m_filterDialog;   // Добавить
    QList<CipherCategory> m_activeCategories; // Добавить - храним выбранные категории

    LogWindow* logWindow;

    // Cipher related
    std::unique_ptr<CipherInterface> m_currentCipher;
    int m_currentCipherId = -1;
    QString m_currentPreviewText;
    QString m_alphabet;

    // Parameters storage
    QMap<QString, QWidget*> m_paramWidgets;
    QMap<QString, QVariantMap> m_cipherAdvancedSettings;

    QTimer* m_statusResetTimer;
};

#endif // MAINWINDOW_H
