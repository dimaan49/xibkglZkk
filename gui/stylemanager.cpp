#include "stylemanager.h"

// ==================== Вспомогательные функции ====================
namespace {
    QString baseStyle() {
        return R"(
            /* ====== Базовые стили ====== */
            QMainWindow, QDialog {
                background-color: %1;
            }

            QWidget {
                color: %2;
                font-family: 'Segoe UI', 'Roboto', 'Noto Sans', sans-serif;
                font-size: 11px;
            }

            /* ====== Containers ====== */
            QFrame {
                background-color: transparent;
            }

            QFrame#mainFrame, QFrame#contentFrame {
                background-color: %1;
                padding: 6px;
            }

            /* ====== ComboBox ====== */
            QComboBox {
                background-color: %3;
                border: 1px solid %4;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 80px;
                max-width: 200px;
                height: 28px;
                selection-background-color: %5;
            }

            QComboBox::drop-down {
                border: none;
                width: 24px;
            }

            QComboBox::down-arrow {
                image: url(:/icons/down-arrow.svg);
                width: 10px;
                height: 10px;
            }

            QComboBox QAbstractItemView {
                background-color: %3;
                border: 1px solid %4;
                border-radius: 4px;
                padding: 2px;
                selection-background-color: %5;
                min-width: 100px;
                max-height: 200px;
            }

            /* ====== GroupBox ====== */
            QGroupBox {
                font-weight: 600;
                border: 1px solid %4;
                border-radius: 6px;
                margin-top: 8px;
                margin-bottom: 8px;
                padding-top: 6px;
                background-color: %6;
                min-height: 60px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                color: %7;
            }

            /* ====== Text Areas ====== */
            QTextEdit, QPlainTextEdit {
                background-color: %3;
                border: 1px solid %4;
                border-radius: 4px;
                padding: 6px;
                selection-background-color: %5;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 11px;
                min-height: 80px;
                max-height: 400px;
            }

            QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid %5;
            }

            /* ====== Input/Output Areas ====== */
            QTextEdit#inputText, QTextEdit#outputText,
            QPlainTextEdit#inputText, QPlainTextEdit#outputText {
                min-height: 100px;
                max-height: 200px;
            }

            /* ====== Console Area ====== */
            QTextEdit#console, QPlainTextEdit#console {
                background-color: %8;
                border: 1px solid %9;
                border-radius: 4px;
                color: %10;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 10px;
                min-height: 150px;
                max-height: 300px;
                selection-background-color: %11;
                selection-color: white;
            }

            /* ====== Labels ====== */
            QLabel {
                color: %7;
                background-color: transparent;
                font-size: 11px;
            }

            /* ====== Buttons ====== */
            QPushButton {
                border: none;
                border-radius: 4px;
                padding: 4px 12px;
                font-weight: 600;
                font-size: 11px;
                min-height: 28px;
                min-width: 60px;
                max-width: 200px;
            }

            /* ====== SpinBox & LineEdit ====== */
            QSpinBox, QLineEdit {
                background-color: %3;
                border: 1px solid %4;
                border-radius: 3px;
                padding: 4px 6px;
                selection-background-color: %5;
                min-height: 26px;
                max-height: 32px;
                min-width: 60px;
                max-width: 150px;
            }

            QSpinBox:focus, QLineEdit:focus {
                border: 1px solid %5;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: %4;
                border: none;
                border-radius: 2px;
                width: 18px;
            }

            /* ====== ScrollBar ====== */
            QScrollBar:vertical {
                background-color: %3;
                width: 8px;
                border-radius: 4px;
            }

            QScrollBar:horizontal {
                background-color: %3;
                height: 8px;
                border-radius: 4px;
            }

            QScrollBar::handle:vertical {
                background-color: %4;
                border-radius: 4px;
                min-height: 20px;
            }

            QScrollBar::handle:horizontal {
                background-color: %4;
                border-radius: 4px;
                min-width: 20px;
            }

            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {
                background-color: %12;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
                width: 0px;
            }

            /* ====== Status Bar ====== */
            QStatusBar {
                background-color: %3;
                color: %7;
                border-top: 1px solid %4;
                padding: 2px;
                font-size: 10px;
                max-height: 24px;
            }

            /* ====== Menu Bar ====== */
            QMenuBar {
                background-color: %1;
                color: %7;
                border-bottom: 1px solid %4;
                padding: 2px;
                font-size: 11px;
                max-height: 26px;
            }

            QMenuBar::item:selected {
                background-color: %3;
                border-radius: 3px;
            }

            QMenu {
                background-color: %3;
                border: 1px solid %4;
                padding: 3px;
                min-width: 120px;
            }

            QMenu::item {
                padding: 4px 8px;
                font-size: 11px;
            }

            QMenu::item:selected {
                background-color: %5;
                border-radius: 3px;
            }

            /* ====== CheckBox & RadioButton ====== */
            QCheckBox, QRadioButton {
                spacing: 6px;
                color: %7;
                font-size: 11px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
            }

            QCheckBox::indicator:checked {
                background-color: %5;
                border: 2px solid %5;
                border-radius: 2px;
            }

            QRadioButton::indicator:checked {
                border: 2px solid %5;
                border-radius: 7px;
                background-color: %5;
            }

            /* ====== Layout Spacing ====== */
            QVBoxLayout, QHBoxLayout, QGridLayout {
                spacing: 4px;
                margin: 2px;
            }

            /* ====== Progress Bar ====== */
            QProgressBar {
                border: 1px solid %4;
                border-radius: 4px;
                background-color: %3;
                text-align: center;
                color: %7;
                min-height: 16px;
                max-height: 20px;
            }

            QProgressBar::chunk {
                background-color: %5;
                border-radius: 3px;
            }
        )";
    }

    QString buttonStyleDarkPro() {
        return R"(
            /* Primary Buttons - Dark Professional */
            QPushButton#encryptButton,
            QPushButton#decryptButton {
                background-color: #3a7afe;
                color: white;
            }

            QPushButton#encryptButton:hover,
            QPushButton#decryptButton:hover {
                background-color: #4a8afe;
            }

            QPushButton#encryptButton:pressed,
            QPushButton#decryptButton:pressed {
                background-color: #2a6afe;
            }

            /* Secondary Buttons */
            QPushButton#clearButton,
            QPushButton#swapButton {
                background-color: #2d2d2d;
                color: #e0e0e0;
            }

            QPushButton#clearButton:hover,
            QPushButton#swapButton:hover {
                background-color: #3d3d3d;
                color: white;
            }

            QPushButton#clearButton:pressed,
            QPushButton#swapButton:pressed {
                background-color: #252525;
            }

        /* Advanced Settings Button - Теперь в едином стиле с defaultTextButton */
        QPushButton#advancedSettingsButton {
            background-color: rgba(58, 122, 254, 0.1);
            color: #3a7afe;
            border: 1px solid rgba(58, 122, 254, 0.3);
            border-radius: 4px;
            padding: 4px 12px;
            font-weight: 600;
            font-size: 11px;
            min-height: 28px;
            min-width: 120px;
            max-width: 150px;
        }

        QPushButton#advancedSettingsButton:hover {
            background-color: rgba(58, 122, 254, 0.2);
            border-color: #3a7afe;
        }

        QPushButton#advancedSettingsButton:pressed {
            background-color: rgba(58, 122, 254, 0.3);
        }

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#logButton {
                background-color: rgba(231, 76, 60, 0.1);
                color: #e74c3c;
                border: 1px solid rgba(231, 76, 60, 0.3);
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 10px;
                min-height: 22px;
                min-width: 50px;
                max-width: 120px;
            }

            QPushButton#clearInputButton:hover,
            QPushButton#clearOutputButton:hover,
            QPushButton#logButton:hover {
                background-color: rgba(231, 76, 60, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#logButton:pressed {
                background-color: rgba(231, 76, 60, 0.3);
            }

            QPushButton#defaultTextButton {
                background-color: rgba(58, 122, 254, 0.1);
                color: #3a7afe;
                border: 1px solid rgba(58, 122, 254, 0.3);
                min-width: 80px;
                max-width: 150px;
            }

            QPushButton#defaultTextButton:hover {
                background-color: rgba(58, 122, 254, 0.2);
                border-color: #3a7afe;
            }

            QPushButton#defaultTextButton:pressed {
                background-color: rgba(58, 122, 254, 0.3);
            }
        )";
    }

    QString buttonStyleCyberMidnight() {
        return R"(
            /* Primary Buttons - Cyber Midnight */
            QPushButton#encryptButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00c896, stop:1 #00a878);
                color: white;
            }

            QPushButton#encryptButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00d8a6, stop:1 #00b888);
            }

            QPushButton#encryptButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #00b886, stop:1 #009868);
            }

            QPushButton#decryptButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff6400, stop:1 #cc5000);
                color: white;
            }

            QPushButton#decryptButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff7410, stop:1 #d56000);
            }

            QPushButton#decryptButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #e65400, stop:1 #b34400);
            }

            /* Secondary Buttons */
            QPushButton#clearButton {
                background-color: #2a3a4d;
                color: #b4bece;
            }

            QPushButton#clearButton:hover {
                background-color: #334155;
                color: white;
            }

            QPushButton#clearButton:pressed {
                background-color: #1f2b3a;
            }
        /* Advanced Settings Button - В стиле Cyber Midnight */
        QPushButton#advancedSettingsButton {
            background-color: rgba(0, 150, 255, 0.1);
            color: #0096ff;
            border: 1px solid rgba(0, 150, 255, 0.3);
            border-radius: 4px;
            padding: 4px 12px;
            font-weight: 600;
            font-size: 11px;
            min-height: 28px;
            min-width: 120px;
            max-width: 150px;
        }

        QPushButton#advancedSettingsButton:hover {
            background-color: rgba(0, 150, 255, 0.2);
            border-color: #0096ff;
        }

        QPushButton#advancedSettingsButton:pressed {
            background-color: rgba(0, 150, 255, 0.3);
        }

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#logButton {
                background-color: rgba(255, 75, 75, 0.1);
                color: #ff4b4b;
                border: 1px solid rgba(255, 75, 75, 0.3);
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 10px;
                min-height: 22px;
                min-width: 50px;
                max-width: 120px;
            }

            QPushButton#clearInputButton:hover,
            QPushButton#clearOutputButton:hover,
            QPushButton#logButton:hover {
                background-color: rgba(255, 75, 75, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#logButton:pressed {
                background-color: rgba(255, 75, 75, 0.3);
            }

            QPushButton#defaultTextButton {
                background-color: rgba(0, 150, 255, 0.1);
                color: #0096ff;
                border: 1px solid rgba(0, 150, 255, 0.3);
                min-width: 80px;
                max-width: 150px;
            }

            QPushButton#defaultTextButton:hover {
                background-color: rgba(0, 150, 255, 0.2);
                border-color: #0096ff;
            }

            QPushButton#defaultTextButton:pressed {
                background-color: rgba(0, 150, 255, 0.3);
            }
        )";
    }

    QString buttonStyleReliableOrange() {
        return R"(
            /* Primary Buttons - Reliable Orange */
            QPushButton#encryptButton,
            QPushButton#decryptButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #e65c00, stop:1 #b34700);
                color: white;
            }

            QPushButton#encryptButton:hover,
            QPushButton#decryptButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #ff751a, stop:1 #d56000);
            }

            QPushButton#encryptButton:pressed,
            QPushButton#decryptButton:pressed {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1,
                    stop:0 #cc4d00, stop:1 #8c3300);
            }

            /* Secondary Buttons */
            QPushButton#clearButton,
            QPushButton#swapButton {
                background-color: #8a9a5b;
                color: white;
            }

            QPushButton#clearButton:hover,
            QPushButton#swapButton:hover {
                background-color: #9aab6b;
            }

            QPushButton#clearButton:pressed,
            QPushButton#swapButton:pressed {
                background-color: #7a8a4b;
            }

        /* Advanced Settings Button - В стиле Reliable Orange */
        QPushButton#advancedSettingsButton {
            background-color: rgba(230, 92, 0, 0.1);
            color: #e65c00;
            border: 1px solid rgba(230, 92, 0, 0.3);
            border-radius: 4px;
            padding: 4px 12px;
            font-weight: 600;
            font-size: 11px;
            min-height: 28px;
            min-width: 120px;
            max-width: 150px;
        }

        QPushButton#advancedSettingsButton:hover {
            background-color: rgba(230, 92, 0, 0.2);
            border-color: #e65c00;
        }

        QPushButton#advancedSettingsButton:pressed {
            background-color: rgba(230, 92, 0, 0.3);
        }

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#logButton {
                background-color: rgba(168, 66, 50, 0.1);
                color: #a84232;
                border: 1px solid rgba(168, 66, 50, 0.3);
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 10px;
                min-height: 22px;
                min-width: 50px;
                max-width: 120px;
            }

            QPushButton#clearInputButton:hover,
            QPushButton#clearOutputButton:hover,
            QPushButton#logButton:hover {
                background-color: rgba(168, 66, 50, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#logButton:pressed {
                background-color: rgba(168, 66, 50, 0.3);
            }

            QPushButton#defaultTextButton {
                background-color: rgba(230, 92, 0, 0.1);
                color: #e65c00;
                border: 1px solid rgba(230, 92, 0, 0.3);
                min-width: 80px;
                max-width: 150px;
            }

            QPushButton#defaultTextButton:hover {
                background-color: rgba(230, 92, 0, 0.2);
                border-color: #e65c00;
            }

            QPushButton#defaultTextButton:pressed {
                background-color: rgba(230, 92, 0, 0.3);
            }
        )";
    }
}


// ==================== StyleManager Implementation ====================
void StyleManager::applyTheme(QWidget* window, StyleTheme theme) {
    QString stylesheet = getStylesheet(theme);
    window->setStyleSheet(stylesheet);
}

QString StyleManager::getStylesheet(StyleTheme theme) {
    QString base;
    QString buttons;

    switch(theme) {
        case THEME_CYBER_MIDNIGHT:
            base = baseStyle()
                .arg("#0f1923")      // bg_main
                .arg("#f0f5ff")      // text
                .arg("#232f3f")      // bg_widget
                .arg("#2a3a4d")      // border
                .arg("#0096ff")      // accent
                .arg("rgba(40, 50, 60, 0.6)") // groupbox_bg
                .arg("#b4bece")      // muted_text
                .arg("#0a0704")      // console_bg
                .arg("#1a140d")      // console_border
                .arg("#d4a017")      // console_text
                .arg("#e65c00")      // console_selection
                .arg("#334155");     // scrollbar_hover

            buttons = buttonStyleCyberMidnight();
            break;

        case THEME_DARK_PROFESSIONAL:
            base = baseStyle()
                .arg("#121212")      // bg_main
                .arg("#e0e0e0")      // text
                .arg("#1e1e1e")      // bg_widget
                .arg("#2a2a2a")      // border
                .arg("#3a7afe")      // accent
                .arg("#1e1e1e")      // groupbox_bg
                .arg("#a0a0a0")      // muted_text
                .arg("#0a0f15")      // console_bg
                .arg("#1a232f")      // console_border
                .arg("#64d8cb")      // console_text
                .arg("#0096ff")      // console_selection
                .arg("#4d4d4d");     // scrollbar_hover

            buttons = buttonStyleDarkPro();
            break;

        case THEME_RELIABLE_ORANGE:
            base = baseStyle()
                .arg("#0c0905")      // bg_main
                .arg("#f0e6d8")      // text
                .arg("#1a140d")      // bg_widget
                .arg("#2a2319")      // border
                .arg("#e65c00")      // accent
                .arg("#1a140d")      // groupbox_bg
                .arg("#b8a992")      // muted_text
                .arg("#0a0704")      // console_bg
                .arg("#1a140d")      // console_border
                .arg("#d4a017")      // console_text
                .arg("#e65c00")      // console_selection
                .arg("#4d4233");     // scrollbar_hover

            buttons = buttonStyleReliableOrange();
            break;
    }

    // Общие стили для меток статуса
    QString statusLabels;
    switch(theme) {
        case THEME_CYBER_MIDNIGHT:
            statusLabels = R"(
                QLabel[status="info"] {
                    color: #64d8cb;
                    background-color: rgba(100, 216, 203, 0.1);
                    border: 1px solid rgba(100, 216, 203, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="success"] {
                    color: #00c896;
                    background-color: rgba(0, 200, 150, 0.1);
                    border: 1px solid rgba(0, 200, 150, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="warning"] {
                    color: #ff6400;
                    background-color: rgba(255, 100, 0, 0.1);
                    border: 1px solid rgba(255, 100, 0, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="error"] {
                    color: #ff4b4b;
                    background-color: rgba(255, 75, 75, 0.1);
                    border: 1px solid rgba(255, 75, 75, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }
            )";
            break;

        case THEME_DARK_PROFESSIONAL:
            statusLabels = R"(
                QLabel[status="info"] {
                    color: #e0e0e0;
                    background-color: rgba(58, 122, 254, 0.1);
                    border: 1px solid rgba(58, 122, 254, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="success"] {
                    color: #2ecc71;
                    background-color: rgba(46, 204, 113, 0.1);
                    border: 1px solid rgba(46, 204, 113, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="warning"] {
                    color: #f39c12;
                    background-color: rgba(243, 156, 18, 0.1);
                    border: 1px solid rgba(243, 156, 18, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="error"] {
                    color: #e74c3c;
                    background-color: rgba(231, 76, 60, 0.1);
                    border: 1px solid rgba(231, 76, 60, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }
            )";
            break;

        case THEME_RELIABLE_ORANGE:
            statusLabels = R"(
                QLabel[status="info"] {
                    color: #8a9a5b;
                    background-color: rgba(138, 154, 91, 0.1);
                    border: 1px solid rgba(138, 154, 91, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="success"] {
                    color: #d4a017;
                    background-color: rgba(212, 160, 23, 0.1);
                    border: 1px solid rgba(212, 160, 23, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="warning"] {
                    color: #e65c00;
                    background-color: rgba(230, 92, 0, 0.1);
                    border: 1px solid rgba(230, 92, 0, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }

                QLabel[status="error"] {
                    color: #a84232;
                    background-color: rgba(168, 66, 50, 0.1);
                    border: 1px solid rgba(168, 66, 50, 0.3);
                    border-radius: 3px;
                    padding: 4px 6px;
                }
            )";
            break;
    }


    return base + buttons + statusLabels;
}

QString StyleManager::getLogWindowStylesheet() {
    return R"(
        /* ====== Log Window Specific Styles ====== */
        QDialog#LogWindow {
            background-color: #1a1a1a;
            color: #e0e0e0;
        }

        /* Заголовок окна журнала */
        QDialog#LogWindow QLabel {
            font-size: 16px;
            font-weight: bold;
            color: #ffffff;
            padding: 10px;
            background-color: #2a2a2a;
            border-radius: 6px;
            margin-bottom: 8px;
        }

        /* Текстовое поле журнала */
        QDialog#LogWindow QTextEdit {
            background-color: #0a0a0a;
            color: #d4d4d4;
            border: 1px solid #333333;
            border-radius: 4px;
            font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
            font-size: 11px;
            selection-background-color: #3a7afe;
            selection-color: white;
            padding: 8px;
        }

        QDialog#LogWindow QTextEdit:focus {
            border: 1px solid #3a7afe;
        }

        /* Кнопки окна журнала */
        QDialog#LogWindow QPushButton {
            border-radius: 4px;
            padding: 6px 12px;
            font-weight: 600;
            font-size: 11px;
            min-height: 30px;
            min-width: 80px;
            max-width: 120px;
            border: none;
        }

        /* Специфичные кнопки для LogWindow */
        QDialog#LogWindow QPushButton#clearButton {
            background-color: #333333;
            color: #e0e0e0;
        }

        QDialog#LogWindow QPushButton#clearButton:hover {
            background-color: #404040;
            color: white;
        }

        QDialog#LogWindow QPushButton#clearButton:pressed {
            background-color: #262626;
        }

        QDialog#LogWindow QPushButton#saveButton {
            background-color: #2a5699;
            color: white;
        }

        QDialog#LogWindow QPushButton#saveButton:hover {
            background-color: #3066b3;
        }

        QDialog#LogWindow QPushButton#saveButton:pressed {
            background-color: #1f4580;
        }

        QDialog#LogWindow QPushButton#closeButton {
            background-color: #5a5a5a;
            color: white;
        }

        QDialog#LogWindow QPushButton#closeButton:hover {
            background-color: #6a6a6a;
        }

        QDialog#LogWindow QPushButton#closeButton:pressed {
            background-color: #4a4a4a;
        }

        /* Скроллбар в текстовом поле журнала */
        QDialog#LogWindow QScrollBar:vertical {
            background-color: #2a2a2a;
            width: 10px;
            border-radius: 5px;
        }

        QDialog#LogWindow QScrollBar::handle:vertical {
            background-color: #5a5a5a;
            border-radius: 5px;
            min-height: 30px;
        }

        QDialog#LogWindow QScrollBar::handle:vertical:hover {
            background-color: #6a6a6a;
        }

        QDialog#LogWindow QScrollBar::add-line:vertical,
        QDialog#LogWindow QScrollBar::sub-line:vertical {
            height: 0px;
        }

        /* Layout в LogWindow */
        QDialog#LogWindow QVBoxLayout,
        QDialog#LogWindow QHBoxLayout {
            spacing: 8px;
            margin: 6px;
        }
    )";
}
