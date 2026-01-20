#include "stylemanager.h"
// ==================== StyleManager Implementation ====================
void StyleManager::applyTheme(QWidget* window, StyleTheme theme) {
    QString stylesheet = getStylesheet(theme);
    window->setStyleSheet(stylesheet);
}

QString StyleManager::getStylesheet(StyleTheme theme) {
    switch(theme) {
        case THEME_CYBER_MIDNIGHT:
        return R"(
            /* ====== Cyber Midnight Theme ====== */
            QMainWindow, QDialog {
                background-color: #0f1923;
            }

            QWidget {
                color: #f0f5ff;
                font-family: 'Segoe UI', 'Roboto', 'Noto Sans', sans-serif;
                font-size: 11px;
            }

            /* ====== Containers ====== */
            QFrame {
                background-color: transparent;
            }

            QFrame#mainFrame, QFrame#contentFrame {
                background-color: #0f1923;
                padding: 6px;
            }

            /* ====== ComboBox ====== */
            QComboBox {
                background-color: #232f3f;
                border: 1px solid #2a3a4d;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 80px;
                max-width: 200px;
                height: 28px;
                selection-background-color: #0096ff;
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
                background-color: #232f3f;
                border: 1px solid #2a3a4d;
                border-radius: 4px;
                padding: 2px;
                selection-background-color: #0096ff;
                min-width: 100px;
                max-height: 200px;
            }

            /* ====== GroupBox ====== */
            QGroupBox {
                font-weight: 600;
                border: 1px solid #2a3a4d;
                border-radius: 6px;
                margin-top: 8px;
                margin-bottom: 8px;
                padding-top: 6px;
                background-color: rgba(40, 50, 60, 0.6);
                min-height: 60px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                color: #b4bece;
            }

            /* ====== Text Areas ====== */
            QTextEdit, QPlainTextEdit {
                background-color: #1a232f;
                border: 1px solid #2a3a4d;
                border-radius: 4px;
                padding: 6px;
                selection-background-color: #0096ff;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 11px;
                min-height: 80px;
                max-height: 400px;
            }

            QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #0096ff;
            }

            /* ====== Input/Output Areas (меньше) ====== */
            QTextEdit#inputText, QTextEdit#outputText,
            QPlainTextEdit#inputText, QPlainTextEdit#outputText {
                min-height: 100px;
                max-height: 200px;
            }

            /* ====== Console/ Area (БОЛЬШЕ) ====== */
            QTextEdit#console, QPlainTextEdit#console,
            QTextEdit#logText, QPlainTextEdit#logText {
                background-color: #0a0f15;
                border: 1px solid #1a232f;
                border-radius: 4px;
                color: #64d8cb;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 10px;
                min-height: 200px;
                max-height: 600px;
            }

            /* ====== Labels ====== */
            QLabel {
                color: #b4bece;
                background-color: transparent;
                font-size: 11px;
            }

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

            /* Primary Buttons */
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

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#clearLogButton {
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
            QPushButton#clearLogButton:hover {
                background-color: rgba(255, 75, 75, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#clearLogButton:pressed {
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

            /* ====== SpinBox & LineEdit ====== */
            QSpinBox, QLineEdit {
                background-color: #1a232f;
                border: 1px solid #2a3a4d;
                border-radius: 3px;
                padding: 4px 6px;
                selection-background-color: #0096ff;
                min-height: 26px;
                max-height: 32px;
                min-width: 60px;
                max-width: 150px;
            }

            QSpinBox:focus, QLineEdit:focus {
                border: 1px solid #0096ff;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #2a3a4d;
                border: none;
                border-radius: 2px;
                width: 18px;
            }

            /* ====== ScrollBar ====== */
            QScrollBar:vertical {
                background-color: #1a232f;
                width: 8px;
                border-radius: 4px;
            }

            QScrollBar:horizontal {
                background-color: #1a232f;
                height: 8px;
                border-radius: 4px;
            }

            QScrollBar::handle:vertical {
                background-color: #2a3a4d;
                border-radius: 4px;
                min-height: 20px;
            }

            QScrollBar::handle:horizontal {
                background-color: #2a3a4d;
                border-radius: 4px;
                min-width: 20px;
            }

            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {
                background-color: #334155;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
                width: 0px;
            }

            /* ====== Status Bar ====== */
            QStatusBar {
                background-color: #1a232f;
                color: #b4bece;
                border-top: 1px solid #2a3a4d;
                padding: 2px;
                font-size: 10px;
                max-height: 24px;
            }

            /* ====== Menu Bar ====== */
            QMenuBar {
                background-color: #0f1923;
                color: #b4bece;
                border-bottom: 1px solid #2a3a4d;
                padding: 2px;
                font-size: 11px;
                max-height: 26px;
            }

            QMenuBar::item:selected {
                background-color: #232f3f;
                border-radius: 3px;
            }

            QMenu {
                background-color: #1a232f;
                border: 1px solid #2a3a4d;
                padding: 3px;
                min-width: 120px;
            }

            QMenu::item {
                padding: 4px 8px;
                font-size: 11px;
            }

            QMenu::item:selected {
                background-color: #0096ff;
                border-radius: 3px;
            }

            /* ====== CheckBox & RadioButton ====== */
            QCheckBox, QRadioButton {
                spacing: 6px;
                color: #b4bece;
                font-size: 11px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
            }

            QCheckBox::indicator:checked {
                background-color: #0096ff;
                border: 2px solid #0096ff;
                border-radius: 2px;
            }

            QRadioButton::indicator:checked {
                border: 2px solid #0096ff;
                border-radius: 7px;
                background-color: #0096ff;
            }

            /* ====== Layout Spacing ====== */
            QVBoxLayout, QHBoxLayout, QGridLayout {
                spacing: 4px;
                margin: 2px;
            }

            /* ====== Progress Bar ====== */
            QProgressBar {
                border: 1px solid #2a3a4d;
                border-radius: 4px;
                background-color: #1a232f;
                text-align: center;
                color: #b4bece;
                min-height: 16px;
                max-height: 20px;
            }

            QProgressBar::chunk {
                background-color: #0096ff;
                border-radius: 3px;
            }
        )";

        case THEME_DARK_PROFESSIONAL:
        return R"(
            /* ====== Dark Professional Theme ====== */
            QMainWindow, QDialog {
                background-color: #121212;
            }

            QWidget {
                color: #e0e0e0;
                font-family: 'Segoe UI', 'Roboto', sans-serif;
                font-size: 11px;
            }

            /* ====== Containers ====== */
            QFrame {
                background-color: transparent;
            }

            QFrame#mainFrame, QFrame#contentFrame {
                background-color: #121212;
                padding: 6px;
            }

            /* ====== ComboBox ====== */
            QComboBox {
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 80px;
                max-width: 200px;
                height: 28px;
                selection-background-color: #3a7afe;
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
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                padding: 2px;
                selection-background-color: #3a7afe;
                min-width: 100px;
                max-height: 200px;
            }

            /* ====== GroupBox ====== */
            QGroupBox {
                font-weight: 600;
                border: 1px solid #2a2a2a;
                border-radius: 6px;
                margin-top: 8px;
                margin-bottom: 8px;
                padding-top: 6px;
                background-color: #1e1e1e;
                min-height: 60px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                color: #a0a0a0;
            }

            /* ====== Text Areas ====== */
            QTextEdit, QPlainTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                padding: 6px;
                selection-background-color: #3a7afe;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 11px;
                min-height: 80px;
                max-height: 400px;
            }

            QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #3a7afe;
            }

            /* ====== Input/Output Areas (меньше) ====== */
            QTextEdit#inputText, QTextEdit#outputText,
            QPlainTextEdit#inputText, QPlainTextEdit#outputText {
                min-height: 100px;
                max-height: 200px;
            }

            /* ====== Console/ Area (БОЛЬШЕ) ====== */
            QTextEdit#console, QPlainTextEdit#console,
            QTextEdit#logText, QPlainTextEdit#logText {
                background-color: #0a0a0a;
                border: 1px solid #1e1e1e;
                border-radius: 4px;
                color: #3a7afe;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 10px;
                min-height: 200px;
                max-height: 600px;
            }

            /* ====== Labels ====== */
            QLabel {
                color: #a0a0a0;
                background-color: transparent;
                font-size: 11px;
            }

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

            /* Primary Buttons */
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
            }

            QPushButton#clearButton:pressed,
            QPushButton#swapButton:pressed {
                background-color: #252525;
            }

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#clearLogButton {
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
            QPushButton#clearLogButton:hover {
                background-color: rgba(231, 76, 60, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#clearLogButton:pressed {
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

            /* ====== SpinBox & LineEdit ====== */
            QSpinBox, QLineEdit {
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                border-radius: 3px;
                padding: 4px 6px;
                selection-background-color: #3a7afe;
                min-height: 26px;
                max-height: 32px;
                min-width: 60px;
                max-width: 150px;
            }

            QSpinBox:focus, QLineEdit:focus {
                border: 1px solid #3a7afe;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #2d2d2d;
                border: none;
                border-radius: 2px;
                width: 18px;
            }

            /* ====== ScrollBar ====== */
            QScrollBar:vertical {
                background-color: #1e1e1e;
                width: 8px;
                border-radius: 4px;
            }

            QScrollBar:horizontal {
                background-color: #1e1e1e;
                height: 8px;
                border-radius: 4px;
            }

            QScrollBar::handle:vertical {
                background-color: #3d3d3d;
                border-radius: 4px;
                min-height: 20px;
            }

            QScrollBar::handle:horizontal {
                background-color: #3d3d3d;
                border-radius: 4px;
                min-width: 20px;
            }

            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {
                background-color: #4d4d4d;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
                width: 0px;
            }

            /* ====== Status Bar ====== */
            QStatusBar {
                background-color: #1e1e1e;
                color: #a0a0a0;
                border-top: 1px solid #2a2a2a;
                padding: 2px;
                font-size: 10px;
                max-height: 24px;
            }

            /* ====== Menu Bar ====== */
            QMenuBar {
                background-color: #121212;
                color: #a0a0a0;
                border-bottom: 1px solid #2a2a2a;
                padding: 2px;
                font-size: 11px;
                max-height: 26px;
            }

            QMenuBar::item:selected {
                background-color: #2d2d2d;
                border-radius: 3px;
            }

            QMenu {
                background-color: #1e1e1e;
                border: 1px solid #2a2a2a;
                padding: 3px;
                min-width: 120px;
            }

            QMenu::item {
                padding: 4px 8px;
                font-size: 11px;
            }

            QMenu::item:selected {
                background-color: #3a7afe;
                border-radius: 3px;
            }

            /* ====== CheckBox & RadioButton ====== */
            QCheckBox, QRadioButton {
                spacing: 6px;
                color: #a0a0a0;
                font-size: 11px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
            }

            QCheckBox::indicator:checked {
                background-color: #3a7afe;
                border: 2px solid #3a7afe;
                border-radius: 2px;
            }

            QRadioButton::indicator:checked {
                border: 2px solid #3a7afe;
                border-radius: 7px;
                background-color: #3a7afe;
            }

            /* ====== Layout Spacing ====== */
            QVBoxLayout, QHBoxLayout, QGridLayout {
                spacing: 4px;
                margin: 2px;
            }

            /* ====== Progress Bar ====== */
            QProgressBar {
                border: 1px solid #2a2a2a;
                border-radius: 4px;
                background-color: #1e1e1e;
                text-align: center;
                color: #a0a0a0;
                min-height: 16px;
                max-height: 20px;
            }

            QProgressBar::chunk {
                background-color: #3a7afe;
                border-radius: 3px;
            }
        )";

        case THEME_RELIABLE_ORANGE:
        return R"(
            /* ====== Reliable Orange Theme ====== */
            QMainWindow, QDialog {
                background-color: #0c0905;
            }

            QWidget {
                color: #f0e6d8;
                font-family: 'Segoe UI', 'Roboto', sans-serif;
                font-size: 11px;
            }

            /* ====== Containers ====== */
            QFrame {
                background-color: transparent;
            }

            QFrame#mainFrame, QFrame#contentFrame {
                background-color: #0c0905;
                padding: 6px;
            }

            /* ====== ComboBox ====== */
            QComboBox {
                background-color: #1a140d;
                border: 1px solid #2a2319;
                border-radius: 4px;
                padding: 4px 8px;
                min-width: 80px;
                max-width: 200px;
                height: 28px;
                selection-background-color: #e65c00;
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
                background-color: #1a140d;
                border: 1px solid #2a2319;
                border-radius: 4px;
                padding: 2px;
                selection-background-color: #e65c00;
                min-width: 100px;
                max-height: 200px;
            }

            /* ====== GroupBox ====== */
            QGroupBox {
                font-weight: 600;
                border: 1px solid #2a2319;
                border-radius: 6px;
                margin-top: 8px;
                margin-bottom: 8px;
                padding-top: 6px;
                background-color: #1a140d;
                min-height: 60px;
            }

            QGroupBox::title {
                subcontrol-origin: margin;
                left: 8px;
                padding: 0 6px 0 6px;
                color: #b8a992;
            }

            /* ====== Text Areas ====== */
            QTextEdit, QPlainTextEdit {
                background-color: #1a140d;
                border: 1px solid #2a2319;
                border-radius: 4px;
                padding: 6px;
                selection-background-color: #e65c00;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 11px;
                min-height: 80px;
                max-height: 400px;
            }

            QTextEdit:focus, QPlainTextEdit:focus {
                border: 1px solid #e65c00;
            }

            /* ====== Input/Output Areas (меньше) ====== */
            QTextEdit#inputText, QTextEdit#outputText,
            QPlainTextEdit#inputText, QPlainTextEdit#outputText {
                min-height: 100px;
                max-height: 200px;
            }

            /* ====== Console/ Area (БОЛЬШЕ) ====== */
            QTextEdit#console, QPlainTextEdit#console {
                background-color: #0a0704;
                border: 1px solid #1a140d;
                border-radius: 4px;
                color: #d4a017;
                font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
                font-size: 10px;
                min-height: 200px;
                max-height: 600px;
            }

            /* ====== Labels ====== */
            QLabel {
                color: #b8a992;
                background-color: transparent;
                font-size: 11px;
            }

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

            /* Primary Buttons */
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

            /* Secondary Buttons - ОЛИВКОВЫЕ КНОПКИ ОЧИСТКИ */
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

            /* Tertiary Buttons */
            QPushButton#clearInputButton,
            QPushButton#clearOutputButton,
            QPushButton#clearLogButton {
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
            QPushButton#clearLogButton:hover {
                background-color: rgba(168, 66, 50, 0.2);
            }

            QPushButton#clearInputButton:pressed,
            QPushButton#clearOutputButton:pressed,
            QPushButton#clearLogButton:pressed {
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

            /* ====== SpinBox & LineEdit ====== */
            QSpinBox, QLineEdit {
                background-color: #1a140d;
                border: 1px solid #2a2319;
                border-radius: 3px;
                padding: 4px 6px;
                selection-background-color: #e65c00;
                min-height: 26px;
                max-height: 32px;
                min-width: 60px;
                max-width: 150px;
            }

            QSpinBox:focus, QLineEdit:focus {
                border: 1px solid #e65c00;
            }

            QSpinBox::up-button, QSpinBox::down-button {
                background-color: #2c2418;
                border: none;
                border-radius: 2px;
                width: 18px;
            }

            /* ====== ScrollBar ====== */
            QScrollBar:vertical {
                background-color: #1a140d;
                width: 8px;
                border-radius: 4px;
            }

            QScrollBar:horizontal {
                background-color: #1a140d;
                height: 8px;
                border-radius: 4px;
            }

            QScrollBar::handle:vertical {
                background-color: #3d3223;
                border-radius: 4px;
                min-height: 20px;
            }

            QScrollBar::handle:horizontal {
                background-color: #3d3223;
                border-radius: 4px;
                min-width: 20px;
            }

            QScrollBar::handle:vertical:hover,
            QScrollBar::handle:horizontal:hover {
                background-color: #4d4233;
            }

            QScrollBar::add-line, QScrollBar::sub-line {
                height: 0px;
                width: 0px;
            }

            /* ====== Status Bar ====== */
            QStatusBar {
                background-color: #1a140d;
                color: #b8a992;
                border-top: 1px solid #2a2319;
                padding: 2px;
                font-size: 10px;
                max-height: 24px;
            }

            /* ====== Menu Bar ====== */
            QMenuBar {
                background-color: #0c0905;
                color: #b8a992;
                border-bottom: 1px solid #2a2319;
                padding: 2px;
                font-size: 11px;
                max-height: 26px;
            }

            QMenuBar::item:selected {
                background-color: #2c2418;
                border-radius: 3px;
            }

            QMenu {
                background-color: #1a140d;
                border: 1px solid #2a2319;
                padding: 3px;
                min-width: 120px;
            }

            QMenu::item {
                padding: 4px 8px;
                font-size: 11px;
            }

            QMenu::item:selected {
                background-color: #e65c00;
                border-radius: 3px;
            }

            /* ====== CheckBox & RadioButton ====== */
            QCheckBox, QRadioButton {
                spacing: 6px;
                color: #b8a992;
                font-size: 11px;
            }

            QCheckBox::indicator, QRadioButton::indicator {
                width: 14px;
                height: 14px;
            }

            QCheckBox::indicator:checked {
                background-color: #e65c00;
                border: 2px solid #e65c00;
                border-radius: 2px;
            }

            QRadioButton::indicator:checked {
                border: 2px solid #e65c00;
                border-radius: 7px;
                background-color: #e65c00;
            }

            /* ====== Layout Spacing ====== */
            QVBoxLayout, QHBoxLayout, QGridLayout {
                spacing: 4px;
                margin: 2px;
            }

            /* ====== Progress Bar ====== */
            QProgressBar {
                border: 1px solid #2a2319;
                border-radius: 4px;
                background-color: #1a140d;
                text-align: center;
                color: #b8a992;
                min-height: 16px;
                max-height: 20px;
            }

            QProgressBar::chunk {
                background-color: #e65c00;
                border-radius: 3px;
            }
        )";
    }

    return "";
}
