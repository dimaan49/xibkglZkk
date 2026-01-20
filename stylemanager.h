#ifndef STYLEMANAGER_H
#define STYLEMANAGER_H

#include <QWidget>
#include <QLabel>
#include <QSpinBox>
#include <QLineEdit>
#include <QHBoxLayout>
#include <QVBoxLayout>
#include <QComboBox>
#include <QCheckBox>
#include <QGroupBox>


class StyleManager {
public:
    enum StyleTheme {
        THEME_CYBER_MIDNIGHT,
        THEME_DARK_PROFESSIONAL,
        THEME_RELIABLE_ORANGE
    };

    static void applyTheme(QWidget* window, StyleTheme theme);
    static QString getStylesheet(StyleTheme theme);
};

#endif // STYLEMANAGER_H
