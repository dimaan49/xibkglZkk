#ifndef STYLEMANAGER_H
#define STYLEMANAGER_H

#include <QString>
#include <QWidget>

class StyleManager {
public:
    enum StyleTheme {
        THEME_CYBER_MIDNIGHT = 0,
        THEME_DARK_PROFESSIONAL = 1,
        THEME_RELIABLE_ORANGE = 2
    };

    static void applyTheme(QWidget* window, StyleTheme theme);
    static QString getStylesheet(StyleTheme theme);
    static QString getLogWindowStylesheet();
    static QString getAdvancedDialogStylesheet(StyleTheme theme);  // Добавляем объявление

private:
    StyleManager() = delete;  // Запрещаем создание экземпляров
};

#endif // STYLEMANAGER_H
