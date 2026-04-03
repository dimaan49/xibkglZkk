#ifndef ADVANCEDSETTINGSDIALOG_H
#define ADVANCEDSETTINGSDIALOG_H

#include "routecipherwidget.h"
#include <QDialog>
#include <QMap>
#include <QVariant>

class QVBoxLayout;
class QHBoxLayout;
class QLabel;
class QWidget;
class QDialogButtonBox;

class AdvancedSettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AdvancedSettingsDialog(int cipherId, const QString& cipherName,
                                   QWidget* parent = nullptr);
    ~AdvancedSettingsDialog();

    QVariantMap getSettings() const;
    void setSettings(const QVariantMap& settings);
    RouteCipherAdvancedWidget* getRouteAdvancedWidget() const;
    void setPreviewText(const QString& text);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void reject() override;
    void accept() override;

private:
    void setupUI();
    void createAdvancedWidgets();

    int m_cipherId;
    QString m_cipherName;
    QVariantMap m_initialSettings;

    // UI Elements
    QVBoxLayout* m_mainLayout;
    QLabel* m_titleLabel;
    QWidget* m_contentWidget;
    QVBoxLayout* m_contentLayout;
    QDialogButtonBox* m_buttonBox;

    // Хранилище виджетов
    QMap<QString, QWidget*> m_advancedWidgets;
    QString m_previewText;
};

#endif // ADVANCEDSETTINGSDIALOG_H
