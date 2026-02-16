#ifndef ADVANCEDSETTINGSDIALOG_H
#define ADVANCEDSETTINGSDIALOG_H

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
    explicit AdvancedSettingsDialog(const QString& cipherId, const QString& cipherName,
                                   QWidget* parent = nullptr);
    ~AdvancedSettingsDialog();

    QVariantMap getSettings() const;
    void setSettings(const QVariantMap& settings);

protected:
    void closeEvent(QCloseEvent* event) override;

private slots:
    void reject() override;
    void accept() override;

private:
    void setupUI();
    void createAdvancedWidgets();

    QString m_cipherId;
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
};

#endif // ADVANCEDSETTINGSDIALOG_H
