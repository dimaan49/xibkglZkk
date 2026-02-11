#ifndef ADVANCEDSETTINGSDIALOG_H
#define ADVANCEDSETTINGSDIALOG_H

#include <QDialog>
#include <QVBoxLayout>
#include <QMap>
#include <QPushButton>
#include <QLabel>
#include <QDialogButtonBox>
#include <QCloseEvent>  // ВАЖНО!

class AdvancedSettingsDialog : public QDialog
{
    Q_OBJECT

public:
    explicit AdvancedSettingsDialog(const QString& cipherId, const QString& cipherName,
                                   QWidget* parent = nullptr);
    ~AdvancedSettingsDialog() override;

    QVariantMap getSettings() const;
    void setSettings(const QVariantMap& settings);

protected:
    void closeEvent(QCloseEvent* event) override;  // ДОБАВЛЯЕМ!
    void reject() override;
    void accept() override;

private:
    void setupUI();
    void createAdvancedWidgets();

    QString m_cipherId;
    QString m_cipherName;
    QMap<QString, QWidget*> m_advancedWidgets;
    QVariantMap m_initialSettings;

    QVBoxLayout* m_mainLayout;
    QLabel* m_titleLabel;
    QWidget* m_contentWidget;
    QVBoxLayout* m_contentLayout;
    QDialogButtonBox* m_buttonBox;
};

#endif // ADVANCEDSETTINGSDIALOG_H
