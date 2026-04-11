#ifndef LIBRARYWINDOW_H
#define LIBRARYWINDOW_H

#include <QDialog>
#include <QListWidget>
#include <QTextEdit>
#include <QLineEdit>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QSplitter>
#include <QCheckBox>

class LibraryWindow : public QDialog
{
    Q_OBJECT

public:
    explicit LibraryWindow(QWidget* parent = nullptr);
    ~LibraryWindow();

private slots:
    void onFilterChanged();
    void onCipherSelected(int index);
    void onSelectAll();
    void onClearAll();

private:
    void setupUI();
    void loadCiphers();
    void applyFilter();

    QSplitter* m_splitter;
    QListWidget* m_cipherList;
    QTextEdit* m_infoEdit;
    QLineEdit* m_searchEdit;

    QList<QCheckBox*> m_categoryCheckboxes;
    QStringList m_allCipherNames;
    QStringList m_allCipherDescriptions;
};

#endif
