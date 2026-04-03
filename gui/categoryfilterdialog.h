#ifndef CATEGORYFILTERDIALOG_H
#define CATEGORYFILTERDIALOG_H

#include <QDialog>
#include <QMap>
#include <QCheckBox>
#include <QPushButton>
#include <QVBoxLayout>
#include <QScrollArea>
#include <QLabel>
#include <QDialogButtonBox>
#include "cipherfactory.h"

class CategoryFilterDialog : public QDialog
{
    Q_OBJECT

public:
    explicit CategoryFilterDialog(QWidget* parent = nullptr);

    QList<CipherCategory> selectedCategories() const;
    void setSelectedCategories(const QList<CipherCategory>& categories);
    void selectAllCategories(bool selected);

private:
    void setupUI();
    QCheckBox* createCategoryCheckbox(CipherCategory category);

    QMap<CipherCategory, QCheckBox*> m_checkboxes;
    QPushButton* m_selectAllButton;
    QPushButton* m_clearAllButton;
    QDialogButtonBox* m_buttonBox;
};

#endif // CATEGORYFILTERDIALOG_H
