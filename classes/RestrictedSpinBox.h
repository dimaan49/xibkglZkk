// restrictedspinbox.h
#ifndef RESTRICTEDSPINBOX_H
#define RESTRICTEDSPINBOX_H

#include <QSpinBox>
#include <QKeyEvent>
#include <QLineEdit>

class RestrictedSpinBox : public QSpinBox
{
    Q_OBJECT

public:
    RestrictedSpinBox(QWidget* parent = nullptr);

protected:
    virtual void keyPressEvent(QKeyEvent* event) override;
};

#endif // RESTRICTEDSPINBOX_H
