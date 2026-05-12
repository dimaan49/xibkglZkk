#ifndef PopupComboBox_H
#define PopupComboBox_H

#include <QComboBox>
#include <QListView>

class PopupComboBox : public QComboBox
{
    Q_OBJECT

public:
    explicit PopupComboBox(QWidget* parent = nullptr);

    void showPopup() override;
    void hidePopup() override;

protected:
    bool eventFilter(QObject* obj, QEvent* event) override;

private slots:
    void onItemClicked(const QModelIndex& index);

private:
    QListView* m_listView;
    bool m_popupVisible;
};

#endif // PopupComboBox_H
