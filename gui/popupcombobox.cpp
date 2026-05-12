#include "popupcombobox.h"
#include <QApplication>
#include <QScreen>
#include <QScrollBar>
#include <QMouseEvent>

PopupComboBox::PopupComboBox(QWidget* parent)
    : QComboBox(parent)
    , m_popupVisible(false)
{
    m_listView = new QListView();
    m_listView->setWindowFlags(Qt::Popup | Qt::FramelessWindowHint);
    m_listView->setAttribute(Qt::WA_ShowWithoutActivating);
    m_listView->setFocusPolicy(Qt::StrongFocus);
    m_listView->setHorizontalScrollBarPolicy(Qt::ScrollBarAlwaysOff);
    m_listView->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    m_listView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_listView->setSelectionMode(QAbstractItemView::SingleSelection);
    m_listView->setMouseTracking(true);

    m_listView->setStyleSheet(R"(
        QListView {
            background-color: #1e2a3a;
            border: 1px solid #2a3a4a;
            border-radius: 6px;
            padding: 4px;
            font-size: 14px;
            color: #e0e0e0;
            outline: none;
        }
        QListView::item {
            padding: 8px 12px;
            margin: 1px 0;
            border-radius: 4px;
            min-height: 22px;
        }
        QListView::item:hover {
            background-color: #2a3a4a;
            color: #ffffff;
        }
        QListView::item:selected {
            background-color: #00c896;
            color: #1e2a3a;
            font-weight: bold;
        }
        QScrollBar:vertical {
            width: 8px;
            background: transparent;
            margin: 2px;
        }
        QScrollBar::handle:vertical {
            background: #3a4a5a;
            border-radius: 4px;
            min-height: 30px;
        }
        QScrollBar::handle:vertical:hover {
            background: #4a5a6a;
        }
        QScrollBar::add-line:vertical,
        QScrollBar::sub-line:vertical {
            height: 0;
        }
    )");

    connect(m_listView, &QListView::clicked, this, &PopupComboBox::onItemClicked);

    // Устанавливаем фильтр событий на список
    m_listView->installEventFilter(this);
}

void PopupComboBox::showPopup()
{
    if (count() == 0) return;

    m_listView->setModel(model());
    m_listView->setCurrentIndex(model()->index(currentIndex(), 0));

    int itemHeight = 45;
    int maxVisibleItems = 10;
    int visibleItems = qMin(count(), maxVisibleItems);
    int popupHeight = visibleItems * itemHeight + 10;

    m_listView->resize(width(), popupHeight);

    QPoint globalPos = mapToGlobal(QPoint(0, height()));

    QScreen* screen = QApplication::screenAt(globalPos);
    if (!screen) screen = QApplication::primaryScreen();
    QRect screenRect = screen->availableGeometry();

    if (globalPos.y() + popupHeight > screenRect.bottom()) {
        globalPos.setY(mapToGlobal(QPoint(0, 0)).y() - popupHeight);
    }

    m_listView->move(globalPos);
    m_popupVisible = true;
    m_listView->show();
    m_listView->setFocus();

    m_listView->scrollTo(m_listView->currentIndex(), QAbstractItemView::PositionAtTop);

    // Устанавливаем глобальный фильтр для закрытия при клике вне
    qApp->installEventFilter(this);
}

void PopupComboBox::hidePopup()
{
    m_popupVisible = false;
    m_listView->hide();
    qApp->removeEventFilter(this); // Убираем глобальный фильтр
}

bool PopupComboBox::eventFilter(QObject* obj, QEvent* event)
{
    if (m_popupVisible && event->type() == QEvent::MouseButtonPress) {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        QPoint globalPos = mouseEvent->globalPos();

        // Если кликнули вне попапа и вне комбобокса
        if (!m_listView->geometry().contains(globalPos) &&
            !this->rect().contains(this->mapFromGlobal(globalPos))) {
            hidePopup();
            return false;
        }
    }
    return QComboBox::eventFilter(obj, event);
}

void PopupComboBox::onItemClicked(const QModelIndex& index)
{
    if (!m_popupVisible) return;

    int row = index.row();
    if (row >= 0 && row < count()) {
        setCurrentIndex(row);
        hidePopup();
        emit activated(row);
    }
}

