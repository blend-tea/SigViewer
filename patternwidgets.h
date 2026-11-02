#ifndef PATTERNWIDGETS_H
#define PATTERNWIDGETS_H

#include <QApplication>
#include <QClipboard>
#include <QContextMenuEvent>
#include <QKeyEvent>
#include <QMenu>
#include <QMimeData>
#include <QPlainTextEdit>
#include <QTableWidget>
#include <QTextBlock>

// Keep the display separators out of clipboard/drag data, including partial
// mouse selections. Only the pattern portion of the marked block is changed.
class PatternRulesEdit : public QPlainTextEdit {
public:
    using QPlainTextEdit::QPlainTextEdit;
    void setPatternBlock(int blockNumber, int prefixLength) {
        m_patternBlock = blockNumber;
        m_prefixLength = prefixLength;
    }
protected:
    QMimeData *createMimeDataFromSelection() const override {
        QMimeData *mime = QPlainTextEdit::createMimeDataFromSelection();
        const QTextCursor cursor = textCursor();
        const QTextBlock block = document()->findBlockByNumber(m_patternBlock);
        if (!block.isValid()) return mime;
        QString text = mime->text();
        const int start = cursor.selectionStart();
        const int end = cursor.selectionEnd();
        const int patternStart = block.position() + m_prefixLength;
        const int patternEnd = block.position() + block.length() - 1;
        for (int pos = qMin(end, patternEnd) - 1; pos >= qMax(start, patternStart); --pos) {
            if (document()->characterAt(pos) == QChar(' ')) text.remove(pos - start, 1);
        }
        // Do not leave HTML or other formats carrying the spaced representation.
        mime->clear();
        mime->setText(text);
        return mime;
    }
private:
    int m_patternBlock = -1;
    int m_prefixLength = 0;
};

class PatternFunctionsTable : public QTableWidget {
public:
    using QTableWidget::QTableWidget;
    void copyCurrentCell() const {
        if (!currentItem()) return;
        QString text = currentItem()->text();
        if (currentColumn() == 5) text.remove(QChar(' '));
        QApplication::clipboard()->setText(text);
    }
protected:
    void keyPressEvent(QKeyEvent *event) override {
        if (event->matches(QKeySequence::Copy)) {
            copyCurrentCell();
            event->accept();
            return;
        }
        QTableWidget::keyPressEvent(event);
    }
    void contextMenuEvent(QContextMenuEvent *event) override {
        if (auto *cell = itemAt(event->pos())) setCurrentItem(cell);
        QMenu menu(this);
        QAction *copy = menu.addAction(tr("Copy"));
        copy->setEnabled(currentItem() != nullptr);
        if (menu.exec(event->globalPos()) == copy) copyCurrentCell();
    }
};

#endif // PATTERNWIDGETS_H
