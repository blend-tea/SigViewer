#include "patternwidgets.h"
#include "sigparser/flirtparser.h"
#include <QTextStream>

class RulesProbe : public PatternRulesEdit {
public:
    using PatternRulesEdit::createMimeDataFromSelection;
};

int main(int argc, char **argv) {
    QApplication app(argc, argv);
    int failures = 0;
    auto check = [&failures](bool ok, const char *label) {
        if (!ok) { ++failures; QTextStream(stderr) << "FAIL: " << label << '\n'; }
    };
    SigParser::FlirtModule module;
    module.patternPath.append({QByteArray::fromHex("485355"), QByteArray(3, 0)});
    module.patternPath.append({QByteArray::fromHex("560057"), QByteArray::fromHex("000100")});
    module.patternPath.append(SigParser::FlirtPatternNode{});
    check(module.patternPathHex() == "48 53 55 56 .. 57", "byte separators ignore node boundaries");

    RulesProbe edit;
    const QString source = "Function: name with spaces\n\nPattern path: 48 53 .. 57\n\nModule length: 64";
    edit.setPlainText(source);
    edit.setPatternBlock(2, 14);
    edit.selectAll();
    QMimeData *mime = edit.createMimeDataFromSelection();
    check(mime->text() == "Function: name with spaces\n\nPattern path: 4853..57\n\nModule length: 64",
          "whole selection only strips pattern spaces");
    check(!mime->hasHtml(), "no spaced HTML representation");
    delete mime;
    const int start = source.indexOf("48 53");
    QTextCursor cursor = edit.textCursor();
    cursor.setPosition(start + 3);
    cursor.setPosition(start + 8, QTextCursor::KeepAnchor);
    edit.setTextCursor(cursor);
    mime = edit.createMimeDataFromSelection();
    check(mime->text() == "53..", "partial mouse-style selection");
    delete mime;
    edit.copy();
    check(QApplication::clipboard()->text() == "53..", "standard copy uses compact pattern");

    PatternFunctionsTable table;
    table.setRowCount(1); table.setColumnCount(6);
    table.setItem(0, 5, new QTableWidgetItem(module.patternPathHex()));
    table.setItem(0, 1, new QTableWidgetItem("name with spaces"));
    table.setCurrentCell(0, 5);
    table.copyCurrentCell();
    check(QApplication::clipboard()->text() == "48535556..57", "table pattern copy");
    table.setCurrentCell(0, 1);
    table.copyCurrentCell();
    check(QApplication::clipboard()->text() == "name with spaces", "table names preserve spaces");
    QTextStream(stdout) << "Pattern widget failures: " << failures << '\n';
    return failures ? 1 : 0;
}
