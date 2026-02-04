#include "mainwindow.h"

#include <QApplication>
#include <QStyleHints>

int main(int argc, char *argv[])
{
    QApplication a(argc, argv);
    a.setStyle("Fusion");
    a.styleHints()->setColorScheme(Qt::ColorScheme::Light);

    MainWindow w;
    w.show();
    return a.exec();
}
