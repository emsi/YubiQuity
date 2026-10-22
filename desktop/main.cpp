#include "window.h"
#include <QApplication>
#include <QCommandLineParser>
#include <QDBusConnectionInterface>
#include <QDBusInterface>
#include <QFileInfo>
#include <QMessageBox>
#include <QStandardPaths>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

int main(int argc, char **argv) {
  umask(0077);
  const rlimit limit{0, 0};
  if (setrlimit(RLIMIT_CORE, &limit) != 0 || prctl(PR_SET_DUMPABLE, 0) != 0 ||
      geteuid() == 0) {
    fputs("YubiQuity Desktop must run as a normal user with process dumping "
          "disabled.\n",
          stderr);
    return 1;
  }
  QApplication app(argc, argv);
  app.setOrganizationName("YubiQuity");
  app.setApplicationName("YubiQuity");
  app.setApplicationVersion("0.1.0");
  app.setQuitOnLastWindowClosed(false);
  QCommandLineParser parser;
  parser.setApplicationDescription(
      "Native confirmation for the YubiQuity software security key");
  parser.addHelpOption();
  parser.addVersionOption();
  parser.addOptions(
      {{"vault", "Open an existing encrypted vault", "path"},
       {"backend", "Path to the matching yubiquity CLI", "executable"},
       {"socket", "Attach to an existing local service instead of owning one",
        "path"},
       {"node-helper", "Explicit container-only helper for the owned service",
        "path"}});
  parser.process(app);
  auto bus = QDBusConnection::sessionBus();
  if (!bus.isConnected()) {
    QMessageBox::critical(nullptr, "YubiQuity",
                          "A desktop D-Bus session is required. Launch "
                          "YubiQuity from your normal desktop session.");
    return 1;
  }
  if (!bus.registerService("org.yubiquity.Desktop")) {
    QDBusInterface existing("org.yubiquity.Desktop", "/Desktop",
                            "org.yubiquity.Desktop", bus);
    const auto reply = existing.call("Show");
    if (reply.type() == QDBusMessage::ErrorMessage) {
      QMessageBox::critical(nullptr, "YubiQuity",
                            "Another desktop client is registered but not "
                            "responding. Close it before restarting.");
      return 1;
    }
    return 0;
  }
  auto backend = parser.value("backend");
  if (backend.isEmpty()) {
    auto sibling = QCoreApplication::applicationDirPath() + "/yubiquity";
    backend = QFileInfo(sibling).isExecutable()
                  ? sibling
                  : QStandardPaths::findExecutable("yubiquity");
  }
  if (backend.isEmpty() || !QFileInfo(backend).isExecutable()) {
    QMessageBox::critical(
        nullptr, "YubiQuity",
        "The yubiquity command was not found. Install the matching CLI beside "
        "this application or use --backend /absolute/path/to/yubiquity.");
    return 1;
  }
  Window window(QFileInfo(backend).absoluteFilePath(), parser.value("vault"),
                parser.value("socket"), parser.value("node-helper"));
  bus.registerObject("/Desktop", &window,
                     QDBusConnection::ExportScriptableSlots);
  window.show();
  return app.exec();
}
