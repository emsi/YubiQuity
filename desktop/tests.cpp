#include "presentation.h"
#include "process.h"
#include "ui.h"
#include "window.h"
#include <QDialogButtonBox>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLocalServer>
#include <QLocalSocket>
#include <QSignalSpy>
#include <QTemporaryDir>
#include <QTest>
#include <QWindow>
#include <QtEndian>
#include <csignal>
#include <optional>
#include <sys/stat.h>
#include <unistd.h>

static QJsonObject pending(QString token = "internal-123",
                           int remaining = 30000) {
  return {{"token", token},
          {"operation", "register"},
          {"rp_id", "example.test"},
          {"account", "alice"},
          {"remaining_ms", remaining}};
}
static QJsonObject snapshotEvent(int sequence, QJsonObject request = {}) {
  QJsonObject state{{"ok", true}, {"state", "ready"}};
  if (!request.isEmpty())
    state.insert("pending", request);
  return {{"version", 1}, {"sequence", sequence}, {"snapshot", state}};
}

static ApprovalDialog *visibleApproval() {
  for (auto *widget : QApplication::topLevelWidgets())
    if (auto *dialog = qobject_cast<ApprovalDialog *>(widget);
        dialog && dialog->isVisible())
      return dialog;
  return nullptr;
}

// Test-only socket fixture, never a production authenticator or approval mode.
// Exercises the real Rust bridge, same-UID checks, framing and Qt controller.
class FakeService : public QObject {
public:
  QTemporaryDir dir;
  QLocalServer listener;
  QPointer<QLocalSocket> watcher;
  QList<QJsonObject> commands;
  int sequence = 0;
  QJsonObject request = pending();
  bool locked = false;
  std::optional<bool> pinConfigured;
  FakeService() {
    chmod(QFile::encodeName(dir.path()).constData(), 0700);
    listener.setSocketOptions(QLocalServer::UserAccessOption);
    if (!listener.listen(path()))
      qFatal("test socket could not listen");
    chmod(QFile::encodeName(path()).constData(), 0600);
    connect(&listener, &QLocalServer::newConnection, this, [this] {
      auto *socket = listener.nextPendingConnection();
      auto buffer = std::make_shared<QByteArray>();
      connect(socket, &QLocalSocket::readyRead, this, [this, socket, buffer] {
        *buffer += socket->readAll();
        if (buffer->size() < 4)
          return;
        auto length = qFromBigEndian<quint32>(buffer->constData());
        if (buffer->size() < 4 + length)
          return;
        auto command = QJsonDocument::fromJson(buffer->mid(4, length)).object();
        buffer->clear();
        if (command.value("command") == "watch") {
          watcher = socket;
          publish();
        } else {
          commands.append(command);
          if (command.value("command") == "configure_pin") {
            pinConfigured = true;
            publish();
          }
          if (command.value("command") == "lock")
            locked = true;
          send(socket, {{"ok", true}, {"state", locked ? "locked" : "ready"}});
          socket->disconnectFromServer();
        }
      });
      connect(socket, &QLocalSocket::disconnected, socket,
              &QObject::deleteLater);
    });
  }
  QString path() const { return dir.path() + "/control.sock"; }
  static void send(QLocalSocket *socket, const QJsonObject &object) {
    auto bytes = QJsonDocument(object).toJson(QJsonDocument::Compact);
    char size[4];
    qToBigEndian<quint32>(quint32(bytes.size()), size);
    socket->write(size, 4);
    socket->write(bytes);
    socket->flush();
  }
  void publish() {
    auto data = snapshotEvent(++sequence, request);
    if (pinConfigured) {
      auto state = data["snapshot"].toObject();
      state["pin_configured"] = *pinConfigured;
      data["snapshot"] = state;
    }
    if (locked)
      data["snapshot"] = QJsonObject{{"ok", true}, {"state", "locked"}};
    if (watcher)
      send(watcher, data);
  }
};

class DesktopTests : public QObject {
  Q_OBJECT
private slots:
  void nativeApprovalPreview() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    ApprovalDialog dialog({"not-visible", "register", "webauthn.io",
                           "emsi-test-001", true, 30000});
    dialog.show();
    QTRY_VERIFY(dialog.isVisible());
    QTest::qWait(100);
    QVERIFY(dialog.grab().save(
        qEnvironmentVariable("YUBIQUITY_TEST_ARTIFACTS") + "/approval.png"));
  }
  void nativeSetupPreview() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    SetupPage page("unused-backend", {});
    page.resize(760, 720);
    page.showReport(
        {{"version", 1},
         {"checks",
          QJsonArray{
              QJsonObject{{"title", "Desktop session"},
                          {"status", "ok"},
                          {"detail", "Current access group is active."}},
              QJsonObject{{"title", "Create a software security key"},
                          {"status", "ok"},
                          {"detail", "UHID is accessible."}},
              QJsonObject{
                  {"title", "Browser-facing device"},
                  {"status", "ok"},
                  {"detail", "A temporary device was opened and detached."}},
              QJsonObject{{"title", "Firefox Snap connection"},
                          {"status", "ok"},
                          {"detail", "Security-key interface connected."}},
              QJsonObject{{"title", "Firefox Snap device permission"},
                          {"status", "ok"},
                          {"detail", "Current device tag present."}}}}});
    page.show();
    QTest::qWait(100);
    QVERIFY(page.grab().save(qEnvironmentVariable("YUBIQUITY_TEST_ARTIFACTS") +
                             "/setup.png"));
  }
  void childDiesWithItsParent() {
    QProcess parent;
    parent.start(QCoreApplication::applicationFilePath(),
                 {"--child-parent-fixture"});
    QVERIFY(parent.waitForStarted(2000));
    QVERIFY(parent.waitForReadyRead(2000));
    bool parsed = false;
    auto pid = parent.readLine().trimmed().toLongLong(&parsed);
    QVERIFY(parsed && pid > 1);
    parent.kill();
    QVERIFY(parent.waitForFinished(2000));
    auto dead = [pid] {
      QFile stat(QString("/proc/%1/stat").arg(pid));
      if (!stat.open(QIODevice::ReadOnly))
        return true;
      auto contents = stat.readAll();
      // An orphan can briefly remain a zombie until the container's init reaps
      // it.
      return contents.mid(contents.lastIndexOf(')') + 2, 1) == "Z";
    };
    QTRY_VERIFY_WITH_TIMEOUT(dead(), 2000);
  }
  void nativePinentryAccept() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    Pinentry prompt;
    QSignalSpy secret(&prompt, &Pinentry::secretReady),
        failed(&prompt, &Pinentry::failed);
    prompt.start(false);
    QTRY_VERIFY_WITH_TIMEOUT(!secret.isEmpty() || !failed.isEmpty(), 15000);
    QVERIFY2(failed.isEmpty(),
             failed.isEmpty() ? "" : qPrintable(failed[0][0].toString()));
    QCOMPARE(secret[0][0].toByteArray(),
             QByteArray("disposable%test+passphrase"));
  }
  void nativePinentryCreate() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    Pinentry prompt;
    QSignalSpy secret(&prompt, &Pinentry::secretReady),
        failed(&prompt, &Pinentry::failed);
    prompt.start(true);
    QTRY_VERIFY_WITH_TIMEOUT(!secret.isEmpty() || !failed.isEmpty(), 15000);
    QVERIFY2(failed.isEmpty(),
             failed.isEmpty() ? "" : qPrintable(failed[0][0].toString()));
    QCOMPARE(secret[0][0].toByteArray(),
             QByteArray("disposable%test+passphrase"));
  }
  void nativeWindowPinSetup() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    FakeService server;
    server.request = {};
    server.pinConfigured = false;
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    auto *pin = window.findChild<QPushButton *>("setupPin");
    QVERIFY(pin);
    QTRY_VERIFY(pin->isEnabled());
    pin->click();
    QTRY_COMPARE_WITH_TIMEOUT(server.commands.size(), 1, 15000);
    const auto request = server.commands.front();
    QCOMPARE(request.value("command").toString(), QString("configure_pin"));
    QCOMPARE(request.value("current").toArray().size(), 0);
    QByteArray received;
    for (auto byte : request.value("new").toArray())
      received.append(char(byte.toInt()));
    QCOMPARE(received, QByteArray("disposable%test+passphrase"));
    QTRY_VERIFY(pin->text().contains("Change"));
    QTRY_VERIFY(window.findChild<QLabel *>("setupResult")
                    ->text()
                    .contains("PIN saved"));
  }
  void setupStatesAndReadableDiagnostics() {
    SetupPage page("unused-backend", {});
    auto *pin = page.findChild<QPushButton *>("setupPin");
    QVERIFY(!pin->isEnabled());
    page.setVaultState(true, true, true, false, false);
    QVERIFY(pin->isEnabled());
    QVERIFY(pin->text().startsWith("Set"));
    page.setVaultState(true, true, true, true, false);
    QVERIFY(pin->text().startsWith("Change"));
    page.setVaultState(true, true, true, true, true);
    QVERIFY(!pin->isEnabled());
    page.setVaultState(true, false, false, false, false);
    QVERIFY(!pin->isEnabled());
    page.showReport(
        {{"version", 1},
         {"repair_device", false},
         {"repair_firefox", true},
         {"checks",
          QJsonArray{QJsonObject{
              {"title", "Firefox Snap"},
              {"status", "attention"},
              {"detail", "Connection missing.\nEnable Firefox Snap."}}}}});
    QVERIFY(!page.findChild<QPushButton *>("setupFirefox")->isHidden());
    QVERIFY(page.findChild<QPushButton *>("setupDevice")->isHidden());
    auto *checks = page.findChild<QLabel *>("setupDetails");
    QCOMPARE(checks->textFormat(), Qt::PlainText);
    QVERIFY(
        checks->text().contains("Connection missing.\nEnable Firefox Snap."));
    page.showReport(
        {{"version", 1}, {"checks", QJsonArray{}}, {"repair_firefox", false}});
    QVERIFY(page.findChild<QPushButton *>("setupFirefox")->isHidden());
  }
  void nativePinentryCancel() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_NATIVE_TEST"))
      QSKIP("Run tests/desktop_native.py on its private Xvfb display");
    Pinentry prompt;
    QSignalSpy secret(&prompt, &Pinentry::secretReady),
        failed(&prompt, &Pinentry::failed);
    prompt.start(false);
    QTRY_COMPARE_WITH_TIMEOUT(failed.size(), 1, 15000);
    QVERIFY(secret.isEmpty());
  }
  void plainTextAndInvisibleControls() {
    QCOMPARE(displayText("a\nb"), QString("a\\u000ab"));
    QCOMPARE(displayText(QString::fromUtf8("abc\xe2\x80\xae")),
             QString("abc\\u202e"));
    ApprovalDialog dialog({"secret-token", "register", "<b>example.test</b>",
                           "Alice", true, 1000});
    auto *site = dialog.findChild<QLabel *>("site");
    QCOMPARE(site->textFormat(), Qt::PlainText);
    QCOMPARE(site->text(), QString("Site: <b>example.test</b>"));
    for (auto *label : dialog.findChildren<QLabel *>())
      QVERIFY(!label->text().contains("secret-token"));
  }
  void exactRequestSingleDecisionAndSafeDefault() {
    ApprovalDialog dialog(
        {"request-A", "authenticate", "example.test", {}, false, 1000});
    QSignalSpy decisions(&dialog, &ApprovalDialog::decision);
    auto *buttons = dialog.findChild<QDialogButtonBox *>();
    QVERIFY(buttons->button(QDialogButtonBox::Cancel)->isDefault());
    auto *approve = dialog.findChild<QPushButton *>("approve");
    QVERIFY(!approve->autoDefault());
    approve->click();
    approve->click();
    QCOMPARE(decisions.size(), 1);
    QCOMPARE(decisions[0][0].toString(), QString("request-A"));
    QCOMPARE(decisions[0][1].toBool(), true);
  }
  void escapeAndCloseDeny() {
    for (bool escape : {false, true}) {
      ApprovalDialog dialog(
          {"request-A", "register", "example.test", {}, false, 1000});
      QSignalSpy decisions(&dialog, &ApprovalDialog::decision);
      dialog.show();
      if (escape)
        QTest::keyClick(&dialog, Qt::Key_Escape);
      else
        dialog.close();
      QCOMPARE(decisions.size(), 1);
      QCOMPARE(decisions[0][1].toBool(), false);
    }
  }
  void expiryCannotBeRenewedOrClicked() {
    ApprovalDialog dialog(
        {"request-A", "register", "example.test", {}, false, 30});
    QSignalSpy decisions(&dialog, &ApprovalDialog::decision),
        expired(&dialog, &ApprovalDialog::expired);
    dialog.shortenLifetime(30000);
    QTRY_COMPARE_WITH_TIMEOUT(expired.size(), 1, 1000);
    dialog.findChild<QPushButton *>("approve")->click();
    QCOMPARE(decisions.size(), 0);
  }
  void presentingAgainCannotRenewDeadline() {
    ApprovalDialog dialog(
        {"request-A", "register", "example.test", {}, false, 30});
    QSignalSpy decisions(&dialog, &ApprovalDialog::decision),
        expired(&dialog, &ApprovalDialog::expired);
    presentWindow(dialog);
    // Leave the expiry event queued: the monotonic deadline must still reject
    // a click immediately after recall, even before that event is delivered.
    QTest::qSleep(40);
    dialog.hide();
    presentWindow(dialog);
    dialog.findChild<QPushButton *>("approve")->click();
    QCOMPARE(decisions.size(), 0);
    QCOMPARE(expired.size(), 1);
    QCOMPARE(dialog.token(), QString("request-A"));
  }
  void resetHasExplicitDestructiveLanguage() {
    ApprovalDialog dialog({"reset", "reset", {}, {}, false, 1000});
    QCOMPARE(dialog.findChild<QPushButton *>("approve")->text(),
             QString("Delete all passkeys"));
    bool warned = false;
    for (auto *label : dialog.findChildren<QLabel *>())
      warned |= label->text().contains("cannot be undone");
    QVERIFY(warned);
  }
  void snapshotVersionAndImmutableRequest() {
    SnapshotModel model;
    QString error;
    QVERIFY(model.update(snapshotEvent(1, pending()), error));
    QVERIFY(
        model.update(snapshotEvent(2, pending("internal-123", 100)), error));
    QVERIFY(!model.update(snapshotEvent(2), error));
    auto changed = pending();
    changed["rp_id"] = "different.test";
    QVERIFY(!model.update(snapshotEvent(3, changed), error));
    auto future = snapshotEvent(3);
    future["version"] = 2;
    QVERIFY(!model.update(future, error));
    QVERIFY(model.update(snapshotEvent(3), error));
    QVERIFY(model.pending.token.isEmpty());
    auto unknown = pending();
    unknown["operation"] = "unknown";
    QVERIFY(!model.update(snapshotEvent(4, unknown), error));
    auto wrongType = pending();
    wrongType["remaining_ms"] = "123";
    QVERIFY(!model.update(snapshotEvent(4, wrongType), error));
  }
  void assuanCodecAndLimits() {
    QByteArray out;
    QVERIFY(assuanDecode("a%25b%0Ac+%C3%A9", out));
    QCOMPARE(out, QByteArray("a%b\nc+\xc3\xa9"));
    QCOMPARE(assuanEscape("%\n\r"), QByteArray("%25%0A%0D"));
    for (auto malformed : {"%", "%0", "%GG"}) {
      out.clear();
      QVERIFY(!assuanDecode(malformed, out));
    }
    out.clear();
    QVERIFY(!assuanDecode(QByteArray(1025, 'x'), out));
    erase(out);
    QVERIFY(out.isEmpty());
  }
  void realBridgeApprovalAndCancellation() {
    const auto backend = qEnvironmentVariable("YUBIQUITY_TEST_BACKEND");
    QVERIFY2(!backend.isEmpty(),
             "Set YUBIQUITY_TEST_BACKEND to the compiled Rust CLI");
    FakeService server;
    Window window(backend, {}, server.path(), {});
    window.show();
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> first = visibleApproval();
    QVERIFY(!first->parentWidget());
    QVERIFY(!first->windowHandle()->transientParent());
    QCOMPARE(first->windowType(), Qt::Window);
    // Removal is cancellation, never approval/denial for a later request.
    server.request = {};
    server.publish();
    QTRY_VERIFY(!visibleApproval());
    QTRY_VERIFY(!first);
    QVERIFY(server.commands.isEmpty());
    server.request = pending("request-B");
    server.publish();
    QTRY_VERIFY(visibleApproval());
    window.hide();
    window.Show();
    QVERIFY(!window.isVisible()); // Tray activation presents only the request.
    visibleApproval()->findChild<QPushButton *>("approve")->click();
    QTRY_COMPARE(server.commands.size(), 1);
    QCOMPARE(server.commands[0].value("command").toString(),
             QString("approve"));
    QCOMPARE(server.commands[0].value("token").toString(),
             QString("request-B"));
    server.publish();
    QTest::qWait(50);
    QVERIFY(!visibleApproval());
    server.request = pending("request-C");
    server.publish();
    QTRY_VERIFY(visibleApproval());
    server.watcher->disconnectFromServer();
    QTRY_VERIFY(!visibleApproval());
    QCOMPARE(server.commands.size(), 1);
    QCOMPARE(window.findChild<QLabel *>("status")->text(),
             QString("Not connected"));
  }
  void screenLockDropsWatcherAndPrompt() {
    FakeService server;
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(visibleApproval());
    window.screenLocked(true);
    QTRY_VERIFY(!server.watcher);
    QTRY_VERIFY(!visibleApproval());
    QVERIFY(!window.findChild<QPushButton *>("unlock")->isEnabled());
    window.screenLocked(false);
    QVERIFY(window.findChild<QPushButton *>("unlock")->isEnabled());
    QVERIFY(server.commands.isEmpty());
  }
  void secretDescriptorUsesRealVaultCode() {
    QTemporaryDir directory;
    chmod(QFile::encodeName(directory.path()).constData(), 0700);
    const auto path = directory.path() + "/credentials.yq";
    const auto backend = qEnvironmentVariable("YUBIQUITY_TEST_BACKEND");
    Command init;
    QSignalSpy finished(&init, &Command::finished);
    init.start(backend, {"init", "--vault", path, "--passphrase-fd", "198"},
               "disposable test passphrase", true);
    QTRY_COMPARE_WITH_TIMEOUT(finished.size(), 1, 10000);
    QVERIFY2(finished[0][0].toBool(), qPrintable(finished[0][2].toString()));
    QVERIFY(QFileInfo::exists(path));
    Command list;
    QSignalSpy listed(&list, &Command::finished);
    list.start(backend, {"list", "--vault", path, "--passphrase-fd", "198"},
               "disposable test passphrase", true);
    QTRY_COMPARE_WITH_TIMEOUT(listed.size(), 1, 10000);
    QVERIFY2(listed[0][0].toBool(), qPrintable(listed[0][2].toString()));
    QVERIFY(!listed[0][1].toByteArray().contains("disposable test passphrase"));
  }
  void readyWithoutTrayStaysAccessible() {
    if (QSystemTrayIcon::isSystemTrayAvailable())
      QSKIP("Requires no tray host");
    FakeService server;
    server.request = {};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    window.show();
    QTRY_COMPARE(window.findChild<QLabel *>("status")->text(),
                 QString("Ready"));
    QVERIFY(window.isVisible());
    QVERIFY(!window.findChild<QPushButton *>("hideToTray")->isVisible());
  }
  void independentPromptDiesWithOwner() {
    FakeService server;
    auto window =
        std::make_unique<Window>(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"),
                                 QString{}, server.path(), QString{});
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> dialog = visibleApproval();
    window.reset();
    QVERIFY(!dialog);
    QVERIFY(!visibleApproval());
    QVERIFY(server.commands.isEmpty());
  }
};

int main(int argc, char **argv) {
  if (argc == 2 && QByteArray(argv[1]) == "--child-parent-fixture") {
    QCoreApplication app(argc, argv);
    QProcess child;
    protectChild(child);
    child.start("/usr/bin/sleep", {"30"});
    if (!child.waitForStarted(2000))
      return 1;
    printf("%lld\n", static_cast<long long>(child.processId()));
    fflush(stdout);
    return app.exec();
  }
  QApplication app(argc, argv);
  QTemporaryDir settings;
  QSettings::setPath(QSettings::NativeFormat, QSettings::UserScope,
                     settings.path());
  DesktopTests tests;
  return QTest::qExec(&tests, argc, argv);
}
#include "tests.moc"
