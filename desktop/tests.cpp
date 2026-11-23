#include "notification_fixture.h"
#include "presentation.h"
#include "process.h"
#include "ui.h"
#include "window.h"
#include <QDBusPendingCallWatcher>
#include <QDialogButtonBox>
#include <QFile>
#include <QJsonArray>
#include <QJsonDocument>
#include <QLabel>
#include <QLineEdit>
#include <QLocalServer>
#include <QLocalSocket>
#include <QSignalSpy>
#include <QTableView>
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
  std::optional<bool> wakeAvailable;
  QJsonObject unlockPending;
  std::optional<bool> pinConfigured;
  QString credentialsRevision;
  QJsonArray stored;
  bool holdListing = false;
  QPointer<QLocalSocket> listingClient;
  QJsonObject listingRequest;
  QJsonObject listingOverride;
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
          if (command.value("command") == "credentials") {
            listingRequest = command;
            if (holdListing)
              listingClient = socket;
            else
              sendCredentials(socket, command);
            return;
          }
          if (command.value("command") == "unlock") {
            locked = false;
            unlockPending = {};
            publish();
          }
          if (command.value("command") == "deny" &&
              command.value("token") == unlockPending.value("token")) {
            unlockPending = {};
            publish();
          }
          if (command.value("command") == "session") {
            wakeAvailable = command.value("active").toBool();
            if (!*wakeAvailable) {
              locked = true;
              request = {};
              unlockPending = {};
            }
            publish();
          }
          if (command.value("command") == "configure_pin") {
            pinConfigured = true;
            publish();
          }
          if (command.value("command") == "lock") {
            locked = true;
            publish();
          }
          send(socket, {{"ok", true}, {"state", locked ? "locked" : "ready"}});
          socket->disconnectFromServer();
        }
      });
      connect(socket, &QLocalSocket::disconnected, socket,
              &QObject::deleteLater);
    });
  }
  QString path() const { return dir.path() + "/control.sock"; }
  void sendCredentials(QLocalSocket *socket, const QJsonObject &command) {
    if (!socket)
      return;
    QJsonObject response{{"ok", true},
                         {"state", "ready"},
                         {"credentials_revision", credentialsRevision}};
    if (!listingOverride.isEmpty())
      response = listingOverride;
    else if (locked ||
             command.value("revision").toString() != credentialsRevision)
      response = {{"ok", false},
                  {"state", locked ? "locked" : "ready"},
                  {"error", "The passkey list changed. Refresh to try again."}};
    else {
      auto offset = command.value("offset").toInt();
      QJsonArray rows;
      for (int i = offset; i < qMin(offset + 2, int(stored.size())); ++i)
        rows.append(stored[i]);
      int end = offset + int(rows.size());
      response["credentials"] = QJsonObject{
          {"items", rows},
          {"total", stored.size()},
          {"next_offset", end < stored.size() ? QJsonValue(end)
                                              : QJsonValue(QJsonValue::Null)}};
    }
    send(socket, response);
    socket->disconnectFromServer();
  }
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
    auto state = data["snapshot"].toObject();
    if (!locked && !credentialsRevision.isEmpty())
      state["credentials_revision"] = credentialsRevision;
    if (wakeAvailable)
      state["wake_available"] = *wakeAvailable;
    if (!unlockPending.isEmpty())
      state["unlock_request"] = unlockPending;
    data["snapshot"] = state;
    if (watcher)
      send(watcher, data);
  }
};

static QJsonObject storedPasskey(char id, QString site, QString username = {},
                                 QString name = {}) {
  return {{"credential_id", QString(64, QChar(id))},
          {"rp_id", site},
          {"name", username.isEmpty() ? QJsonValue(QJsonValue::Null)
                                      : QJsonValue(username)},
          {"display_name",
           name.isEmpty() ? QJsonValue(QJsonValue::Null) : QJsonValue(name)},
          {"user_handle", "012345"},
          {"discoverable", true},
          {"algorithm", -7}};
}

// Disposable Assuan prompt. It waits for the test to supply an answer, so
// cancellation and late secret delivery are exercised without a host desktop.
class SecretPromptFixture {
  QTemporaryDir dir;
  QByteArray path = qgetenv("PATH"), display = qgetenv("DISPLAY");

public:
  SecretPromptFixture() {
    QFile script(dir.path() + "/pinentry-qt");
    if (!script.open(QIODevice::WriteOnly))
      qFatal("cannot create secret fixture");
    script.write(QString("#!/usr/bin/python3\nimport sys, time, pathlib\n"
                         "print('OK', flush=True)\n"
                         "for line in sys.stdin:\n"
                         " if line.strip() == 'BYE': break\n"
                         " if line.strip() == 'GETPIN':\n"
                         "  p = pathlib.Path('%1')\n"
                         "  while not p.exists(): time.sleep(.01)\n"
                         "  print(p.read_text(), end='', flush=True)\n"
                         " else: print('OK', flush=True)\n")
                     .arg(answerPath())
                     .toUtf8());
    script.close();
    QFile::setPermissions(script.fileName(), QFile::ReadOwner |
                                                 QFile::WriteOwner |
                                                 QFile::ExeOwner);
    qputenv("PATH", QFile::encodeName(dir.path()) + ":" + path);
    qputenv("DISPLAY", ":yubiquity-test");
  }
  QString answerPath() const { return dir.path() + "/answer"; }
  void answer() {
    QFile file(answerPath());
    if (!file.open(QIODevice::WriteOnly))
      qFatal("cannot answer secret fixture");
    file.write("D disposable-test-passphrase\nOK\n");
  }
  ~SecretPromptFixture() {
    qputenv("PATH", path);
    qputenv("DISPLAY", display);
  }
};

class DesktopTests : public QObject {
  Q_OBJECT
private slots:
  void passkeysUnlockAndRefreshAfterVaultChanges() {
    SecretPromptFixture secret;
    FakeService server;
    server.locked = true;
    server.request = {};
    server.wakeAvailable = true;
    server.credentialsRevision = "catalog-1";
    server.stored = {storedPasskey('a', "old.example", "alice")};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    window.show();
    QTRY_VERIFY(server.watcher);
    window.findChild<QTabWidget *>("mainTabs")->setCurrentIndex(2);
    auto *table = window.findChild<QTableView *>("passkeysTable");
    QCOMPARE(table->model()->rowCount(), 0);
    window.findChild<QPushButton *>("passkeysUnlock")->click();
    secret.answer();
    QTRY_COMPARE(table->model()->rowCount(), 1);
    QVERIFY(window.isVisible());
    QCOMPARE(table->model()->index(0, 0).data().toString(),
             QString("old.example"));
    // A replacement with the same count must refresh too.
    server.credentialsRevision = "catalog-2";
    server.stored = {storedPasskey('b', "new.example", "bob")};
    server.publish();
    QTRY_COMPARE(table->model()->index(0, 0).data().toString(),
                 QString("new.example"));
    QCOMPARE(table->model()->rowCount(), 1);
  }

  void passkeysDisplaySearchAndDistinguishSameSiteAndAccount() {
    FakeService server;
    server.credentialsRevision = "catalog-1";
    server.stored = {
        storedPasskey('a', "example.test", "alice", "<b>Alice</b>\u202e"),
        storedPasskey('b', "example.test", "alice", "Alice"),
        storedPasskey('c', "another.test")};
    CredentialsPage page(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"));
    page.setContext(server.path(), true, server.credentialsRevision);
    page.show();
    auto *table = page.findChild<QTableView *>("passkeysTable");
    auto *search = page.findChild<QLineEdit *>("passkeysSearch");
    auto *details = page.findChild<QLabel *>("passkeyDetails");
    QTRY_COMPARE(table->model()->rowCount(), 3);
    QCOMPARE(table->model()->index(0, 0).data().toString(),
             QString("another.test"));
    search->setText("ALICE");
    QCOMPARE(table->model()->rowCount(), 2);
    search->setText(QString(64, 'a'));
    QCOMPARE(table->model()->rowCount(), 1);
    table->selectRow(0);
    QVERIFY(details->text().contains(QString(64, 'a')));
    QVERIFY(details->text().contains("<b>Alice</b>\\u202e"));
    QCOMPARE(details->textFormat(), Qt::PlainText);
    search->setText("another");
    QCOMPARE(table->model()->index(0, 1).data().toString(),
             QString("Not provided"));
    search->setText("absent");
    QCOMPARE(table->model()->rowCount(), 0);
    QVERIFY(details->text().isEmpty());
    page.setContext(server.path(), false, {});
    QVERIFY(search->text().isEmpty());
    QCOMPARE(table->model()->rowCount(), 0);
  }

  void passkeysClearOnLockAndIgnoreLateListingReply() {
    FakeService server;
    server.credentialsRevision = "catalog-1";
    server.stored = {storedPasskey('a', "old.example", "alice")};
    server.holdListing = true;
    CredentialsPage page(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"));
    page.setContext(server.path(), true, server.credentialsRevision);
    page.show();
    auto *table = page.findChild<QTableView *>("passkeysTable");
    QTRY_VERIFY(server.listingClient);
    page.setContext(server.path(), false, {});
    server.sendCredentials(server.listingClient, server.listingRequest);
    QTest::qWait(50);
    QCOMPARE(table->model()->rowCount(), 0);
    QVERIFY(page.findChild<QLabel *>("passkeyDetails")->text().isEmpty());
    server.holdListing = false;
    server.credentialsRevision = "catalog-2";
    server.stored = {storedPasskey('b', "new.example", "bob")};
    page.setContext(server.path(), true, server.credentialsRevision);
    QTRY_COMPARE(table->model()->rowCount(), 1);
    QCOMPARE(table->model()->index(0, 0).data().toString(),
             QString("new.example"));
    page.hide();
    QCOMPARE(table->model()->rowCount(), 0);
  }

  void passkeysRejectMalformedAndChangedPages() {
    FakeService server;
    server.credentialsRevision = "catalog-1";
    server.listingOverride = {
        {"ok", true},
        {"state", "ready"},
        {"credentials_revision", "catalog-1"},
        {"credentials",
         QJsonObject{{"items", QJsonArray{storedPasskey('a', "example.test")}},
                     {"total", 2},
                     {"next_offset", 0}}}};
    CredentialsPage page(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"));
    page.setContext(server.path(), true, server.credentialsRevision);
    page.show();
    auto *table = page.findChild<QTableView *>("passkeysTable");
    auto *status = page.findChild<QLabel *>("passkeysStatus");
    QTRY_VERIFY(status->text().contains("Invalid"));
    QCOMPARE(table->model()->rowCount(), 0);
    server.listingOverride["credentials_revision"] = "catalog-old";
    page.findChild<QPushButton *>("passkeysRefresh")->click();
    QTRY_VERIFY(status->text().contains("Invalid"));
    QCOMPARE(table->model()->rowCount(), 0);
    server.listingOverride = {};
    page.findChild<QPushButton *>("passkeysRefresh")->click();
    QTRY_VERIFY(status->text().contains("No passkeys"));
  }

  void passkeysClearAcrossWindowLifecycle_data() {
    QTest::addColumn<QString>("ending");
    for (const auto &ending : {"lock", "screen-lock", "suspend", "disconnect"})
      QTest::newRow(ending) << QString(ending);
  }
  void passkeysClearAcrossWindowLifecycle() {
    QFETCH(QString, ending);
    FakeService server;
    server.request = {};
    server.wakeAvailable = true;
    server.credentialsRevision = "catalog-1";
    server.stored = {storedPasskey('a', "example.test", "alice")};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    window.show();
    QTRY_VERIFY(server.watcher);
    auto *tabs = window.findChild<QTabWidget *>("mainTabs");
    tabs->setCurrentIndex(2);
    auto *table = window.findChild<QTableView *>("passkeysTable");
    QTRY_COMPARE(table->model()->rowCount(), 1);
    if (ending == "lock")
      window.findChild<QPushButton *>("lock")->click();
    else if (ending == "screen-lock")
      window.screenLocked(true);
    else if (ending == "suspend")
      window.sleepChanged(true);
    else
      server.watcher->disconnectFromServer();
    QTRY_COMPARE(table->model()->rowCount(), 0);
    QVERIFY(window.findChild<QLabel *>("passkeyDetails")->text().isEmpty());
  }

  void browserUnlockPromptsAndResumesWithoutApproving() {
    SecretPromptFixture secret;
    FakeService server;
    server.locked = true;
    server.wakeAvailable = true;
    server.request = {};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(server.watcher);
    window.hide();
    server.unlockPending = pending("wake-123");
    server.unlockPending["operation"] = "unlock";
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QCOMPARE(visibleApproval()->objectName(), QString("unlockRequestDialog"));
    QVERIFY(!window.isVisible());
    secret.answer();
    QTRY_VERIFY(!server.locked);
    QTRY_VERIFY(!visibleApproval());
    bool unlocked = false;
    for (const auto &command : server.commands) {
      QVERIFY(command["command"] != "approve");
      if (command["command"] == "unlock") {
        QCOMPARE(command["token"].toString(), QString("wake-123"));
        unlocked = true;
      }
    }
    QVERIFY(unlocked);
    server.request = pending("approval-456");
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QCOMPARE(visibleApproval()->token(), QString("approval-456"));
  }
  void browserUnlockCancellation_data() {
    QTest::addColumn<QString>("ending");
    for (const auto &ending :
         {"browser", "expired", "screen-lock", "suspend", "user"})
      QTest::newRow(ending) << QString(ending);
  }
  void browserUnlockCancellation() {
    QFETCH(QString, ending);
    SecretPromptFixture secret;
    FakeService server;
    server.locked = true;
    server.wakeAvailable = true;
    server.request = {};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(server.watcher);
    window.hide();
    server.unlockPending =
        pending("wake-cancel", ending == "expired" ? 250 : 30000);
    server.unlockPending["operation"] = "unlock";
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QTest::qWait(30);
    if (ending == "browser") {
      server.unlockPending = {};
      server.publish();
    } else if (ending == "screen-lock")
      window.screenLocked(true);
    else if (ending == "suspend")
      window.sleepChanged(true);
    else if (ending == "user")
      visibleApproval()->close();
    QTRY_VERIFY(!visibleApproval());
    secret.answer();
    QTest::qWait(100);
    for (const auto &command : server.commands) {
      QVERIFY(command["command"] != "unlock");
      QVERIFY(command["command"] != "approve");
    }
    QVERIFY(server.locked);
    QVERIFY(!window.isVisible());
    if (ending == "screen-lock" || ending == "suspend") {
      QTRY_COMPARE(server.wakeAvailable, std::optional<bool>(false));
      if (ending == "screen-lock")
        window.screenLocked(false);
      else
        window.sleepChanged(false);
      QTRY_COMPARE(server.wakeAvailable, std::optional<bool>(true));
      QVERIFY(server.locked);
      QVERIFY(!visibleApproval());
    }
  }
  void unlockSnapshotValidationAndDeadline() {
    SnapshotModel model;
    QString error;
    auto event = snapshotEvent(1);
    auto state = event["snapshot"].toObject();
    auto wake = pending("wake");
    wake["operation"] = "unlock";
    state["unlock_request"] = wake;
    state["wake_available"] = true;
    event["snapshot"] = state;
    QVERIFY(!model.update(event, error)); // ready state cannot request unlock
    state["state"] = "locked";
    event["sequence"] = 2;
    event["snapshot"] = state;
    QVERIFY(model.update(event, error));
    QCOMPARE(model.unlockRequest.token, QString("wake"));
    Pending request = model.unlockRequest;
    request.remaining = 150;
    ApprovalDialog dialog(request);
    QSignalSpy expired(&dialog, &ApprovalDialog::expired);
    dialog.show();
    QTest::qWait(75);
    dialog.shortenLifetime(30000);
    QTRY_COMPARE_WITH_TIMEOUT(expired.size(), 1, 300);
  }
  void init() {
    if (QByteArray(QTest::currentTestFunction()).startsWith("notification") &&
        !qEnvironmentVariableIsSet("YUBIQUITY_PRIVATE_TEST_BUS"))
      QSKIP("Run through CTest or dbus-run-session with "
            "YUBIQUITY_PRIVATE_TEST_BUS=1");
  }
  void notificationOwnershipReplacementAndPrivacy() {
    NotificationServer server;
    ApprovalNotification notification;
    QSignalSpy actions(&notification, &ApprovalNotification::activated);
    notification.show("PRIVATE-A");
    QTRY_COMPARE(server.requests.size(), 1);
    QTRY_VERIFY(
        notification.findChildren<QDBusPendingCallWatcher *>().isEmpty());
    const auto first = server.lastId;
    QCOMPARE(server.requests[0][1].toUInt(), uint(0));
    for (const auto &argument : server.requests[0])
      QVERIFY(!argument.toString().contains("PRIVATE-"));
    server.action(first + 100);
    server.action(first, "unexpected");
    server.dismiss(first + 100);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 0);
    server.action(first);
    QTRY_COMPARE(actions.size(), 1);
    QCOMPARE(actions[0][0].toString(), QString("PRIVATE-A"));
    notification.show("PRIVATE-B");
    QTRY_COMPARE(server.requests.size(), 2);
    QTRY_VERIFY(
        notification.findChildren<QDBusPendingCallWatcher *>().isEmpty());
    const auto second = server.lastId;
    QVERIFY(second != first);
    QCOMPARE(server.requests[1][1].toUInt(), uint(0));
    QTRY_VERIFY(server.closed.contains(first));
    server.action(first);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 1);
    server.action(second);
    QTRY_COMPARE(actions.size(), 2);
    QCOMPARE(actions[1][0].toString(), QString("PRIVATE-B"));
    server.dismiss(second);
    QTest::qWait(50);
    server.action(second);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 2);
  }
  void notificationUnlockCannotRestoreAfterCancellation() {
    SecretPromptFixture secret;
    NotificationServer notifications;
    FakeService server;
    server.locked = true;
    server.wakeAvailable = true;
    server.request = {};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(server.watcher);
    window.hide();
    server.unlockPending = pending("wake-notification");
    server.unlockPending["operation"] = "unlock";
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QTRY_COMPARE(notifications.requests.size(), 1);
    const auto id = notifications.lastId;
    server.unlockPending = {};
    server.publish();
    QTRY_VERIFY(!visibleApproval());
    QTRY_VERIFY(notifications.closed.contains(id));
    notifications.action(id);
    secret.answer();
    QTest::qWait(100);
    QVERIFY(!visibleApproval());
    QVERIFY(!window.isVisible());
    for (const auto &command : server.commands)
      QVERIFY(command["command"] != "unlock");
  }
  void notificationLateRepliesCannotReviveRequests() {
    NotificationServer server;
    server.hold = true;
    ApprovalNotification notification;
    QSignalSpy actions(&notification, &ApprovalNotification::activated);
    notification.show("A");
    QTRY_COMPARE(server.delayed.size(), 1);
    const auto first = server.lastId;
    notification.clear();
    notification.show("B");
    QTRY_COMPARE(server.delayed.size(), 2);
    server.reply();
    QTRY_VERIFY(server.closed.contains(first));
    server.action(first);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 0);
    notification.clear();
    server.reply();
    QTRY_VERIFY(server.closed.contains(server.lastId));
    server.action(server.lastId);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 0);
  }
  void notificationServerRestartAndReusedId() {
    NotificationServer oldServer;
    ApprovalNotification notification;
    QSignalSpy actions(&notification, &ApprovalNotification::activated);
    notification.show("A");
    QTRY_COMPARE(oldServer.requests.size(), 1);
    QTest::qWait(50);
    QVERIFY(oldServer.bus.unregisterService("org.freedesktop.Notifications"));
    NotificationServer newServer;
    QTest::qWait(50);
    // Both servers issue ID 1, but their unique bus owners differ.
    newServer.action(1);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 0);
    notification.show("B");
    QTRY_COMPARE(newServer.requests.size(), 1);
    QTest::qWait(50);
    QCOMPARE(oldServer.lastId, newServer.lastId);
    oldServer.action(1);
    QTest::qWait(50);
    QCOMPARE(actions.size(), 0);
    newServer.action(1);
    QTRY_COMPARE(actions.size(), 1);
    QCOMPARE(actions[0][0].toString(), QString("B"));
    QVERIFY(newServer.closed.isEmpty());
  }
  void notificationLateReplyFromReplacedServer() {
    NotificationServer oldServer;
    oldServer.hold = true;
    ApprovalNotification notification;
    QSignalSpy actions(&notification, &ApprovalNotification::activated);
    notification.show("A");
    QTRY_COMPARE(oldServer.delayed.size(), 1);
    QVERIFY(oldServer.bus.unregisterService("org.freedesktop.Notifications"));
    NotificationServer newServer;
    QTest::qWait(50);
    notification.show("B");
    QTRY_COMPARE(newServer.requests.size(), 1);
    oldServer.reply();
    QTRY_VERIFY(oldServer.closed.contains(1));
    QVERIFY(newServer.closed.isEmpty());
    newServer.action(1);
    QTRY_COMPARE(actions.size(), 1);
    QCOMPARE(actions[0][0].toString(), QString("B"));
  }
  void notificationRecallOnlyCurrentLiveApproval() {
    NotificationServer notifications;
    FakeService server;
    server.request = {};
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_COMPARE(window.findChild<QLabel *>("status")->text(),
                 QString("Ready"));
    window.hide();
    auto *tray = window.findChild<QSystemTrayIcon *>();
    QVERIFY(QMetaObject::invokeMethod(tray, "messageClicked"));
    notifications.action(123);
    QTest::qWait(50);
    QVERIFY(!window.isVisible());
    server.request = pending("A");
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> first = visibleApproval();
    QTRY_COMPARE(notifications.requests.size(), 1);
    const auto firstId = notifications.lastId;
    first->hide();
    notifications.action(firstId + 100);
    QVERIFY(QMetaObject::invokeMethod(tray, "messageClicked"));
    QTest::qWait(50);
    QVERIFY(!first->isVisible());
    notifications.action(firstId);
    QTRY_VERIFY(first->isVisible());
    QVERIFY(!window.isVisible());
    server.request = pending("B");
    server.publish();
    QTRY_VERIFY(!first);
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> second = visibleApproval();
    QTRY_COMPARE(notifications.requests.size(), 2);
    second->hide();
    notifications.action(firstId);
    QTest::qWait(50);
    QVERIFY(!second->isVisible());
    notifications.action(notifications.lastId);
    QTRY_VERIFY(second->isVisible());
    // Recall must reject an elapsed deadline even with its timer event queued.
    second->shortenLifetime(10);
    second->hide();
    QTest::qSleep(20);
    QVERIFY(!second->isLive());
    auto *notification = window.findChild<ApprovalNotification *>();
    notification->activated("B");
    QVERIFY(!second->isVisible());
    QVERIFY(!window.isVisible());
    QTRY_VERIFY(!second);
    QTRY_VERIFY(notifications.closed.contains(notifications.lastId));
    server.request = pending("C");
    server.publish();
    QTRY_VERIFY(visibleApproval());
    QTRY_COMPARE(notifications.requests.size(), 3);
    window.screenLocked(true);
    window.screenLocked(false);
    QTRY_VERIFY(notifications.closed.contains(notifications.lastId));
    notifications.action(notifications.lastId);
    QVERIFY(QMetaObject::invokeMethod(tray, "messageClicked"));
    QTest::qWait(50);
    QVERIFY(!visibleApproval());
    QVERIFY(!window.isVisible());
    QCOMPARE(window.findChild<QLabel *>("status")->text(), QString("Locked"));
    QVERIFY(server.commands.isEmpty());
    window.Show();
    QVERIFY(window.isVisible()); // Explicit application opening still works.
  }
  void notificationFailureDoesNotAffectApproval_data() {
    QTest::addColumn<int>("mode");
    QTest::newRow("absent") << 0;
    QTest::newRow("error") << 1;
    QTest::newRow("timeout") << 2;
  }
  void notificationEndsWithApproval_data() {
    QTest::addColumn<QString>("ending");
    for (const auto *name : {"cancelled", "approved", "denied", "disconnected",
                             "suspend", "manual-lock"})
      QTest::newRow(name) << QString(name);
  }
  void notificationEndsWithApproval() {
    QFETCH(QString, ending);
    NotificationServer notifications;
    FakeService server;
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> dialog = visibleApproval();
    QTRY_COMPARE(notifications.requests.size(), 1);
    if (ending == "cancelled") {
      server.request = {};
      server.publish();
    } else if (ending == "approved") {
      dialog->findChild<QPushButton *>("approve")->click();
    } else if (ending == "denied") {
      dialog->close();
    } else if (ending == "disconnected") {
      server.watcher->disconnectFromServer();
    } else if (ending == "suspend") {
      window.sleepChanged(true);
    } else {
      window.findChild<QPushButton *>("lock")->click();
    }
    QTRY_VERIFY(!dialog);
    QTRY_VERIFY(notifications.closed.contains(notifications.lastId));
    const bool commandExpected =
        ending == "approved" || ending == "denied" || ending == "manual-lock";
    if (commandExpected)
      QTRY_COMPARE(server.commands.size(), 1);
    // An explicit failure may present the main window; a subsequent stale
    // notification must not present it again after the user hides it.
    window.hide();
    notifications.action(notifications.lastId);
    QTest::qWait(50);
    QVERIFY(!window.isVisible());
    QVERIFY(!visibleApproval());
    QCOMPARE(server.commands.size(), commandExpected ? 1 : 0);
  }
  void notificationFailureDoesNotAffectApproval() {
    QFETCH(int, mode);
    std::unique_ptr<NotificationServer> notifications;
    if (mode) {
      notifications = std::make_unique<NotificationServer>();
      notifications->fail = mode == 1;
      notifications->hold = mode == 2;
    }
    FakeService server;
    Window window(qEnvironmentVariable("YUBIQUITY_TEST_BACKEND"), {},
                  server.path(), {});
    QTRY_VERIFY(visibleApproval());
    QPointer<ApprovalDialog> dialog = visibleApproval();
    window.hide();
    auto *notification = window.findChild<ApprovalNotification *>();
    QTRY_VERIFY_WITH_TIMEOUT(
        notification->findChildren<QDBusPendingCallWatcher *>().isEmpty(),
        4000);
    QVERIFY(dialog && dialog->isLive() && dialog->isVisible());
    QVERIFY(!window.isVisible());
    dialog->findChild<QPushButton *>("approve")->click();
    QTRY_COMPARE(server.commands.size(), 1);
    QCOMPARE(server.commands[0]["command"].toString(), QString("approve"));
    QCOMPARE(server.commands[0]["token"].toString(), QString("internal-123"));
  }
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
              QJsonObject{{"id", "uhid"},
                          {"title", "Security-key access"},
                          {"status", "ok"},
                          {"detail", "UHID is accessible."}},
              QJsonObject{
                  {"id", "hidraw"},
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
    // One actionable summary; raw process details stay behind a disclosure.
    page.showReport(
        {{"version", 1},
         {"repair_device", true},
         {"checks", QJsonArray{QJsonObject{
                        {"id", "uhid"},
                        {"title", "Security-key access"},
                        {"status", "attention"},
                        {"detail", "cannot open /dev/uhid\nGroups:\t1000"}}}}});
    QVERIFY(!page.findChild<QPushButton *>("setupDevice")->isHidden());
    auto summary = page.findChild<QLabel *>("setupChecks")->text();
    QVERIFY(summary.contains("No logout or reboot"));
    QVERIFY(!summary.contains("/dev/uhid"));
    QVERIFY(!summary.contains("Groups:"));
    QVERIFY(checks->isHidden());
    QVERIFY(checks->text().contains("Groups: 1000"));
    QVERIFY(!checks->text().contains("\\u0009"));
    page.findChild<QPushButton *>("setupShowDetails")->click();
    QVERIFY(!checks->isHidden());
    page.showReport(
        {{"version", 1},
         {"checks",
          QJsonArray{QJsonObject{{"id", "uhid"}, {"status", "ok"}},
                     QJsonObject{{"id", "hidraw"}, {"status", "ok"}}}}});
    QCOMPARE(page.findChild<QLabel *>("setupChecks")->text(),
             QString("Access is ready. Continue with your vault below."));
    QVERIFY(page.findChild<QPushButton *>("setupDevice")->isHidden());
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
