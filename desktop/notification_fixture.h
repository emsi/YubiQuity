#pragma once
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusVirtualObject>
#include <QUuid>

// Test-only notification server. Run on a private session bus, never the host.
class NotificationServer : public QDBusVirtualObject {
public:
  const QString name = QUuid::createUuid().toString();
  QDBusConnection bus =
      QDBusConnection::connectToBus(QDBusConnection::SessionBus, name);
  QList<QList<QVariant>> requests;
  QList<uint> closed;
  QList<QPair<QDBusMessage, uint>> delayed;
  bool hold = false, fail = false;
  uint lastId = 0;
  NotificationServer() {
    if (!qEnvironmentVariableIsSet("YUBIQUITY_PRIVATE_TEST_BUS") ||
        !bus.registerVirtualObject("/org/freedesktop/Notifications", this) ||
        !bus.registerService("org.freedesktop.Notifications"))
      qFatal("notification fixture requires an unused private session bus");
  }
  ~NotificationServer() override {
    bus.unregisterService("org.freedesktop.Notifications");
    bus.unregisterObject("/org/freedesktop/Notifications");
    QDBusConnection::disconnectFromBus(name);
  }
  QString introspect(const QString &) const override { return {}; }
  bool handleMessage(const QDBusMessage &message,
                     const QDBusConnection &connection) override {
    if (message.member() == "Notify") {
      requests.append(message.arguments());
      if (fail) {
        connection.send(message.createErrorReply(
            "org.freedesktop.DBus.Error.Failed", "fixture"));
      } else {
        const auto id = ++lastId;
        if (hold)
          delayed.append({message, id});
        else
          connection.send(message.createReply(QVariantList{id}));
      }
      return true;
    }
    if (message.member() == "CloseNotification") {
      const auto id = message.arguments()[0].toUInt();
      closed.append(id);
      connection.send(message.createReply());
      dismiss(id);
      return true;
    }
    return false;
  }
  void reply() {
    const auto pending = delayed.takeFirst();
    bus.send(pending.first.createReply(QVariantList{pending.second}));
  }
  void action(uint id, const QString &key = "default") {
    auto message = QDBusMessage::createSignal("/org/freedesktop/Notifications",
                                              "org.freedesktop.Notifications",
                                              "ActionInvoked");
    message << id << key;
    bus.send(message);
  }
  void dismiss(uint id) {
    auto message = QDBusMessage::createSignal("/org/freedesktop/Notifications",
                                              "org.freedesktop.Notifications",
                                              "NotificationClosed");
    message << id << uint(2);
    bus.send(message);
  }
};
