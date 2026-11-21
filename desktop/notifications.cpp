#include "notifications.h"
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDBusServiceWatcher>
#include <QVariantMap>

namespace {
const QString service = QStringLiteral("org.freedesktop.Notifications");
const QString path = QStringLiteral("/org/freedesktop/Notifications");
constexpr int callTimeout = 2000;
} // namespace

ApprovalNotification::ApprovalNotification(QObject *parent)
    : QObject(parent), bus(QDBusConnection::sessionBus()) {
  auto *watcher = new QDBusServiceWatcher(
      service, bus, QDBusServiceWatcher::WatchForOwnerChange, this);
  connect(watcher, &QDBusServiceWatcher::serviceOwnerChanged, this,
          &ApprovalNotification::clear);
  bus.connect(service, path, service, "ActionInvoked", this,
              SLOT(actionInvoked(uint, QString, QDBusMessage)));
  bus.connect(service, path, service, "NotificationClosed", this,
              SLOT(notificationClosed(uint, uint, QDBusMessage)));
}

ApprovalNotification::~ApprovalNotification() { clear(); }

void ApprovalNotification::close(const QString &serviceOwner, uint id) {
  if (serviceOwner.isEmpty() || !id)
    return;
  // Address the unique owner, never a replacement server that may reuse IDs.
  auto message = QDBusMessage::createMethodCall(serviceOwner, path, service,
                                                "CloseNotification");
  message << id;
  bus.asyncCall(message, callTimeout); // Best effort; state is already invalid.
}

void ApprovalNotification::clear() {
  const auto previousOwner = owner;
  const auto previousId = notificationId;
  ++generation; // Also invalidates outstanding GetNameOwner/Notify replies.
  request.clear();
  owner.clear();
  notificationId = 0;
  close(previousOwner, previousId);
}

void ApprovalNotification::show(const QString &requestToken, bool unlock) {
  clear();
  if (requestToken.isEmpty())
    return;
  request = requestToken;
  unlocking = unlock;
  const auto sequence = generation;
  // Resolve asynchronously and do not activate a missing notification service.
  auto message = QDBusMessage::createMethodCall(
      "org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus",
      "GetNameOwner");
  message << service;
  auto *call =
      new QDBusPendingCallWatcher(bus.asyncCall(message, callTimeout), this);
  connect(call, &QDBusPendingCallWatcher::finished, this,
          [this, call, sequence] {
            QDBusPendingReply<QString> reply = *call;
            call->deleteLater();
            if (sequence != generation)
              return;
            if (reply.isError() || reply.value().isEmpty()) {
              clear();
              return;
            }
            owner = reply.value();
            send(owner, sequence);
          });
}

void ApprovalNotification::send(const QString &serviceOwner, quint64 sequence) {
  auto message =
      QDBusMessage::createMethodCall(serviceOwner, path, service, "Notify");
  // A fresh ID for every request: an old notification must never become a new
  // approval's notification. The five-second display hint is not its validity.
  message << QStringLiteral("YubiQuity") << uint(0)
          << QStringLiteral("dialog-password") << tr("YubiQuity")
          << (unlocking
                  ? tr("Unlock YubiQuity to continue a security-key request.")
                  : tr("A passkey request needs your confirmation."))
          << QStringList{QStringLiteral("default"), tr("Show request")}
          << QVariantMap{{"desktop-entry",
                          QStringLiteral("org.yubiquity.Desktop")},
                         {"urgency", QVariant::fromValue(uchar(1))}}
          << 5000;
  auto *call =
      new QDBusPendingCallWatcher(bus.asyncCall(message, callTimeout), this);
  connect(call, &QDBusPendingCallWatcher::finished, this,
          [this, call, sequence, serviceOwner] {
            QDBusPendingReply<uint> reply = *call;
            call->deleteLater();
            if (sequence != generation) {
              if (!reply.isError())
                close(serviceOwner, reply.value());
              return;
            }
            if (reply.isError() || !reply.value()) {
              clear();
              return;
            }
            notificationId = reply.value();
          });
}

void ApprovalNotification::actionInvoked(uint id, const QString &action,
                                         const QDBusMessage &message) {
  if (!notificationId || id != notificationId || message.service() != owner)
    return;
  if (action == "default")
    emit activated(request);
}

void ApprovalNotification::notificationClosed(uint id, uint,
                                              const QDBusMessage &message) {
  if (!notificationId || id != notificationId || message.service() != owner)
    return;
  notificationId = 0; // Already closed; do not send CloseNotification back.
  clear();            // Closing a notification never decides an approval.
}
