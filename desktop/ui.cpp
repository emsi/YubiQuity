#include "ui.h"
#include <QDialogButtonBox>
#include <QLabel>
#include <QScrollArea>
#include <QStyle>
#include <QVBoxLayout>
#include <algorithm>

QString displayText(const QString &value) {
  QString result;
  // Preserve the actual text but make invisible controls explicit. In
  // particular, a site/account must not change surrounding text direction.
  for (const auto c : value) {
    if (c.category() == QChar::Other_Control ||
        c.category() == QChar::Other_Format || c == QChar::LineSeparator ||
        c == QChar::ParagraphSeparator)
      result +=
          QStringLiteral("\\u%1").arg(c.unicode(), 4, 16, QLatin1Char('0'));
    else
      result += c;
  }
  return result;
}

bool SnapshotModel::update(const QJsonObject &event, QString &error) {
  const auto seq = event.value("sequence").toInteger(-1);
  const auto snapshot = event.value("snapshot").toObject();
  const auto nextState = snapshot.value("state").toString();
  if (event.value("version").toInteger(-1) != 1 || seq <= sequence ||
      !snapshot.value("ok").isBool() || !snapshot.value("ok").toBool() ||
      (nextState != "locked" && nextState != "ready")) {
    error = QStringLiteral(
        "Incompatible or out-of-order desktop service response.");
    return false;
  }
  Pending next;
  if (snapshot.contains("pending")) {
    const auto p = snapshot.value("pending").toObject();
    next = {
        p.value("token").toString(),   p.value("operation").toString(),
        p.value("rp_id").toString(),   p.value("account").toString(),
        p.value("account").isString(), p.value("remaining_ms").toInteger(-1)};
    if (nextState != "ready" || next.token.isEmpty() ||
        next.token.size() > 128 || !p.value("rp_id").isString() ||
        (!p.value("account").isNull() && !p.value("account").isString()) ||
        next.remaining < 0 || next.remaining > 30000 ||
        !QStringList{"register", "authenticate", "select-device", "reset"}
             .contains(next.operation)) {
      error = QStringLiteral(
          "Unsupported or expired approval request. Nothing was approved.");
      return false;
    }
    if (next.operation != "reset" && next.rp.isEmpty()) {
      error = QStringLiteral("The approval request is missing its site.");
      return false;
    }
    if (pending.token == next.token &&
        (pending.operation != next.operation || pending.rp != next.rp ||
         pending.account != next.account ||
         pending.hasAccount != next.hasAccount)) {
      error = QStringLiteral(
          "The pending request changed unexpectedly. Nothing was approved.");
      return false;
    }
  }
  sequence = seq;
  state = nextState;
  pending = next;
  return true;
}

ApprovalDialog::ApprovalDialog(const Pending &pending)
    // No transient parent or group-transient dialog: the vault window may be
    // hidden on another workspace. This request gets its own taskbar entry and
    // normal top-level placement on both X11 and Wayland. Window owns its
    // lifetime.
    : QDialog(nullptr, Qt::Window | Qt::WindowTitleHint |
                           Qt::WindowSystemMenuHint |
                           Qt::WindowCloseButtonHint),
      request(pending), deadline(pending.remaining) {
  setObjectName("approvalDialog");
  setWindowIcon(QIcon::fromTheme(
      "dialog-password", style()->standardIcon(QStyle::SP_ComputerIcon)));
  setWindowTitle(request.operation == "register" ? tr("Create a passkey")
                 : request.operation == "authenticate"
                     ? tr("Sign in with a passkey")
                 : request.operation == "reset" ? tr("Reset YubiQuity?")
                                                : tr("Use YubiQuity"));
  setWindowModality(Qt::NonModal);
  auto *layout = new QVBoxLayout(this);
  auto *content = new QWidget;
  auto *fields = new QVBoxLayout(content);
  auto field = [fields](const QString &text) {
    auto *label = new QLabel(text);
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    label->setTextInteractionFlags(Qt::TextSelectableByMouse |
                                   Qt::TextSelectableByKeyboard);
    label->setLayoutDirection(Qt::LeftToRight);
    fields->addWidget(label);
    return label;
  };
  if (request.operation == "reset")
    field(tr("Delete ALL passkeys and the security-key PIN in this vault? This "
             "cannot be undone."));
  else {
    field(request.operation == "register"
              ? tr("Approve creating a passkey on this site?")
          : request.operation == "authenticate"
              ? tr("Approve signing in to this site?")
              : tr("Allow this site to select YubiQuity as its security key?"));
    auto *site = field(tr("Site: %1").arg(displayText(request.rp)));
    site->setObjectName("site");
    field(request.hasAccount
              ? tr("Account: %1").arg(displayText(request.account))
              : tr("Account: not provided or not yet selected"));
  }
  field(tr("Approve only if you started this request. This confirmation "
           "replaces touching a physical security key."));
  auto *scroll = new QScrollArea;
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  scroll->setWidget(content);
  layout->addWidget(scroll);
  auto *buttons = new QDialogButtonBox;
  approve = buttons->addButton(
      request.operation == "reset" ? tr("Delete all passkeys") : tr("Approve"),
      QDialogButtonBox::AcceptRole);
  approve->setObjectName("approve");
  approve->setAutoDefault(false);
  auto *cancel = buttons->addButton(QDialogButtonBox::Cancel);
  cancel->setDefault(true);
  cancel->setFocus();
  connect(approve, &QPushButton::clicked, this, [this] { choose(true); });
  connect(cancel, &QPushButton::clicked, this, &ApprovalDialog::reject);
  layout->addWidget(buttons);
  resize(500, 320);
  elapsed.start();
  timeout.setSingleShot(true);
  connect(&timeout, &QTimer::timeout, this, [this] {
    if (decided)
      return;
    decided = true;
    approve->setEnabled(false);
    hide();
    emit expired();
  });
  timeout.start(int(deadline));
}

void ApprovalDialog::shortenLifetime(qint64 remaining) {
  deadline = std::min(deadline, elapsed.elapsed() + remaining);
  if (!decided)
    timeout.start(int(std::max(qint64(0), deadline - elapsed.elapsed())));
}

void ApprovalDialog::choose(bool yes) {
  if (decided)
    return;
  if (elapsed.elapsed() >= deadline) {
    decided = true;
    hide();
    emit expired();
    return;
  }
  decided = true;
  timeout.stop();
  approve->setEnabled(false);
  hide();
  emit decision(request.token, yes);
}

void ApprovalDialog::reject() { choose(false); }
