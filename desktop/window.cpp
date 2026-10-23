#include "window.h"
#include "presentation.h"
#include <QApplication>
#include <QCloseEvent>
#include <QDBusConnection>
#include <QDBusMessage>
#include <QDBusPendingCallWatcher>
#include <QDBusPendingReply>
#include <QDir>
#include <QFileDialog>
#include <QFileInfo>
#include <QJsonDocument>
#include <QMenu>
#include <QStandardPaths>
#include <QStyle>
#include <QVBoxLayout>
#include <sys/stat.h>
#include <unistd.h>

Window::Window(QString executable, QString vaultPath, QString socketPath,
               QString helperPath)
    : backend(std::move(executable)), vault(std::move(vaultPath)),
      externalSocket(std::move(socketPath)), helper(std::move(helperPath)) {
  setWindowTitle(tr("YubiQuity"));
  setWindowIcon(QIcon::fromTheme(
      "dialog-password", style()->standardIcon(QStyle::SP_ComputerIcon)));
  resize(520, 360);
  auto *body = new QWidget;
  auto *layout = new QVBoxLayout(body);
  status = new QLabel(tr("Locked"));
  status->setObjectName("status");
  auto font = status->font();
  font.setPointSize(font.pointSize() + 6);
  status->setFont(font);
  detail =
      new QLabel(tr("Unlock your vault, then use a passkey in your browser. "
                    "Requests open a separate confirmation window."));
  detail->setObjectName("detail");
  vaultLabel = new QLabel;
  sessionNote = new QLabel;
  for (auto *label : {status, detail, vaultLabel, sessionNote}) {
    label->setTextFormat(Qt::PlainText);
    label->setWordWrap(true);
    layout->addWidget(label);
  }
  unlock = new QPushButton(tr("Unlock"));
  unlock->setObjectName("unlock");
  lock = new QPushButton(tr("Lock"));
  lock->setObjectName("lock");
  choose = new QPushButton(tr("Open existing vault…"));
  create = new QPushButton(tr("Create new vault…"));
  for (auto *button : {unlock, lock, choose, create})
    layout->addWidget(button);
  auto *explanation =
      new QLabel(tr("The vault passphrase unlocks your saved passkeys. Your "
                    "browser may also ask for the security-key PIN. Clicking "
                    "Approve replaces touching a physical key."));
  explanation->setWordWrap(true);
  layout->addWidget(explanation);
  hideToTray = new QPushButton(tr("Hide to tray"));
  hideToTray->setObjectName("hideToTray");
  layout->addWidget(hideToTray);
  auto *quit = new QPushButton(tr("Lock and quit"));
  layout->addWidget(quit);
  setCentralWidget(body);
  tray = new QSystemTrayIcon(windowIcon(), this);
  tray->setToolTip(tr("YubiQuity — locked"));
  auto *menu = new QMenu(this);
  menu->addAction(tr("Show YubiQuity"), this, &Window::Show);
  menu->addAction(tr("Lock"), this, &Window::lockVault);
  menu->addSeparator();
  menu->addAction(tr("Lock and quit"), qApp, &QApplication::quit);
  tray->setContextMenu(menu);
  connect(tray, &QSystemTrayIcon::activated, this,
          [this](QSystemTrayIcon::ActivationReason reason) {
            if (reason == QSystemTrayIcon::Trigger ||
                reason == QSystemTrayIcon::DoubleClick)
              Show();
          });
  connect(tray, &QSystemTrayIcon::messageClicked, this, &Window::Show);
  // Qt registers the visible icon if a tray host appears later. Do not hide a
  // window unless a host is actually available, however.
  tray->show();
  connect(hideToTray, &QPushButton::clicked, this, &Window::hideInTray);
  connect(quit, &QPushButton::clicked, qApp, &QApplication::quit);
  connect(unlock, &QPushButton::clicked, this, [this] {
    if (model.state == "locked")
      promptSecret();
    else
      startService(true);
  });
  connect(lock, &QPushButton::clicked, this, &Window::lockVault);
  connect(choose, &QPushButton::clicked, this, [this] { selectVault(false); });
  connect(create, &QPushButton::clicked, this, [this] { selectVault(true); });
  connect(&service, &QProcess::readyReadStandardOutput, this,
          [this] { service.readAllStandardOutput(); });
  connect(&service, &QProcess::readyReadStandardError, this, [this] {
    serviceError += service.readAllStandardError();
    serviceError = serviceError.right(16384);
  });
  connect(&service, &QProcess::finished, this, [this] {
    if (!stopping)
      failure(tr("The device service stopped.\n%1")
                  .arg(QString::fromUtf8(serviceError).trimmed()));
  });
  connect(
      &service, &QProcess::errorOccurred, this,
      [this](QProcess::ProcessError error) {
        if (error == QProcess::FailedToStart && !stopping)
          failure(
              tr("Could not start %1: %2").arg(backend, service.errorString()));
      });
  connect(&watch, &QProcess::readyReadStandardOutput, this,
          &Window::readSnapshots);
  connect(&watch, &QProcess::finished, this, [this] {
    if (!stopping)
      failure(
          tr("Desktop connection closed. No requests can be approved here.\n%1")
              .arg(QString::fromUtf8(watch.readAllStandardError()).trimmed()));
  });
  connect(&watch, &QProcess::errorOccurred, this,
          [this](QProcess::ProcessError error) {
            if (error == QProcess::FailedToStart && !stopping)
              failure(tr("Could not start the local control client."));
          });
  startup.setInterval(25);
  connect(&startup, &QTimer::timeout, this, [this] {
    if (QFileInfo::exists(socket)) {
      startup.stop();
      startWatch();
    } else if (++startupAttempts > 200)
      failure(tr("The device service did not become ready.\n%1")
                  .arg(QString::fromUtf8(serviceError)));
  });
  heartbeat.setSingleShot(true);
  connect(&heartbeat, &QTimer::timeout, this, [this] {
    failure(
        tr("The device service stopped responding. The key is being locked."));
  });
  if (vault.isEmpty() && externalSocket.isEmpty())
    vault = settings.value("vault").toString();
  vaultLabel->setText(externalSocket.isEmpty()
                          ? tr("Vault: %1").arg(displayText(vault))
                          : tr("Connected to an existing local service"));
  monitorSession();
  updateButtons();
  if (!vault.isEmpty() || !externalSocket.isEmpty())
    QTimer::singleShot(0, this, [this] { startService(); });
}

Window::~Window() { stopService(); }

void Window::Show() {
  if (approval) {
    presentWindow(*approval);
    return;
  }
  presentWindow(*this);
}

void Window::hideInTray() {
  if (QSystemTrayIcon::isSystemTrayAvailable())
    hide();
}

void Window::changeEvent(QEvent *event) {
  QMainWindow::changeEvent(event);
  if (event->type() == QEvent::WindowStateChange && isMinimized()) {
    QTimer::singleShot(0, this, [this] {
      if (isMinimized())
        hideInTray();
    });
  }
}

void Window::closeEvent(QCloseEvent *event) {
  if (QSystemTrayIcon::isSystemTrayAvailable()) {
    hide();
    event->ignore();
  } else {
    stopService();
    event->accept();
    qApp->quit();
  }
}

void Window::setBusy(bool value) {
  busy = value;
  updateButtons();
}

void Window::updateButtons() {
  unlock->setEnabled(!busy && !sessionLocked && model.state != "ready" &&
                     (!vault.isEmpty() || !externalSocket.isEmpty()));
  lock->setEnabled(model.state == "ready" || busy);
  choose->setEnabled(!busy && model.state != "ready" &&
                     externalSocket.isEmpty());
  create->setEnabled(choose->isEnabled());
  hideToTray->setVisible(QSystemTrayIcon::isSystemTrayAvailable());
}

void Window::startService(bool askUnlock) {
  stopService();
  unlockOnConnect = askUnlock;
  status->setText(tr("Connecting…"));
  setBusy(true);
  serviceError.clear();
  if (!externalSocket.isEmpty()) {
    socket = externalSocket;
    startWatch();
    return;
  }
  if (!QFileInfo(vault).isFile()) {
    failure(tr("The selected vault is missing. Open an existing vault or "
               "explicitly create a new one. Nothing has been replaced."));
    return;
  }
  auto base = QStandardPaths::writableLocation(QStandardPaths::RuntimeLocation);
  struct stat info {};
  auto encoded = QFile::encodeName(base);
  if (lstat(encoded.constData(), &info) != 0 || !S_ISDIR(info.st_mode) ||
      info.st_uid != geteuid() || (info.st_mode & 0777) != 0700) {
    failure(tr("Your desktop runtime directory must be owned by you with mode "
               "0700. Launch from your normal desktop session."));
    return;
  }
  runtime = std::make_unique<QTemporaryDir>(base + "/yubiquity-XXXXXX");
  if (!runtime->isValid()) {
    failure(tr("Could not create a private runtime directory."));
    return;
  }
  socket = runtime->path() + "/control.sock";
  QStringList arguments{"serve", "--vault", vault, "--socket", socket};
  if (!helper.isEmpty())
    arguments << "--node-helper" << helper;
  protectChild(service);
  service.start(backend, arguments);
  service.closeWriteChannel();
  startupAttempts = 0;
  startup.start();
}

void Window::startWatch() {
  model = SnapshotModel{};
  watchBuffer.clear();
  protectChild(watch);
  watch.start(backend, {"control", "--socket", socket, "watch"});
  watch.closeWriteChannel();
  heartbeat.start(22000);
}

void Window::stopService() {
  if (stopping)
    return;
  stopping = true;
  startup.stop();
  heartbeat.stop();
  dismissApproval();
  if (pinentry)
    pinentry->cancel();
  if (command)
    command->cancel();
  // Closing the watch lease is the fail-closed path even if a command or the
  // service is wedged. Owned children are also terminated, then bounded-killed.
  for (auto *process : {&watch, &service}) {
    if (process->state() != QProcess::NotRunning) {
      process->terminate();
      if (!process->waitForFinished(750)) {
        process->kill();
        process->waitForFinished(750);
      }
    }
  }
  runtime.reset();
  watchBuffer.clear();
  erase(heldSecret);
  model = SnapshotModel{};
  dismissedToken.clear();
  displayedState.clear();
  hideWhenReady = false;
  tray->setToolTip(tr("YubiQuity — locked"));
  busy = false;
  stopping = false;
  updateButtons();
}

void Window::failure(const QString &message) {
  stopService();
  status->setText(tr("Not connected"));
  detail->setText(message);
  tray->setToolTip(tr("YubiQuity — not connected"));
  Show();
}

void Window::readSnapshots() {
  if (stopping) {
    watch.readAllStandardOutput();
    return;
  }
  watchBuffer += watch.readAllStandardOutput();
  if (watchBuffer.size() > 65536) {
    failure(tr("Oversized service response."));
    return;
  }
  while (watchBuffer.contains('\n')) {
    auto end = watchBuffer.indexOf('\n');
    if (end > 8192) {
      failure(tr("Oversized service snapshot."));
      return;
    }
    auto line = watchBuffer.left(end);
    watchBuffer.remove(0, end + 1);
    QJsonParseError parse;
    const auto event = QJsonDocument::fromJson(line, &parse);
    QString error;
    const bool initial = model.state.isEmpty();
    if (parse.error != QJsonParseError::NoError || !event.isObject() ||
        !model.update(event.object(), error)) {
      failure(error.isEmpty() ? tr("Invalid service response.") : error);
      return;
    }
    heartbeat.start(22000);
    if (initial) {
      setBusy(false);
      if (externalSocket.isEmpty())
        settings.setValue("vault", vault);
    }
    applySnapshot();
    if (initial && model.state == "locked") {
      if (!heldSecret.isEmpty()) {
        auto secret = heldSecret;
        heldSecret.clear();
        unlockWith(secret);
        erase(secret);
      } else if (unlockOnConnect) {
        unlockOnConnect = false;
        promptSecret();
      }
    }
  }
}

void Window::dismissApproval() {
  if (!approval)
    return;
  approval->disconnect(this);
  approval->hide();
  // It is deliberately not a child/transient of the vault window. Reparent only
  // AFTER hiding and disconnecting, so QObject also cleans it up at app
  // shutdown if the event loop has already stopped before deleteLater is
  // processed.
  approval->setParent(this);
  approval->deleteLater();
  approval = nullptr;
}

void Window::applySnapshot() {
  updateButtons();
  if (sessionLocked) {
    if (model.state == "ready")
      lockVault();
    return;
  }
  status->setText(model.state == "ready" ? tr("Ready") : tr("Locked"));
  tray->setToolTip(model.state == "ready" ? tr("YubiQuity — ready")
                                          : tr("YubiQuity — locked"));
  if (displayedState != model.state) {
    hideWhenReady = model.state == "ready";
    displayedState = model.state;
    detail->setText(
        model.state == "ready"
            ? tr("Choose “Security key” in your browser. A confirmation will "
                 "open when it needs your approval.")
            : tr("Unlock to make your software security key available to "
                 "browsers."));
  }
  if (hideWhenReady && !busy) {
    hideWhenReady = false;
    hideInTray(); // Once per ready transition, never on every heartbeat.
  }
  if (model.pending.token.isEmpty()) {
    dismissApproval();
    dismissedToken.clear();
    return;
  }
  if (busy) {
    dismissApproval();
    return;
  }
  status->setText(tr("Approval requested"));
  tray->setToolTip(tr("YubiQuity — approval requested"));
  if (model.pending.token == dismissedToken)
    return;
  if (approval && approval->token() == model.pending.token) {
    approval->shortenLifetime(model.pending.remaining);
    return;
  }
  dismissApproval();
  approval = new ApprovalDialog(model.pending);
  connect(approval, &ApprovalDialog::expired, this, [this] {
    if (approval)
      dismissedToken = approval->token();
    dismissApproval();
    detail->setText(tr("The request expired. Try again in your browser."));
  });
  connect(
      approval, &ApprovalDialog::decision, this,
      [this](const QString &token, bool yes) {
        dismissedToken = token;
        dismissApproval();
        if (sessionLocked || busy || model.pending.token != token)
          return;
        setBusy(true);
        runCommand(
            {"control", "--socket", socket, yes ? "approve" : "deny", token},
            {}, false, [this](bool ok, QByteArray, const QString &error) {
              setBusy(false);
              if (!ok)
                detail->setText(tr("The request is no longer available or was "
                                   "rejected. Nothing else was approved.\n%1")
                                    .arg(error));
            });
      });
  presentWindow(*approval);
  if (QSystemTrayIcon::isSystemTrayAvailable())
    tray->showMessage(tr("YubiQuity"),
                      tr("A passkey request needs your confirmation."),
                      QSystemTrayIcon::Information, 5000);
}

void Window::runCommand(const QStringList &arguments, QByteArray secret,
                        bool secretInput,
                        std::function<void(bool, QByteArray, QString)> done) {
  auto *job = new Command(this);
  command = job;
  connect(job, &Command::finished, this,
          [this, job, done](bool ok, const QByteArray &output,
                            const QString &error) {
            if (command == job)
              command = nullptr;
            job->deleteLater();
            if (!stopping)
              done(ok, output, error);
          });
  job->start(backend, arguments, secret, secretInput);
  erase(secret);
}

void Window::promptSecret(bool newVault) {
  if (busy || sessionLocked)
    return;
  setBusy(true);
  auto *prompt = new Pinentry(this);
  pinentry = prompt;
  connect(prompt, &Pinentry::failed, this,
          [this, prompt](const QString &message) {
            pinentry = nullptr;
            prompt->deleteLater();
            if (!stopping) {
              setBusy(false);
              detail->setText(message);
            }
          });
  connect(prompt, &Pinentry::secretReady, this,
          [this, prompt, newVault](QByteArray secret) {
            pinentry = nullptr;
            prompt->deleteLater();
            if (sessionLocked || stopping) {
              erase(secret);
              return;
            }
            if (!newVault) {
              unlockWith(secret);
              erase(secret);
              return;
            }
            // Retain only until the new vault is opened; no second unlock
            // prompt.
            heldSecret = secret;
            runCommand({"init", "--vault", vault, "--passphrase-fd", "198"},
                       secret, true,
                       [this](bool ok, QByteArray, const QString &error) {
                         if (!ok) {
                           erase(heldSecret);
                           setBusy(false);
                           detail->setText(error);
                           return;
                         }
                         settings.setValue("vault", vault);
                         auto secret = heldSecret;
                         heldSecret.clear();
                         startService();
                         if (service.state() != QProcess::NotRunning)
                           heldSecret = secret;
                         erase(secret);
                       });
            erase(secret);
          });
  prompt->start(newVault);
}

void Window::unlockWith(QByteArray secret) {
  setBusy(true);
  status->setText(tr("Unlocking…"));
  runCommand(
      {"control", "--socket", socket, "unlock", "--passphrase-fd", "198"},
      secret, true, [this](bool ok, QByteArray, const QString &error) {
        setBusy(false);
        if (!ok) {
          status->setText(tr("Locked"));
          detail->setText(
              tr("Unlock failed. Check the vault passphrase and try again.\n%1")
                  .arg(error));
        } else
          applySnapshot();
      });
  erase(secret);
}

void Window::selectVault(bool newVault) {
  auto defaultDirectory =
      QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation) +
      "/yubiquity/vault";
  // Explicit creation action only. umask is 0077; do not chmod existing paths.
  // The Rust vault preflight still validates every ancestor at actual use time.
  if (newVault && !QDir().mkpath(defaultDirectory)) {
    detail->setText(tr("Could not create the application data directory. Check "
                       "its permissions."));
    return;
  }
  auto path = newVault ? QFileDialog::getSaveFileName(
                             this, tr("Create a new encrypted vault"),
                             defaultDirectory + "/credentials.yq",
                             tr("YubiQuity vault (*.yq)"))
                       : QFileDialog::getOpenFileName(
                             this, tr("Open an existing encrypted vault"),
                             QFileInfo(vault).absolutePath(),
                             tr("YubiQuity vault (*.yq);;All files (*)"));
  if (path.isEmpty())
    return;
  if (newVault && QFileInfo::exists(path)) {
    detail->setText(tr("That file already exists. It will not be overwritten. "
                       "Choose a new name or open the existing vault."));
    return;
  }
  stopService();
  vault = QFileInfo(path).absoluteFilePath();
  vaultLabel->setText(tr("Vault: %1").arg(displayText(vault)));
  if (newVault)
    promptSecret(true);
  else {
    settings.setValue("vault", vault);
    startService(true);
  }
}

void Window::lockVault() {
  if (busy || model.state.isEmpty()) {
    stopService();
    status->setText(tr("Locked"));
    detail->setText(tr("Unlock when you are ready to use the key again."));
    return;
  }
  dismissApproval();
  setBusy(true);
  runCommand({"control", "--socket", socket, "lock"}, {}, false,
             [this](bool ok, QByteArray, const QString &error) {
               setBusy(false);
               if (!ok)
                 failure(tr("Lock could not be confirmed.\n%1").arg(error));
             });
}

void Window::screenLocked(bool locked) {
  sessionLocked = locked;
  if (locked) {
    stopService();
    status->setText(tr("Locked"));
  }
  updateButtons();
}

void Window::sleepChanged(bool sleeping) {
  if (sleeping) {
    stopService();
    status->setText(tr("Locked"));
  }
}

void Window::monitorSession() {
  sessionNote->setText(
      tr("Session-lock monitoring unavailable until a desktop screen-lock "
         "service responds. You can always Lock manually."));
  auto bus = QDBusConnection::sessionBus();
  for (const auto &name : {QString("org.freedesktop.ScreenSaver"),
                           QString("org.gnome.ScreenSaver")}) {
    const auto path = name == "org.gnome.ScreenSaver" ? "/org/gnome/ScreenSaver"
                                                      : "/ScreenSaver";
    bus.connect(name, path, name, "ActiveChanged", this,
                SLOT(screenLocked(bool)));
    auto query = QDBusMessage::createMethodCall(name, path, name, "GetActive");
    auto *pending = new QDBusPendingCallWatcher(bus.asyncCall(query), this);
    connect(pending, &QDBusPendingCallWatcher::finished, this, [this, pending] {
      QDBusPendingReply<bool> reply = *pending;
      if (!reply.isError()) {
        sessionNote->setText(tr("Locks when the desktop reports screen lock. "
                                "After restart or sleep, unlock explicitly."));
        if (reply.value())
          screenLocked(true);
      }
      pending->deleteLater();
    });
  }
  QDBusConnection::systemBus().connect(
      "org.freedesktop.login1", "/org/freedesktop/login1",
      "org.freedesktop.login1.Manager", "PrepareForSleep", this,
      SLOT(sleepChanged(bool)));
}
