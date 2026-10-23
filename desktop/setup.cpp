#include "setup.h"
#include "ui.h"
#include <QDesktopServices>
#include <QGroupBox>
#include <QHBoxLayout>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QScrollArea>
#include <QUrl>
#include <QVBoxLayout>
#include <sys/stat.h>

namespace {
QString diagnosticText(const QString &text) {
  QStringList lines;
  for (const auto &line : text.split('\n'))
    lines << displayText(line);
  return lines.join("\n");
}
bool installedHelper() {
  // Never elevate a helper from a checkout, PATH, or a user-writable location.
  for (const char *path :
       {"/", "/usr", "/usr/sbin", "/usr/sbin/yubiquity-setup"}) {
    struct stat meta {};
    if (stat(path, &meta) || meta.st_uid != 0 || (meta.st_mode & 0022))
      return false;
  }
  struct stat meta {};
  const bool executable = !lstat("/usr/sbin/yubiquity-setup", &meta) &&
                          S_ISREG(meta.st_mode) && (meta.st_mode & 0111);
  // v0.1.0's helper lacks the desktop verbs and policy. Do not offer it as a
  // working repair when a source build is launched over that older package.
  return executable &&
         !lstat("/usr/share/polkit-1/actions/org.yubiquity.setup.policy",
                &meta) &&
         S_ISREG(meta.st_mode) && meta.st_uid == 0 && !(meta.st_mode & 0022);
}
QLabel *label(const QString &text, QVBoxLayout *layout) {
  auto *item = new QLabel(text);
  item->setTextFormat(Qt::PlainText);
  item->setWordWrap(true);
  item->setTextInteractionFlags(Qt::TextSelectableByMouse);
  layout->addWidget(item);
  return item;
}
} // namespace

SetupPage::SetupPage(QString executable, QString nodeHelper, QWidget *parent)
    : QWidget(parent), backend(std::move(executable)),
      helper(std::move(nodeHelper)) {
  auto *layout = new QVBoxLayout(this);
  auto *scroll = new QScrollArea;
  scroll->setWidgetResizable(true);
  scroll->setFrameShape(QFrame::NoFrame);
  auto *content = new QWidget;
  auto *steps = new QVBoxLayout(content);
  label(tr("Set up YubiQuity on this computer. You can return to this page any "
           "time. Your browser stays unmodified."),
        steps);
  auto section = [steps](const QString &title) {
    auto *group = new QGroupBox(title);
    auto *items = new QVBoxLayout(group);
    steps->addWidget(group);
    return items;
  };
  auto *device = section(tr("1. Check device and browser access"));
  checks = label(tr("Choose Check again to test device access and detect "
                    "browser integration."),
                 device);
  checks->setObjectName("setupChecks");
  auto *details = new QPushButton(tr("Show diagnostic details"));
  details->setCheckable(true);
  device->addWidget(details);
  diagnostics = label({}, device);
  diagnostics->setObjectName("setupDetails");
  diagnostics->hide();
  connect(details, &QPushButton::toggled, this, [this, details](bool visible) {
    diagnostics->setVisible(visible);
    details->setText(visible ? tr("Hide diagnostic details")
                             : tr("Show diagnostic details"));
  });
  auto *actions = new QHBoxLayout;
  refresh = new QPushButton(tr("Check again"));
  refresh->setObjectName("setupCheck");
  deviceRepair = new QPushButton(tr("Configure device access…"));
  deviceRepair->setObjectName("setupDevice");
  firefoxRepair = new QPushButton(tr("Enable Firefox Snap…"));
  firefoxRepair->setObjectName("setupFirefox");
  for (auto *button : {refresh, deviceRepair, firefoxRepair})
    actions->addWidget(button);
  device->addLayout(actions);
  label(tr("Device setup grants your account permission to create HID devices. "
           "Grant it only to trusted users. Firefox setup connects Snap's "
           "security-key interface and reloads the packaged rules. Each repair "
           "asks for administrator authentication and preserves local rule "
           "customizations."),
        device);
  result = label({}, device);
  result->setObjectName("setupResult");
  auto *vault = section(tr("2. Open your vault and set its browser PIN"));
  vaultState = label({}, vault);
  auto *vaultActions = new QHBoxLayout;
  create = new QPushButton(tr("Create vault…"));
  create->setObjectName("setupCreate");
  open = new QPushButton(tr("Open vault…"));
  open->setObjectName("setupOpen");
  unlock = new QPushButton(tr("Unlock"));
  pin = new QPushButton(tr("Set security-key PIN…"));
  pin->setObjectName("setupPin");
  for (auto *button : {create, open, unlock, pin})
    vaultActions->addWidget(button);
  vault->addLayout(vaultActions);
  label(tr("The vault passphrase encrypts your saved passkeys. The "
           "security-key PIN is what your browser asks for. Both allow "
           "unlimited attempts. A copied vault keeps its existing PIN."),
        vault);
  auto *browser = section(tr("3. Try registration and sign-in"));
  label(tr("Open the test site in each browser you use. Enter a disposable "
           "test username, register using “Security key”, enter the PIN, and "
           "click Approve in YubiQuity. Then authenticate with the same "
           "username. This creates a test credential on that public service. "
           "Device checks alone cannot confirm browser compatibility."),
        browser);
  auto *test = new QPushButton(tr("Open webauthn.io in my default browser"));
  test->setObjectName("setupBrowserTest");
  browser->addWidget(test);
  label(tr("If Firefox Snap still waits for a touch without a YubiQuity "
           "prompt: run the checks again, apply any suggested repair, lock and "
           "unlock the vault, and fully restart Firefox. For another browser, "
           "copy https://webauthn.io into that browser."),
        browser);
  scroll->setWidget(content);
  layout->addWidget(scroll);
  auto *done = new QPushButton(tr("Done — return to my vault"));
  done->setObjectName("setupDone");
  layout->addWidget(done);
  connect(refresh, &QPushButton::clicked, this, &SetupPage::check);
  connect(deviceRepair, &QPushButton::clicked, this,
          [this] { repair("device"); });
  connect(firefoxRepair, &QPushButton::clicked, this,
          [this] { repair("firefox"); });
  connect(create, &QPushButton::clicked, this, &SetupPage::createVault);
  connect(open, &QPushButton::clicked, this, &SetupPage::openVault);
  connect(unlock, &QPushButton::clicked, this, &SetupPage::unlockVault);
  connect(pin, &QPushButton::clicked, this, &SetupPage::configurePin);
  connect(done, &QPushButton::clicked, this, &SetupPage::finished);
  connect(test, &QPushButton::clicked, this, [this] {
    if (!QDesktopServices::openUrl(QUrl("https://webauthn.io")))
      message(tr("Could not open your default browser. Open "
                 "https://webauthn.io in the browser you want to test."));
  });
  setVaultState(false, false, false, false, false);
  updateRepairs();
}

void SetupPage::setVaultState(bool selected, bool ready, bool pinKnown,
                              bool configured, bool busy, bool manageVault) {
  create->setEnabled(manageVault && !busy && !ready);
  open->setEnabled(manageVault && !busy && !ready);
  unlock->setEnabled(selected && !busy && !ready);
  pin->setEnabled(ready && pinKnown && !busy);
  pin->setText(configured ? tr("Change security-key PIN…")
                          : tr("Set security-key PIN…"));
  vaultState->setText(
      ready ? (pinKnown
                   ? (configured ? tr("Vault unlocked. Its security-key PIN is "
                                      "configured; you can test your browser.")
                                 : tr("Vault unlocked. Set a security-key PIN "
                                      "before testing PIN-required passkeys."))
                   : tr("Vault unlocked. Waiting for PIN status; if it does "
                        "not appear, update both application components."))
            : (selected ? tr("Unlock your selected vault to check or set its "
                             "security-key PIN.")
                        : tr("Create a new vault or open a vault copied from "
                             "another computer.")));
}
void SetupPage::message(const QString &text) {
  result->setText(diagnosticText(text));
}
void SetupPage::updateRepairs() {
  refresh->setEnabled(!job);
  deviceRepair->setVisible(repairDevice);
  firefoxRepair->setVisible(repairFirefox);
  deviceRepair->setEnabled(!job && installedHelper());
  firefoxRepair->setEnabled(!job && installedHelper());
}
void SetupPage::showReport(const QJsonObject &report) {
  if (report.value("version").toInt() != 1 ||
      !report.value("checks").isArray()) {
    message(
        tr("Incompatible setup report. Update the GUI and backend together."));
    return;
  }
  QStringList lines, summary;
  for (const auto &value : report.value("checks").toArray()) {
    const auto check = value.toObject();
    const auto state = check.value("status").toString();
    const auto prefix = state == "ok"          ? tr("OK")
                        : state == "attention" ? tr("Action needed")
                        : state == "unknown"   ? tr("Unknown")
                        : state == "unchecked" ? tr("Not checked")
                                               : tr("Info");
    lines << tr("%1 — %2\n%3")
                 .arg(prefix, displayText(check.value("title").toString()),
                      diagnosticText(check.value("detail").toString()));
    if (check.value("id").toString() != "browser-test") {
      auto line = tr("%1 — %2").arg(
          displayText(check.value("title").toString()), prefix);
      if (state == "attention" || state == "unknown")
        line += "\n" + diagnosticText(check.value("detail").toString().section(
                           '\n', 0, 0));
      summary << line;
    }
  }
  checks->setText(summary.join("\n"));
  diagnostics->setText(lines.join("\n\n"));
  repairDevice = report.value("repair_device").toBool();
  repairFirefox = report.value("repair_firefox").toBool();
  if ((repairDevice || repairFirefox) && !installedHelper())
    message(tr("Automatic repair requires the installed YubiQuity package. "
               "This build will not run a helper from the source checkout as "
               "administrator. Install the package, or follow "
               "docs/host-testing.md for source installation."));
  updateRepairs();
}
void SetupPage::check() {
  if (job)
    return;
  checks->setText(tr("Checking this session, attaching a temporary key, and "
                     "detecting browser access… No credentials are loaded."));
  auto *command = new Command(this);
  job = command;
  updateRepairs();
  connect(command, &Command::finished, this,
          [this, command](bool ok, QByteArray output, const QString &error) {
            job = nullptr;
            command->deleteLater();
            if (ok)
              showReport(QJsonDocument::fromJson(output).object());
            else
              message(tr("Checks did not finish. No settings were changed.\n%1")
                          .arg(error));
            updateRepairs();
          });
  QStringList args{"doctor", "--json", "--probe"};
  if (!helper.isEmpty())
    args << "--node-helper" << helper;
  command->start(backend, args, {}, false, 60000);
}
void SetupPage::repair(const QString &action) {
  if (job || !installedHelper())
    return;
  auto *command = new Command(this);
  job = command;
  updateRepairs();
  message(tr("Waiting for the desktop administrator prompt. Cancelling it "
             "leaves setup available to retry."));
  connect(
      command, &Command::finished, this,
      [this, command](bool ok, QByteArray output, const QString &error) {
        job = nullptr;
        command->deleteLater();
        message(
            ok ? QString::fromUtf8(output).trimmed()
               : tr("Setup was cancelled or could not finish. Completed steps "
                    "may already have taken effect.\n%1\nIf no password window "
                    "appeared, check that your desktop has a polkit "
                    "authentication agent. You can also ask an administrator "
                    "to run sudo yubiquity-setup YOUR_USERNAME.")
                     .arg(error));
        check();
      });
  command->start("/usr/bin/pkexec",
                 {"--disable-internal-agent", "/usr/sbin/yubiquity-setup",
                  "--desktop-" + action},
                 {}, false, 120000);
}
