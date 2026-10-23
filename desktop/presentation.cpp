#include "presentation.h"
#include <QGuiApplication>
#include <cstdlib>
#include <cstring>
#include <memory>

#if QT_CONFIG(xcb)
#include <xcb/xcb.h>

namespace {
template <typename T> using Reply = std::unique_ptr<T, decltype(&std::free)>;

xcb_atom_t atom(xcb_connection_t *connection, const char *name) {
  Reply<xcb_intern_atom_reply_t> reply(
      xcb_intern_atom_reply(
          connection,
          xcb_intern_atom(connection, true, std::strlen(name), name), nullptr),
      std::free);
  return reply ? reply->atom : xcb_atom_t{XCB_ATOM_NONE};
}

void requestCurrentDesktop(QWidget &window) {
  if (QGuiApplication::platformName() != "xcb")
    return;
  auto *native = qGuiApp->nativeInterface<QNativeInterface::QX11Application>();
  if (!native)
    return; // In particular, never use DISPLAY from a Wayland app.
  auto *connection = native->connection();
  if (!connection || xcb_connection_has_error(connection))
    return;
  const auto id = static_cast<xcb_window_t>(window.winId());
  Reply<xcb_get_geometry_reply_t> geometry(
      xcb_get_geometry_reply(connection, xcb_get_geometry(connection, id),
                             nullptr),
      std::free);
  const auto currentAtom = atom(connection, "_NET_CURRENT_DESKTOP");
  const auto desktopAtom = atom(connection, "_NET_WM_DESKTOP");
  if (!geometry || !currentAtom || !desktopAtom)
    return;
  Reply<xcb_get_property_reply_t> current(
      xcb_get_property_reply(connection,
                             xcb_get_property(connection, false, geometry->root,
                                              currentAtom, XCB_ATOM_CARDINAL, 0,
                                              1),
                             nullptr),
      std::free);
  if (!current || current->type != XCB_ATOM_CARDINAL || current->format != 32 ||
      xcb_get_property_value_length(current.get()) != 4)
    return;
  uint32_t desktop;
  std::memcpy(&desktop, xcb_get_property_value(current.get()), sizeof desktop);
  if (desktop == UINT32_MAX)
    return; // Never make the approval sticky/all-desktops.

  // EWMH: initial hint for withdrawn windows, message for already managed ones.
  // This moves only our window; _NET_CURRENT_DESKTOP itself is never changed.
  if (!window.isVisible())
    xcb_change_property(connection, XCB_PROP_MODE_REPLACE, id, desktopAtom,
                        XCB_ATOM_CARDINAL, 32, 1, &desktop);
  xcb_client_message_event_t message{};
  message.response_type = XCB_CLIENT_MESSAGE;
  message.format = 32;
  message.window = id;
  message.type = desktopAtom;
  message.data.data32[0] = desktop;
  message.data.data32[1] = 1; // Normal application, not a privileged pager.
  xcb_send_event(connection, false, geometry->root,
                 XCB_EVENT_MASK_SUBSTRUCTURE_REDIRECT |
                     XCB_EVENT_MASK_SUBSTRUCTURE_NOTIFY,
                 reinterpret_cast<const char *>(&message));
  xcb_flush(connection);
}
} // namespace
#endif

void presentWindow(QWidget &window) {
  // Wayland has no portable workspace-moving API. Remap an existing window
  // when explicitly recalled (e.g. from the tray), letting the compositor place
  // it anew. Keep the QWidget and its request/deadline intact.
  if (QGuiApplication::platformName().startsWith("wayland") &&
      window.isVisible())
    window.hide();
#if QT_CONFIG(xcb)
  requestCurrentDesktop(window);
#endif
  window.showNormal();
  window.raise();
  // A request, never bypassing compositor focus policy.
  window.activateWindow();
}
