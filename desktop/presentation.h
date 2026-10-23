#pragma once
#include <QWidget>

// Request presentation on the current desktop. Native Wayland placement and
// activation remain the compositor's decision.
void presentWindow(QWidget &window);
