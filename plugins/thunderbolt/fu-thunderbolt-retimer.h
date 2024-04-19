/*
 * Copyright 2021 Richard Hughes <richard@hughsie.com>
 * Copyright 2020 Mario Limonciello <mario.limonciello@dell.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include <fwupdplugin.h>

#include "fu-thunderbolt-device.h"

#define FU_TYPE_THUNDERBOLT_RETIMER (fu_thunderbolt_retimer_get_type())
G_DECLARE_FINAL_TYPE(FuThunderboltRetimer,
		     fu_thunderbolt_retimer,
		     FU,
		     THUNDERBOLT_RETIMER,
		     FuThunderboltDevice)

gboolean
fu_thunderbolt_retimer_set_parent_port_offline(FuDevice *device, const gchar *port, GError **error);

gboolean
fu_thunderbolt_retimer_set_parent_port_online(FuDevice *device, const gchar *port, GError **error);
