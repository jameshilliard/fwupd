/*
 * Copyright 2022 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fu-backend.h"

gboolean
fu_backend_load(FuBackend *self,
		JsonObject *json_object,
		GError **error) G_GNUC_NON_NULL(1, 2);
gboolean
fu_backend_save(FuBackend *self,
		JsonBuilder *json_builder,
		GError **error) G_GNUC_NON_NULL(1, 2);
