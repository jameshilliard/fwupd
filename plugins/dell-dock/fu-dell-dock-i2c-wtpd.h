/*
 * Copyright 2024 Dell Inc.
 * All rights reserved.
 *
 * This software and associated documentation (if any) is furnished
 * under a license and may only be used or copied in accordance
 * with the terms of the license.
 *
 * This file is provided under a dual MIT/LGPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 * Dell Chooses the MIT license part of Dual MIT/LGPLv2 license agreement.
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later OR MIT
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_DELL_DOCK_WTPD (fu_dell_dock_wtpd_get_type())
G_DECLARE_FINAL_TYPE(FuDellDockWtpd, fu_dell_dock_wtpd, FU, DELL_DOCK_WTPD, FuDevice)

FuDellDockWtpd *
fu_dell_dock_wtpd_new(FuDevice *parent);
