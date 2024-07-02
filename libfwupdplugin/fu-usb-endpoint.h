/*
 * Copyright 2020 Emmanuel Pacaud <emmanuel@gnome.org>
 *
 * SPDX-License-Identifier: LGPL-2.1-or-later
 */

#pragma once

#include "fu-usb-device.h"

#define FU_TYPE_USB_ENDPOINT (fu_usb_endpoint_get_type())
G_DECLARE_FINAL_TYPE(FuUsbEndpoint, fu_usb_endpoint, FU, USB_ENDPOINT, GObject)

guint8
fu_usb_endpoint_get_kind(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint16
fu_usb_endpoint_get_maximum_packet_size(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint8
fu_usb_endpoint_get_polling_interval(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint8
fu_usb_endpoint_get_refresh(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint8
fu_usb_endpoint_get_synch_address(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint8
fu_usb_endpoint_get_address(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
guint8
fu_usb_endpoint_get_number(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
FuUsbDeviceDirection
fu_usb_endpoint_get_direction(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
GBytes *
fu_usb_endpoint_get_extra(FuUsbEndpoint *self) G_GNUC_NON_NULL(1);
