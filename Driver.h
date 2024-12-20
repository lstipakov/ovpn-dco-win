/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2020-2021 OpenVPN Inc <sales@openvpn.net>
 *
 *  Author:	Lev Stipakov <lev@openvpn.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2
 *  as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#pragma once

#include <ntddk.h>
#include <wdf.h>
#include <netadaptercx.h>
#include <initguid.h>
#include <Ndisguid.h>
#include <wsk.h>

#include "adapter.h"
#include "bufferpool.h"
#include "crypto.h"
#include "notifyqueue.h"
#include "socket.h"
#include "uapi\ovpn-dco.h"

extern "C" {
    DRIVER_INITIALIZE DriverEntry;
}

EVT_WDF_DRIVER_DEVICE_ADD OvpnEvtDeviceAdd;

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoRead;
EVT_WDF_IO_QUEUE_IO_WRITE OvpnEvtIoWrite;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OvpnEvtIoDeviceControl;

typedef struct _OVPN_DRIVER {
    WSK_PROVIDER_NPI WskProviderNpi;
    WSK_REGISTRATION WskRegistration;
    WDFDEVICE ControlDevice;
    LONG DeviceCount;
} OVPN_DRIVER, * POVPN_DRIVER;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_DRIVER, OvpnGetDriverContext)

struct OVPN_DEVICE {
    EX_SPIN_LOCK SpinLock;

    // WDF handle associated with this context
    WDFDEVICE WdfDevice;

    WDFQUEUE PendingReadsQueue;
    WDFQUEUE PendingWritesQueue;
    WDFQUEUE PendingNotificationRequestsQueue;

    // NEW_PEER request may be enqueued here if TCP connect doesn't finish immediatelly
    WDFQUEUE PendingNewPeerQueue;

    // buffer queue for received decrypted data channel packets
    OVPN_BUFFER_QUEUE DataRxBufferQueue;

    // buffer queue for received control channel packets
    OVPN_BUFFER_QUEUE ControlRxBufferQueue;

    // pool for OVPN_RX_BUFFER entries
    OVPN_RX_BUFFER_POOL RxBufferPool;

    // buffer pool for encrypted data channel and control channel packets to be sent
    OVPN_TX_BUFFER_POOL TxBufferPool;

    // queue to store pending userspace notifications
    NotifyQueue PendingNotificationsQueue;

    OVPN_STATS Stats;

    BCRYPT_ALG_HANDLE AesAlgHandle;
    BCRYPT_ALG_HANDLE ChachaAlgHandle;

    _Guarded_by_(SpinLock)
    OvpnSocket Socket;

    _Guarded_by_(SpinLock)
    NETADAPTER Adapter;

    _Guarded_by_(SpinLock)
    RTL_GENERIC_TABLE Peers;

    _Guarded_by_(SpinLock)
    RTL_GENERIC_TABLE PeersByVpn4;

    _Guarded_by_(SpinLock)
    RTL_GENERIC_TABLE PeersByVpn6;

    OVPN_MODE Mode;
};

typedef OVPN_DEVICE * POVPN_DEVICE;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(OVPN_DEVICE, OvpnGetDeviceContext)

struct OvpnPeerContext;

_Must_inspect_result_
NTSTATUS
OvpnAddPeerToTable(POVPN_DEVICE device, _In_ RTL_GENERIC_TABLE* table, _In_ OvpnPeerContext* peer);

VOID
OvpnFlushPeers(_In_ POVPN_DEVICE device);

VOID
OvpnCleanupPeerTable(_In_ POVPN_DEVICE device, _In_ RTL_GENERIC_TABLE*);

_Must_inspect_result_
OvpnPeerContext*
OvpnGetFirstPeer(_In_ POVPN_DEVICE device);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeer(_In_ POVPN_DEVICE device, INT32 PeerId);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeerVPN4(_In_ POVPN_DEVICE device, _In_ IN_ADDR addr);

_Must_inspect_result_
OvpnPeerContext*
OvpnFindPeerVPN6(_In_ POVPN_DEVICE device, _In_ IN6_ADDR addr);

_Must_inspect_result_
NTSTATUS
OvpnDeletePeer(_In_ POVPN_DEVICE device, INT32 peerId);
