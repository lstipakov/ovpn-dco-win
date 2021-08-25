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

#include <ntddk.h>
#include <wsk.h>
#include <wdf.h>
#include <wdfrequest.h>

#include "driver.h"
#include "trace.h"
#include "peer.h"
#include "uapi\ovpn-dco.h"
#include "socket.h"

TRACELOGGING_DEFINE_PROVIDER(OpenVPNTraceProvider, "Ovpn", (0x4970f9cf, 0x2c0c, 0x4f11, 0xb1, 0xcc, 0xe3, 0xa1, 0xe9, 0x95, 0x88, 0x33));

// WSK Client Dispatch table that denotes the WSK version
// that the WSK application wants to use and optionally a pointer
// to the WskClientEvent callback function
const WSK_CLIENT_DISPATCH WskAppDispatch = { MAKE_WSK_VERSION(1,0), 0, NULL };

EVT_WDF_OBJECT_CONTEXT_CLEANUP OvpnEvtDriverContextCleanup;

_Use_decl_annotations_
VOID
OvpnEvtDriverContextCleanup(_In_ WDFOBJECT driverObject)
{
    UNREFERENCED_PARAMETER(driverObject);

    TraceLoggingUnregister(OpenVPNTraceProvider);
}

NTSTATUS
DriverEntry(_In_ PDRIVER_OBJECT driverObject, _In_ PUNICODE_STRING registryPath)
{
    TraceLoggingRegister(OpenVPNTraceProvider);

    WDF_OBJECT_ATTRIBUTES driverAttrs;
    WDF_OBJECT_ATTRIBUTES_INIT(&driverAttrs);
    driverAttrs.EvtCleanupCallback = OvpnEvtDriverContextCleanup;
    WDF_OBJECT_ATTRIBUTES_SET_CONTEXT_TYPE(&driverAttrs, OVPN_DRIVER);

    WDF_DRIVER_CONFIG driverConfig;
    WDF_DRIVER_CONFIG_INIT(&driverConfig, OvpnEvtDeviceAdd);

    WSK_CLIENT_NPI wskClientNpi = {};

    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDriverCreate(driverObject, registryPath, &driverAttrs, &driverConfig, WDF_NO_HANDLE));

    // Register the WSK application
    wskClientNpi.ClientContext = NULL;
    wskClientNpi.Dispatch = &WskAppDispatch;

    POVPN_DRIVER driverCtx = OvpnGetDriverContext(WdfGetDriver());

    GOTO_IF_NOT_NT_SUCCESS(done, status, WskRegister(&wskClientNpi, &driverCtx->WskRegistration));

done:
    return status;
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoRead;

_Use_decl_annotations_
VOID
OvpnEvtIoRead(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // do we have pending control packets?
    LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->RxControlQueue);
    if (entry == NULL) {
        // no pending control packets, move request to manual queue
        LOG_IF_NOT_NT_SUCCESS(WdfRequestForwardToIoQueue(request, device->PendingReadsQueue));
        return;
    }

    OVPN_RX_WORKITEM* work = CONTAINING_RECORD(entry, OVPN_RX_WORKITEM, ListEntry);

    ULONG dstLen = 0;
    MDL* mdl = NULL;
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveOutputWdmMdl(request, &mdl));

    UCHAR* src = (UCHAR*)MmGetSystemAddressForMdlSafe(work->Mdl, LowPagePriority | MdlMappingNoExecute);
    UCHAR* dst = (UCHAR*)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);

    if ((src == NULL) || (dst == NULL)) {
        LOG_ERROR("MmGetSystemAddressForMdlSafe() failed");
        length = 0;
        goto done;
    }

    src += work->Offset;

    dstLen = MmGetMdlByteCount(mdl);
    if (dstLen < work->Length) {
        LOG_WARN("Control packet buffer too small", TraceLoggingValue(dstLen, "dstLen"), TraceLoggingValue(work->Length, "work->Length"));
        status = STATUS_BUFFER_TOO_SMALL;
        length = 0;
        goto done;
    }

    RtlCopyMemory(dst, src, work->Length);
    length = work->Length;

done:
    WSK_SOCKET* socket = device->Socket.Socket;
    if (work->Tcp) {
        IoFreeMdl(work->Mdl);

        if (work->DUMMYUNION.TCP.DataIndication) {
            LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_CONNECTION_DISPATCH*)socket->Dispatch)->WskRelease(socket, (WSK_DATA_INDICATION*)work->DUMMYUNION.TCP.DataIndication));
        }
    }
    else
        LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_DATAGRAM_DISPATCH*)socket->Dispatch)->WskRelease(socket, (WSK_DATAGRAM_INDICATION*)work->DUMMYUNION.DatagramIndication));

    // return workitem to pool
    OvpnBufferPoolPut(device->RxPool, work);

    // complete IO request
    WdfRequestCompleteWithInformation(request, status, length);
}

EVT_WDF_IO_QUEUE_IO_READ OvpnEvtIoWrite;

_Use_decl_annotations_
VOID
OvpnEvtIoWrite(WDFQUEUE queue, WDFREQUEST request, size_t length)
{
    UNREFERENCED_PARAMETER(length);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    // acquire spinlock, since we access device->TransportSocket
    KIRQL kiqrl = ExAcquireSpinLockShared(&device->SpinLock);

    if (length > 1500) {
        LOG_WARN("Control packet too large, ignore", TraceLoggingValue(length, "length"));
        status = STATUS_BAD_DATA;
        goto error;
    }

    if (device->Socket.Socket == NULL) {
        status = STATUS_INVALID_DEVICE_STATE;
        LOG_ERROR("TransportSocket is not initialized");
        goto error;
    }

    MDL* mdl = NULL;
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestRetrieveInputWdmMdl(request, &mdl));

    // move request to manual queue
    GOTO_IF_NOT_NT_SUCCESS(error, status, WdfRequestForwardToIoQueue(request, device->PendingWritesQueue));

    // fetch tx workitem
    OVPN_TX_WORKITEM* work = (OVPN_TX_WORKITEM*)OvpnBufferPoolGet(device->TxPool);
    work->Pool = device->TxPool;
    work->IoQueue = device->PendingWritesQueue;

    if (device->Socket.Tcp) {
        work->TcpData = (UCHAR*)OvpnBufferPoolGet(device->TcpDataTxPool);
        work->TcpDataPool = device->TcpDataTxPool;

        UCHAR* src = (UCHAR*)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
        if (!src) {
            LOG_ERROR("MmGetSystemAddressForMdlSafe() failed");
            status = STATUS_NO_MEMORY;
            OvpnBufferPoolPut(device->TcpDataTxPool, work->TcpData);
            goto error;
        }
        length += 2;
        RtlCopyMemory(work->TcpData + 2, src, length);

        mdl = IoAllocateMdl(work->TcpData, (ULONG)length, FALSE, FALSE, NULL);
        MmBuildMdlForNonPagedPool(mdl);
        work->Mdl = mdl;
    }

    // send
    LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, mdl, 0, length, work));

    goto done_not_complete;

error:
    ULONG_PTR bytesCopied = 0;
    WdfRequestCompleteWithInformation(request, status, bytesCopied);

done_not_complete:
    ExReleaseSpinLockShared(&device->SpinLock, kiqrl);
}

EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL OvpnEvtIoDeviceControl;

_Use_decl_annotations_
VOID
OvpnEvtIoDeviceControl(WDFQUEUE queue, WDFREQUEST request, size_t outputBufferLength, size_t inputBufferLength, ULONG ioControlCode) {
    UNREFERENCED_PARAMETER(outputBufferLength);
    UNREFERENCED_PARAMETER(inputBufferLength);

    NTSTATUS status = STATUS_SUCCESS;

    POVPN_DEVICE device = OvpnGetDeviceContext(WdfIoQueueGetDevice(queue));

    ULONG_PTR bytesReturned = 0;

    KIRQL kirql = 0;
    switch ((long)ioControlCode) {
    case OVPN_IOCTL_GET_STATS:
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
        status = OvpnPeerGetStats(device, request, &bytesReturned);
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_NEW_PEER:
        status = OvpnPeerNew(device, request);
        break;

    case OVPN_IOCTL_START_VPN:
        status = OvpnPeerStartVPN(device);
        break;

    case OVPN_IOCTL_NEW_KEY:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerNewKey(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SWAP_KEYS:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSwapKeys(device);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    case OVPN_IOCTL_SET_PEER:
        kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
        status = OvpnPeerSet(device, request);
        ExReleaseSpinLockExclusive(&device->SpinLock, kirql);
        break;

    default:
        LOG_WARN("Unknown <ioControlCode>", TraceLoggingValue(ioControlCode, "ioControlCode"));
        status = STATUS_INVALID_DEVICE_REQUEST;
    }

    if (status != STATUS_PENDING) {
        WdfRequestCompleteWithInformation(request, status, bytesReturned);
    }
}

EVT_WDF_FILE_CLEANUP OvpnEvtFileCleanup;

_Use_decl_annotations_
VOID OvpnEvtFileCleanup(WDFFILEOBJECT fileObject) {
    POVPN_DEVICE device = OvpnGetDeviceContext(WdfFileObjectGetDevice(fileObject));

    OvpnPeerUninit(device);
}

EVT_WDF_DRIVER_DEVICE_ADD OvpnEvtDeviceAdd;

_Use_decl_annotations_
NTSTATUS
OvpnEvtDeviceAdd(WDFDRIVER wdfDriver, PWDFDEVICE_INIT deviceInit) {
    // make sure only one app can access driver at time
    WdfDeviceInitSetExclusive(deviceInit, TRUE);

    WDF_FILEOBJECT_CONFIG fileConfig;
    WDF_FILEOBJECT_CONFIG_INIT(&fileConfig, WDF_NO_EVENT_CALLBACK, WDF_NO_EVENT_CALLBACK, OvpnEvtFileCleanup);

    WdfDeviceInitSetFileObjectConfig(deviceInit, &fileConfig, WDF_NO_OBJECT_ATTRIBUTES);

    DECLARE_CONST_UNICODE_STRING(symLink, L"\\DosDevices\\ovpn-dco");

    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, NetDeviceInitConfig(deviceInit));

    WDF_OBJECT_ATTRIBUTES objAttributes;
    WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&objAttributes, OVPN_DEVICE);
    // BCryptOpenAlgorithmProvider with BCRYPT_PROV_DISPATCH returns STATUS_NOT_SUPPORTED if sync scope is WdfSynchronizationScopeDevice
    objAttributes.SynchronizationScope = WdfSynchronizationScopeNone;

    WDFDEVICE wdfDevice;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreate(&deviceInit, &objAttributes, &wdfDevice));

    // this will fail if one device has already been created but that's ok, since
    // openvpn2/3 accesses devices via Device Interface GUID, and symlink is used only by test client.
    LOG_IF_NOT_NT_SUCCESS(WdfDeviceCreateSymbolicLink(wdfDevice, &symLink));

    UNICODE_STRING referenceString;
    RtlInitUnicodeString(&referenceString, L"ovpn-dco");
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfDeviceCreateDeviceInterface(wdfDevice, &GUID_DEVINTERFACE_NET, &referenceString));

    // create main queue which handles reads/writes from userspace
    WDF_IO_QUEUE_CONFIG queueConfig;
    WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queueConfig, WdfIoQueueDispatchSequential);
    queueConfig.EvtIoRead = OvpnEvtIoRead;
    queueConfig.EvtIoWrite = OvpnEvtIoWrite;
    queueConfig.EvtIoDeviceControl = OvpnEvtIoDeviceControl;
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, WDF_NO_HANDLE));

    POVPN_DEVICE device = OvpnGetDeviceContext(wdfDevice);
    device->WdfDevice = wdfDevice;

    // create manual pending queue which handles async reads
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingReadsQueue));

    // create manual pending queue which handles async writes
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingWritesQueue));

    // create manual pending queue which handles async NewPeer requests (when proto is TCP, connect is async)
    WDF_IO_QUEUE_CONFIG_INIT(&queueConfig, WdfIoQueueDispatchManual);
    GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueCreate(wdfDevice, &queueConfig, WDF_NO_OBJECT_ATTRIBUTES, &device->PendingNewPeerQueue));

    POVPN_DRIVER driver = OvpnGetDriverContext(wdfDriver);

    // Capture the WSK Provider NPI. If WSK subsystem is not ready yet, wait until it becomes ready.
    GOTO_IF_NOT_NT_SUCCESS(done, status, WskCaptureProviderNPI(&driver->WskRegistration, WSK_INFINITE_WAIT, &driver->WskProviderNpi));

done:
    return status;
}
