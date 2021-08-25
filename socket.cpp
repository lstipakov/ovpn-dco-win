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

#include "adapter.h"
#include "crypto.h"
#include "driver.h"
#include "trace.h"
#include "rxqueue.h"
#include "timer.h"
#include "socket.h"

IO_COMPLETION_ROUTINE OvpnSocketSyncOpCompletionRoutine;

_Use_decl_annotations_
NTSTATUS
OvpnSocketSyncOpCompletionRoutine(PDEVICE_OBJECT reserved, PIRP irp, PVOID context)
{
    UNREFERENCED_PARAMETER(reserved);
    UNREFERENCED_PARAMETER(irp);

    if (context != NULL)
        KeSetEvent((PKEVENT)context, IO_NO_INCREMENT, FALSE);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

template <class OP, class SUCCESS>
__forceinline static NTSTATUS
_Must_inspect_result_
_IRQL_requires_(PASSIVE_LEVEL)
OvpnSocketSyncOp(_In_z_ CHAR* opName, OP op, SUCCESS success)
{
    PIRP irp; // used for async completion
    KEVENT event; // used to wait for pending create operation
    NTSTATUS status;

    KeInitializeEvent(&event, NotificationEvent, FALSE);

    irp = IoAllocateIrp(1, FALSE);
    if (!irp) {
        LOG_ERROR("IoAllocateIrp failed");
        status = STATUS_INSUFFICIENT_RESOURCES;
        goto done;
    }

    IoSetCompletionRoutine(irp, OvpnSocketSyncOpCompletionRoutine, &event, TRUE, TRUE, TRUE);

    status = op(irp);
    if (!NT_SUCCESS(status)) {
        LOG_ERROR("<op> failed with status <status>", TraceLoggingValue(opName, "op"), TraceLoggingNTStatus(status, "status"));
        IoFreeIrp(irp);
        goto done;
    }

    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = irp->IoStatus.Status;
        if (!NT_SUCCESS(status)) {
            LOG_ERROR("<op> error after wait, irp->IoStatus.status = <status>", TraceLoggingValue(opName, "op"), TraceLoggingNTStatus(status, "status"));
            IoFreeIrp(irp);
            goto done;
        }
    }

    success(irp);

    IoFreeIrp(irp);

done:
    return status;
}

static
_Requires_shared_lock_held_(device->SpinLock)
NTSTATUS
OvpnSocketControlPacketReceived(_In_ POVPN_DEVICE device, _In_ OVPN_RX_WORKITEM* work)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (work->Length > 1500) {
        LOG_WARN("Control packet too large, ignore", TraceLoggingValue(work->Length, "length"));
        return STATUS_BAD_DATA;
    }

    WDFREQUEST request;
    status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (!NT_SUCCESS(status)) {
        OVPN_RX_WORKITEM* deferredWork = (OVPN_RX_WORKITEM*)OvpnBufferPoolGet(device->RxPool);
        if (deferredWork == NULL) {
            LOG_ERROR("RxPool exhausted");
            status = STATUS_NO_MEMORY;
            goto done;
        }
        deferredWork->DUMMYUNION = work->DUMMYUNION;
        deferredWork->Length = work->Length;
        deferredWork->Mdl = work->Mdl;
        deferredWork->Offset = work->Offset;
        deferredWork->Tcp = work->Tcp;

        // set to success, otherwise calling code (also) releases dataIndication
        status = STATUS_SUCCESS;

        // enqueue buffer, it will be dequeued when read request arrives
        OvpnBufferQueueEnqueue(device->RxControlQueue, &deferredWork->ListEntry);
    } else {
        // service IO request right away
        MDL* mdl = NULL;
        GOTO_IF_NOT_NT_SUCCESS(done, status, WdfRequestRetrieveOutputWdmMdl(request, &mdl));

        UCHAR* src = (UCHAR*)MmGetSystemAddressForMdlSafe(work->Mdl, LowPagePriority | MdlMappingNoExecute);
        UCHAR* dst = (UCHAR*)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);

        if ((src == NULL) || (dst == NULL)) {
            LOG_ERROR("MmGetSystemAddressForMdlSafe() failed");
            status = STATUS_NO_MEMORY;
            goto done;
        }

        ULONG dstLen = MmGetMdlByteCount(mdl);
        if (dstLen < work->Length) {
            LOG_WARN("IO request buffer is too small", TraceLoggingValue(dstLen, "mdlByteCount"), TraceLoggingValue(work->Length, "work->Length"));
            status = STATUS_BUFFER_TOO_SMALL;

            // complete request
            ULONG_PTR bytesSent = 0;
            WdfRequestCompleteWithInformation(request, status, bytesSent);

            goto done;
        }

        RtlCopyMemory(dst, src + work->Offset, work->Length);

        // complete request
        ULONG_PTR bytesSent = work->Length;
        WdfRequestCompleteWithInformation(request, status, bytesSent);

        InterlockedIncrementNoFence(&device->Stats.ReceivedControlPackets);

        WSK_SOCKET* socket = device->Socket.Socket;
        if (work->Tcp) {
            IoFreeMdl(work->Mdl);

            if (work->DUMMYUNION.TCP.DataIndication) {
                LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_CONNECTION_DISPATCH*)socket->Dispatch)->WskRelease(socket, (WSK_DATA_INDICATION*)work->DUMMYUNION.TCP.DataIndication));
            }
        }
        else
            LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_DATAGRAM_DISPATCH*)socket->Dispatch)->WskRelease(socket, (WSK_DATAGRAM_INDICATION*)work->DUMMYUNION.DatagramIndication));
    }

done:
    return status;
}

static
_Requires_shared_lock_held_(device->SpinLock)
NTSTATUS
OvpnSocketDataPacketReceived(_In_ POVPN_DEVICE device, ULONG op, OVPN_RX_WORKITEM* rxWork, BOOLEAN* indicate)
{
    NTSTATUS status = STATUS_SUCCESS;

    if (device->CryptoContext.Decrypt) {
        unsigned int keyId = OvpnCryptoKeyIdExtract(op);
        OvpnCryptoKeySlot* keySlot = OvpnCryptoKeySlotFromKeyId(&device->CryptoContext, keyId);
        if (!keySlot) {
            status = STATUS_INVALID_DEVICE_STATE;
            LOG_ERROR("keyId <keyId> not found", TraceLoggingValue(keyId, "keyId"));
        }
        else {
            // decrypt in-place
            status = device->CryptoContext.Decrypt(keySlot, rxWork->Mdl, rxWork->Length, rxWork->Offset);
        }
    }
    else {
        status = STATUS_INVALID_DEVICE_STATE;

        LOG_WARN("CryptoContext not yet initialized");
    }

    if (NT_SUCCESS(status)) {
        OvpnTimerReset(device->KeepaliveRecvTimer, device->KeepaliveTimeout);

        // ping packet?
        if (OvpnTimerIsKeepaliveMessage(rxWork->Mdl, rxWork->Length, rxWork->Offset)) {
            LOG_INFO("Ping received");

            // no need to indicate ping packet, release datagram indication
            if (!rxWork->Tcp)
                LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_DATAGRAM_DISPATCH*)device->Socket.Socket->Dispatch)->WskRelease(device->Socket.Socket, (WSK_DATAGRAM_INDICATION*)rxWork->DUMMYUNION.DatagramIndication));
        }
        else {
            OVPN_RX_WORKITEM* rx = (OVPN_RX_WORKITEM*)OvpnBufferPoolGet(device->RxPool);
            if (rx != NULL) {
                RtlCopyMemory(rx, rxWork, sizeof(OVPN_RX_WORKITEM));

                rx->DUMMYUNION = rxWork->DUMMYUNION;
                rx->Length = rxWork->Length - device->CryptoContext.CryptoOverhead;
                rx->Mdl = rxWork->Mdl;
                rx->Offset = rxWork->Offset + device->CryptoContext.CryptoOverhead;
                rx->Tcp = rxWork->Tcp;

                OvpnBufferQueueEnqueue(device->RxDataQueue, &rx->ListEntry);
                *indicate = TRUE;
            }
            else {
                LOG_ERROR("RxPool exhausted");

                status = STATUS_NO_MEMORY;
            }
        }
    }

    return status;
}

NTSTATUS
OvpnSocketProcessIncomingPacket(_In_ POVPN_DEVICE device, OVPN_RX_WORKITEM* rxWork, BOOLEAN dpc, BOOLEAN* indicate)
{
    InterlockedExchangeAddNoFence64(&device->Stats.TransportBytesReceived, rxWork->Length);

    // If we're at dispatch level, we can use a small optimization and use function
    // which is not calling KeRaiseIRQL to raise the IRQL to DISPATCH_LEVEL before attempting to acquire the lock

    NTSTATUS status = STATUS_SUCCESS;

    if ((rxWork->Length == 0) || (rxWork->Mdl == NULL)) {
        LOG_WARN("Zero-size packet received, ignore");
        return STATUS_DATA_ERROR;
    }

    UCHAR* buf = (PUCHAR)MmGetSystemAddressForMdlSafe(rxWork->Mdl, LowPagePriority | MdlMappingNoExecute);
    if (buf == NULL) {
        LOG_ERROR("MmGetSystemAddressForMdlSafe() returned NULL");
        return STATUS_DATA_ERROR;
    }

    buf += rxWork->Offset;
    ULONG op = RtlUlongByteSwap(*(ULONG*)(buf)) >> 24;

    KIRQL kirql = 0;
    if (dpc) {
        ExAcquireSpinLockSharedAtDpcLevel(&device->SpinLock);
    }
    else {
        kirql = ExAcquireSpinLockShared(&device->SpinLock);
    }

    if (OvpnCryptoOpcodeExtract(op) == OVPN_OP_DATA_V2) {
        LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketDataPacketReceived(device, op, rxWork, indicate));
    }
    else {
        LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketControlPacketReceived(device, rxWork));
    }

    // don't forget to release spinlock
    if (dpc) {
        ExReleaseSpinLockSharedFromDpcLevel(&device->SpinLock);
    }
    else {
        ExReleaseSpinLockShared(&device->SpinLock, kirql);
    }

    return status;
}

_Must_inspect_result_
static
NTSTATUS
OvpnSocketUdpReceiveFromEvent(_In_ PVOID socketContext, ULONG flags, _In_opt_ PWSK_DATAGRAM_INDICATION dataIndication)
{
    UNREFERENCED_PARAMETER(flags);

    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    // could happen on uninit
    if (device->Socket.Socket == NULL) {
        LOG_ERROR("TransportSocket is not initialized");
        return STATUS_SUCCESS;
    }

    BOOLEAN indicate = FALSE;

    // each datagram indication is one UDP datagram
    for (PWSK_DATAGRAM_INDICATION next; dataIndication != NULL; dataIndication = next) {
        next = dataIndication->Next;

        // break list so that we can pass individual WSK_DATAGRAM_INDICATION to WskRelease
        dataIndication->Next = NULL;

        OVPN_RX_WORKITEM rxWork = { 0 };
        rxWork.DUMMYUNION.DatagramIndication = dataIndication;
        rxWork.Length = (ULONG)dataIndication->Buffer.Length;
        rxWork.Offset = dataIndication->Buffer.Offset;
        rxWork.Mdl = dataIndication->Buffer.Mdl;
        rxWork.Tcp = FALSE;

        if (!NT_SUCCESS(OvpnSocketProcessIncomingPacket(device, &rxWork, flags & WSK_FLAG_AT_DISPATCH_LEVEL, &indicate))) {
            LOG_IF_NOT_NT_SUCCESS(((WSK_PROVIDER_DATAGRAM_DISPATCH*)device->Socket.Socket->Dispatch)->WskRelease(device->Socket.Socket, dataIndication));
        }
    }

    // tell NetAdapter that we have something to consume
    if (indicate)
        OvpnAdapterNotifyRx(device->Adapter);

    return STATUS_PENDING;
}

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpReceiveEvent(_In_opt_ PVOID socketContext, _In_ ULONG flags, _In_opt_ PWSK_DATA_INDICATION dataIndication, _In_ SIZE_T bytesIndicated, _Inout_ SIZE_T* bytesAccepted)
{
    UNREFERENCED_PARAMETER(bytesAccepted);
    UNREFERENCED_PARAMETER(bytesIndicated);

    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    OvpnSocketTcpState* tcpState = &device->Socket.TcpState;

    BOOLEAN indicate = FALSE;

    // iterate over data indications
    while (dataIndication != NULL) {
        WSK_DATA_INDICATION* next = dataIndication->Next;
        dataIndication->Next = NULL;

        PMDL mdl = dataIndication->Buffer.Mdl;
        ULONG offset = dataIndication->Buffer.Offset;
        SIZE_T dataIndicationLen = dataIndication->Buffer.Length;

        // iterate over MDLs
        while (dataIndicationLen > 0 && mdl != NULL) {
            SIZE_T mdlDataLen = min(dataIndicationLen, MmGetMdlByteCount(mdl) - offset);
            PUCHAR sysAddr = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority);

            if (sysAddr == NULL) {
                return STATUS_INSUFFICIENT_RESOURCES;
            }
            sysAddr += offset;

            // there could be multiple packets inside MDL
            while (mdlDataLen > 0) {
                // have we already read packet length?
                if (tcpState->PacketLength == 0) {
                    // read packet length (or part of it)
                    USHORT packetLengthRead = (USHORT)min(mdlDataLen, sizeof(tcpState->LenBuf) - tcpState->BytesRead);
                    RtlCopyMemory(tcpState->LenBuf + tcpState->BytesRead, sysAddr, packetLengthRead);
                    tcpState->BytesRead += packetLengthRead;

                    // header fully read?
                    if (tcpState->BytesRead == sizeof(tcpState->LenBuf)) {
                        USHORT len = RtlUshortByteSwap(*(USHORT*)tcpState->LenBuf);
                        if ((len == 0) || (len > OVPN_SOCKET_PACKET_BUFFER_SIZE)) {
                            return STATUS_INVALID_BUFFER_SIZE;
                        }

                        tcpState->PacketLength = len;
                        tcpState->BytesRead = 0;
                    }

                    sysAddr += packetLengthRead;

                    mdlDataLen -= packetLengthRead;
                    dataIndicationLen -= packetLengthRead;
                }
                else {
                    // read packet content

                    SIZE_T bytesRemained = tcpState->PacketLength - tcpState->BytesRead;
                    BOOLEAN packetFitsIntoMDL = bytesRemained <= mdlDataLen;

                    if (packetFitsIntoMDL) {
                        OVPN_RX_WORKITEM work;

                        PUCHAR buf;
                        if (tcpState->BytesRead == 0) {
                            // we haven't started reading packet and it fits into MDL, so process it in-place
                            buf = sysAddr;
                            work.DUMMYUNION.TCP.PacketBuf = NULL;
                        } else {
                            // copy rest of packet into buffer
                            RtlCopyMemory(tcpState->PacketBuf + tcpState->BytesRead, sysAddr, bytesRemained);
                            buf = tcpState->PacketBuf;
                            work.DUMMYUNION.TCP.PacketBuf = tcpState->PacketBuf;
                        }

                        MDL* targetMdl = IoAllocateMdl(buf, tcpState->PacketLength, FALSE, FALSE, NULL);
                        MmBuildMdlForNonPagedPool(targetMdl);

                        if (dataIndication != tcpState->LastDataIndication) {
                            // dataIndication has changed, tell RX datapath to free previous dataIndication
                            work.DUMMYUNION.TCP.DataIndication = tcpState->LastDataIndication;
                            tcpState->LastDataIndication = dataIndication;
                        }
                        else {
                            work.DUMMYUNION.TCP.DataIndication = NULL;
                        }
                        work.Length = tcpState->PacketLength;
                        work.Mdl = targetMdl;
                        work.Offset = 0;
                        work.Tcp = TRUE;

                        OvpnSocketProcessIncomingPacket(device, &work, flags & WSK_FLAG_AT_DISPATCH_LEVEL, &indicate);

                        mdlDataLen -= bytesRemained;
                        dataIndicationLen -= bytesRemained;
                        sysAddr += bytesRemained;

                        // get ready for next packet
                        tcpState->PacketLength = 0;
                        tcpState->BytesRead = 0;
                    }
                    else {
                        if (tcpState->BytesRead == 0) {
                            tcpState->PacketBuf = (UCHAR*)OvpnBufferPoolGet(device->TcpDataRxPool);
                        }

                        // payload doesn't fit into MDL, copy rest of MDL into buffer
                        RtlCopyMemory(tcpState->PacketBuf + tcpState->BytesRead, sysAddr, mdlDataLen);

                        tcpState->BytesRead += (USHORT)mdlDataLen;

                        dataIndicationLen -= mdlDataLen;
                        mdlDataLen = 0;
                    }
                }
            }

            offset = 0;
            mdl = mdl->Next;
        }

        dataIndication = next;
    }

    // tell NetAdapter that we have something to consume
    if (indicate)
        OvpnAdapterNotifyRx(device->Adapter);

    return STATUS_PENDING;
}

_Must_inspect_result_
NTSTATUS
OvpnSocketTcpDisconnectEvent(_In_opt_ PVOID socketContext, _In_ ULONG flags)
{
    UNREFERENCED_PARAMETER(flags);

    LOG_INFO("TCP disconnect");

    if (socketContext == NULL) {
        return STATUS_SUCCESS;
    }

    POVPN_DEVICE device = (POVPN_DEVICE)socketContext;

    // inform userspace about error
    WDFREQUEST request;
    NTSTATUS status = WdfIoQueueRetrieveNextRequest(device->PendingReadsQueue, &request);
    if (NT_SUCCESS(status)) {
        ULONG_PTR bytesCopied = 0;
        WdfRequestCompleteWithInformation(request, STATUS_REMOTE_DISCONNECT, bytesCopied);
    }
    else {
        LOG_WARN("No pending read request, cannot inform userspace");
    }

    return STATUS_SUCCESS;
}

const WSK_CLIENT_DATAGRAM_DISPATCH OvpnSocketUdpDispatch = { OvpnSocketUdpReceiveFromEvent };
const WSK_CLIENT_CONNECTION_DISPATCH OvpnSocketTcpDispatch = { OvpnSocketTcpReceiveEvent, OvpnSocketTcpDisconnectEvent, NULL };

_Use_decl_annotations_
NTSTATUS
OvpnSocketInit(WSK_PROVIDER_NPI* wskProviderNpi, ADDRESS_FAMILY addressFamily, BOOLEAN tcp, PSOCKADDR localAddr,
    PSOCKADDR remoteAddr, SIZE_T remoteAddrSize, PVOID deviceContext, PWSK_SOCKET* socket)
{
    WSK_EVENT_CALLBACK_CONTROL eventCallbackControl = {};

    // create socket

    USHORT socketType = tcp ? SOCK_STREAM : SOCK_DGRAM;
    ULONG proto = tcp ? IPPROTO_TCP : IPPROTO_UDP;
    ULONG flags = tcp ? WSK_FLAG_CONNECTION_SOCKET : WSK_FLAG_DATAGRAM_SOCKET;
    PVOID dispatch = tcp ? (PVOID)&OvpnSocketTcpDispatch : (PVOID)&OvpnSocketUdpDispatch;

    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnSocketSyncOp("CreateSocket", [&status, wskProviderNpi, addressFamily, socketType, proto, flags, deviceContext, dispatch](PIRP irp) {
        return wskProviderNpi->Dispatch->WskSocket(wskProviderNpi->Client, addressFamily, socketType, proto, flags, deviceContext,
            dispatch, NULL, NULL, NULL, irp);
        }, [socket](PIRP irp) {
            *socket = (PWSK_SOCKET)irp->IoStatus.Information;
        }
    ));

    PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(*socket)->Dispatch;

    if (tcp) {
        // bind
        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("BindSocket", [connectionDispatch, socket, localAddr](PIRP irp) {
            return connectionDispatch->WskBind(*socket, localAddr, 0, irp);
        }, [](PIRP) {}));

        // connect will be done later
    }
    else {
        // bind
        PWSK_PROVIDER_DATAGRAM_DISPATCH datagramDispatch = (PWSK_PROVIDER_DATAGRAM_DISPATCH)(*socket)->Dispatch;

        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("BindSocket", [datagramDispatch, socket, localAddr](PIRP irp) {
            return datagramDispatch->WskBind(*socket, localAddr, 0, irp);
        }, [](PIRP) {}));

        // set remote
        PWSK_PROVIDER_BASIC_DISPATCH basicDispatch = (PWSK_PROVIDER_BASIC_DISPATCH)(*socket)->Dispatch;

        GOTO_IF_NOT_NT_SUCCESS(error, status, OvpnSocketSyncOp("SetRemote", [basicDispatch, socket, remoteAddrSize, remoteAddr](PIRP irp) {
            return basicDispatch->WskControlSocket(*socket, WskIoctl, SIO_WSK_SET_REMOTE_ADDRESS, 0, remoteAddrSize, remoteAddr, 0, NULL, NULL, irp);
        }, [](PIRP) {}));

        // enable ReceiveFrom event
        eventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
        eventCallbackControl.EventMask = WSK_EVENT_RECEIVE_FROM;

        GOTO_IF_NOT_NT_SUCCESS(error, status, connectionDispatch->Basic.WskControlSocket(*socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET,
            sizeof(WSK_EVENT_CALLBACK_CONTROL), &eventCallbackControl, 0, NULL, NULL, NULL));
    }

    goto done;

error:
    // ignore return value of CloseSocket
#pragma warning(suppress: 6031)
    OvpnSocketClose(*socket);
    *socket = NULL;

done:
    return status;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketClose(PWSK_SOCKET socket)
{
    if (socket == NULL) {
        return STATUS_SUCCESS;
    }

    NTSTATUS status;
    PWSK_PROVIDER_BASIC_DISPATCH dispatch = (PWSK_PROVIDER_BASIC_DISPATCH)socket->Dispatch;

    status = OvpnSocketSyncOp("CloseSocket", [dispatch, socket](PIRP irp) {
        return dispatch->WskCloseSocket(socket, irp);
    }, [](PIRP) { });

    return status;
}

_Function_class_(IO_COMPLETION_ROUTINE)
NTSTATUS
OvpnSocketTcpConnectComplete(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP irp, _In_ PVOID context)
{
    UNREFERENCED_PARAMETER(deviceObj);

    POVPN_DEVICE device = (POVPN_DEVICE)context;

    // finish pending IO request
    WDFREQUEST request;
    NTSTATUS status;
    LOG_IF_NOT_NT_SUCCESS(status = WdfIoQueueRetrieveNextRequest(device->PendingNewPeerQueue, &request));

    if (!NT_SUCCESS(status)) {
        LOG_ERROR("No pending NewPeer requests");
    }
    else {
        status = irp->IoStatus.Status;
        LOG_INFO("TCP Connect completed", TraceLoggingNTStatus(status, "status"));
        if (status == STATUS_SUCCESS) {
            WSK_EVENT_CALLBACK_CONTROL eventCallbackControl = {};
            // enable Receive and Disconnect events
            eventCallbackControl.NpiId = &NPI_WSK_INTERFACE_ID;
            eventCallbackControl.EventMask = WSK_EVENT_RECEIVE | WSK_EVENT_DISCONNECT;

            KIRQL kirql = ExAcquireSpinLockExclusive(&device->SpinLock);
            PWSK_SOCKET socket = device->Socket.Socket;
            ExReleaseSpinLockExclusive(&device->SpinLock, kirql);

            if (socket != NULL) {
                PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(socket)->Dispatch;
                LOG_IF_NOT_NT_SUCCESS(status = connectionDispatch->Basic.WskControlSocket(socket, WskSetOption, SO_WSK_EVENT_CALLBACK, SOL_SOCKET,
                    sizeof(WSK_EVENT_CALLBACK_CONTROL), &eventCallbackControl, 0, NULL, NULL, NULL));
            }
            else {
                LOG_ERROR("socket is NULL");
                status = STATUS_INVALID_DEVICE_STATE;
            }

        }
        // complete request
        ULONG_PTR bytesSent = 0;
        WdfRequestCompleteWithInformation(request, status, bytesSent);
    }

    // Free the IRP
    IoFreeIrp(irp);

    // Always return STATUS_MORE_PROCESSING_REQUIRED to
    // terminate the completion processing of the IRP.
    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketTcpConnect(PWSK_SOCKET socket, PVOID context, PSOCKADDR remote)
{
    // Get pointer to the socket's provider dispatch structure
    PWSK_PROVIDER_CONNECTION_DISPATCH dispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)(socket->Dispatch);

    // Allocate an IRP
    PIRP irp = IoAllocateIrp(1, FALSE);

    // Check result
    if (!irp)
    {
        // Return error
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    // Set the completion routine for the IRP
    IoSetCompletionRoutine(irp, OvpnSocketTcpConnectComplete, context, TRUE, TRUE, TRUE);

    LOG_INFO("TCP Connect initiated");

    // Initiate the connect operation on the socket
    return dispatch->WskConnect(socket, remote, 0, irp);
}

static
VOID
OvpnFreeMdl(PMDL Mdl)
{
    PMDL currentMdl, nextMdl;

    for (currentMdl = Mdl; currentMdl != NULL; currentMdl = nextMdl) {
        nextMdl = currentMdl->Next;
        if (currentMdl->MdlFlags & MDL_PAGES_LOCKED) {
            MmUnlockPages(currentMdl);
        }
        IoFreeMdl(currentMdl);
    }
}

static
VOID
OvpnSocketFinalizeTxWorkItem(_In_ OVPN_TX_WORKITEM* work, NTSTATUS ioStatus, ULONG bytesSent)
{
    NET_PACKET* packet = (NET_PACKET*)work->Packet;

    // indicate that packet has been sent and its structures can be reclaimed
    if (packet && !work->TcpDataPool)
        packet->Scratch = 1;

    if (work->TcpData)
        OvpnBufferPoolPut(work->TcpDataPool, work->TcpData);

    // if we allocated MDL for before send - free it
    if (work->Mdl)
        OvpnFreeMdl(work->Mdl);

    if (work->IoQueue != NULL) {
        WDFREQUEST request;
        NTSTATUS status;
        GOTO_IF_NOT_NT_SUCCESS(done, status, WdfIoQueueRetrieveNextRequest(work->IoQueue, &request));

        // report status and bytesSent to userspace
        WdfRequestCompleteWithInformation(request, ioStatus, bytesSent);
    }

done:
    OvpnBufferPoolPut(work->Pool, work);
}

_Function_class_(IO_COMPLETION_ROUTINE)
NTSTATUS
OvpnSocketSendComplete(_In_ PDEVICE_OBJECT deviceObj, _In_ PIRP irp, _In_ PVOID ctx)
{
    UNREFERENCED_PARAMETER(deviceObj);

    if (irp->IoStatus.Status != STATUS_SUCCESS) {
        LOG_ERROR("Send failed", TraceLoggingNTStatus(irp->IoStatus.Status, "status"));
    }

    OVPN_TX_WORKITEM* work = (OVPN_TX_WORKITEM*)ctx;
    ULONG bytesSend = (ULONG)(irp->IoStatus.Information);
    if (work->TcpData)
        bytesSend -= 2;
    OvpnSocketFinalizeTxWorkItem(work, irp->IoStatus.Status, bytesSend);

    IoFreeIrp(irp);

    return STATUS_MORE_PROCESSING_REQUIRED;
}

NTSTATUS
_Use_decl_annotations_
OvpnSocketSend(OvpnSocket* ovpnSocket, PMDL mdl, SIZE_T offset, SIZE_T length, OVPN_TX_WORKITEM* workItem) {
    PWSK_SOCKET socket = ovpnSocket->Socket;

    NTSTATUS status;

    PIRP irp = IoAllocateIrp(1, FALSE);
    if (irp == NULL) {
        LOG_ERROR("Failed to allocate IRP");
        OvpnSocketFinalizeTxWorkItem(workItem, STATUS_INSUFFICIENT_RESOURCES, 0);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if (socket == NULL) {
        LOG_ERROR("Socket is NULL");
        OvpnSocketFinalizeTxWorkItem(workItem, STATUS_INVALID_DEVICE_STATE, 0);
        IoFreeIrp(irp);
        return STATUS_INVALID_DEVICE_STATE;
    }

    // completion routine will be called in any case and will free IRP
    IoSetCompletionRoutine(irp, OvpnSocketSendComplete, workItem, TRUE, TRUE, TRUE);

    // prepend TCP packet with size, as required by OpenVPN protocol
    if (ovpnSocket->Tcp) {
        UCHAR* buf = (UCHAR*)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute);
        if (buf == NULL) {
            return STATUS_NO_MEMORY;
        }
        UINT16 len = RtlUshortByteSwap(length - 2);
        *(UINT16*)(buf + offset) = len;
    }

    WSK_BUF wskBuf = {};
    wskBuf.Length = length;
    wskBuf.Mdl = mdl;
    wskBuf.Offset = (ULONG)offset;

    if (ovpnSocket->Tcp) {
        PWSK_PROVIDER_CONNECTION_DISPATCH connectionDispatch = (PWSK_PROVIDER_CONNECTION_DISPATCH)socket->Dispatch;
        LOG_IF_NOT_NT_SUCCESS(status = connectionDispatch->WskSend(socket, &wskBuf, 0, irp));
    }
    else {
        PWSK_PROVIDER_DATAGRAM_DISPATCH datagramDispatch = (PWSK_PROVIDER_DATAGRAM_DISPATCH)socket->Dispatch;
        LOG_IF_NOT_NT_SUCCESS(status = datagramDispatch->WskSendTo(socket, &wskBuf, 0, NULL, 0, NULL, irp));
    }

    return status;
}
