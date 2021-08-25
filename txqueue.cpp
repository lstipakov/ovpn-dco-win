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
#include <wdf.h>
#include <netadaptercx.h>

#include <net/virtualaddress.h>
#include <net/mdl.h>

#include "crypto.h"
#include "driver.h"
#include "trace.h"
#include "netringiterator.h"
#include "timer.h"
#include "txqueue.h"
#include "socket.h"

NTSTATUS
OvpnTxEncryptAndSend(OVPN_DEVICE* device, MDL* mdl, SIZE_T packetLen, SIZE_T firstFragmentOffset, OVPN_TX_WORKITEM* work)
{
    NTSTATUS status;

    // rest fragments have MDLs attached to the MDL of first fragment, so it enough to pass only first MDL to crypto
    // in-place encrypt, always with primary key
    SIZE_T offsetToCryptoHeader = OVPN_PAYLOAD_BACKFILL - device->CryptoContext.CryptoOverhead;
    LOG_IF_NOT_NT_SUCCESS(status = device->CryptoContext.Encrypt(&device->CryptoContext.Primary, mdl,
        packetLen - offsetToCryptoHeader,
        (ULONG)firstFragmentOffset + offsetToCryptoHeader));

    SIZE_T offsetToTransportOverhead = offsetToCryptoHeader - device->Socket.TransportOverhead;
    LOG_IF_NOT_NT_SUCCESS(status = OvpnSocketSend(&device->Socket, mdl,
        (ULONG)firstFragmentOffset + offsetToTransportOverhead,
        packetLen - offsetToTransportOverhead, work));

    return status;
}

_Must_inspect_result_
_Requires_shared_lock_held_(device->SpinLock)
NTSTATUS
OvpnTxTransmitUDPPacket(OVPN_DEVICE* device, OVPN_TX_WORKITEM* work, NET_RING_PACKET_ITERATOR* pi, OVPN_TXQUEUE* queue)
{
    NET_PACKET* packet = NetPacketIteratorGetPacket(pi);
    NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(pi);

    SIZE_T packetLen = 0;

    SIZE_T firstFragmentOffset = 0;
    SIZE_T firstFragmentLength = 0;
    UINT32 firstFragmentIndex = 0;
    UINT32 lastFragmentIndex = 0;
    VOID* firstFragmentVa = NULL;

    // iterate over all fragments to get packet length
    while (NetFragmentIteratorHasAny(&fi)) {
        NET_FRAGMENT* fragment = NetFragmentIteratorGetFragment(&fi);

        lastFragmentIndex = NetFragmentIteratorGetIndex(&fi);

        NET_FRAGMENT_VIRTUAL_ADDRESS* va = NetExtensionGetFragmentVirtualAddress(
            &queue->VirtualAddressExtension, lastFragmentIndex);

        if (packetLen == 0) {
            firstFragmentIndex = lastFragmentIndex;
            firstFragmentOffset = device->Socket.Tcp ? 0 : fragment->Offset;
            firstFragmentLength = fragment->ValidLength;
            firstFragmentVa = va->VirtualAddress;
        }

        packetLen += (SIZE_T)fragment->ValidLength;
        NetFragmentIteratorAdvance(&fi);
    }

    NET_FRAGMENT_MDL* fr_mdl = NetExtensionGetFragmentMdl(&queue->MdlExtension, firstFragmentIndex);
    MDL* mdl = fr_mdl->Mdl;

    // VirtualAddress mismatch (why NetAdapter, why?), allocate MDL
    if (mdl && (firstFragmentVa != MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute)))
        mdl = NULL;

    // create MDL if packet was bounced
    if (mdl == NULL) {
        mdl = IoAllocateMdl(firstFragmentVa, (ULONG)firstFragmentLength, FALSE, FALSE, NULL);
        // TODO: handle NULL
        MmBuildMdlForNonPagedPool(mdl);
        work->Mdl = mdl;
    }

    work->Packet = packet;
    work->Pool = device->TxPool;

    NTSTATUS status = OvpnTxEncryptAndSend(device, mdl, packetLen, firstFragmentOffset, work);

    NET_RING* const fragmentRing = NetRingCollectionGetFragmentRing(fi.Iterator.Rings);
    fragmentRing->NextIndex = fragmentRing->EndIndex;

    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, packetLen);

    return status;
}

_Must_inspect_result_
_Requires_shared_lock_held_(device->SpinLock)
NTSTATUS
OvpnTxTransmitTCPPacket(OVPN_DEVICE* device, OVPN_TX_WORKITEM* work, NET_RING_PACKET_ITERATOR* pi, OVPN_TXQUEUE* queue)
{
    NET_PACKET* packet = NetPacketIteratorGetPacket(pi);
    NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(pi);

    SIZE_T packetLen = 0;

    work->TcpData = (UCHAR*)OvpnBufferPoolGet(device->TcpDataTxPool);
    work->TcpDataPool = device->TcpDataTxPool;

    SIZE_T firstFragmentOffset = 0;
    UINT32 lastFragmentIndex = 0;

    // iterate over all fragments to get packet length
    while (NetFragmentIteratorHasAny(&fi)) {
        NET_FRAGMENT* fragment = NetFragmentIteratorGetFragment(&fi);

        lastFragmentIndex = NetFragmentIteratorGetIndex(&fi);

        NET_FRAGMENT_VIRTUAL_ADDRESS* va = NetExtensionGetFragmentVirtualAddress(
            &queue->VirtualAddressExtension, lastFragmentIndex);

        if (packetLen == 0)
            firstFragmentOffset = device->Socket.Tcp ? 0 : fragment->Offset;

        RtlCopyMemory(work->TcpData + packetLen, (UCHAR const*)va->VirtualAddress + fragment->Offset, fragment->ValidLength);

        packetLen += (SIZE_T)fragment->ValidLength;
        NetFragmentIteratorAdvance(&fi);
    }

    MDL* mdl = IoAllocateMdl(work->TcpData, (ULONG)packetLen, FALSE, FALSE, NULL);
    MmBuildMdlForNonPagedPool(mdl);
    work->Mdl = mdl;

    work->Packet = packet;
    work->Pool = device->TxPool;

    NTSTATUS status = OvpnTxEncryptAndSend(device, mdl, packetLen, firstFragmentOffset, work);

    NET_RING* const fragmentRing = NetRingCollectionGetFragmentRing(fi.Iterator.Rings);
    // update fragment ring's BeginIndex to indicate that we've processes all fragments
    fragmentRing->BeginIndex = lastFragmentIndex;

    InterlockedExchangeAddNoFence64(&device->Stats.TunBytesSent, packetLen);

    return status;
}

/*
 * Drain completed transmit packets to the OS
 */
static
VOID
OvpnTxComplete(POVPN_TXQUEUE queue)
{
    BOOLEAN retry = TRUE;

    // TODO: find a better solution that busy waiting, although this doesn't
    // seem to eat CPU and affect throughput much

    // without this loop, multiple TCP streams break tunnel
    // by exhausing ring and NetAdapterCx stops calling Tx Advance.
    while (retry == TRUE) {
        retry = FALSE;
        NET_RING_PACKET_ITERATOR pi = NetRingGetDrainPackets(queue->Rings);
        while (NetPacketIteratorHasAny(&pi)) {
            NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
            // has packet been sent?
            if (!packet->Scratch) {
                retry = TRUE;
                break;
            }

            NET_RING_FRAGMENT_ITERATOR fi = NetPacketIteratorGetFragments(&pi);
            for (UINT i = 0; i < packet->FragmentCount; ++i) {
                NetFragmentIteratorAdvance(&fi);
            }
            fi.Iterator.Rings->Rings[NetRingTypeFragment]->BeginIndex
                = NetFragmentIteratorGetIndex(&fi);

            NetPacketIteratorAdvance(&pi);
        }
        // drain packets from the ring and return ownership to OS
        NetPacketIteratorSet(&pi);

        //break;
    }

    /*
    NET_RING_FRAGMENT_ITERATOR fi = NetRingGetDrainFragments(queue->Rings);

    // advance fragment iterator to the end of drain section (NextIndex)
    NetFragmentIteratorAdvanceToTheEnd(&fi);

    // drain fragments from the ring and return ownership to OS
    NetFragmentIteratorSet(&fi);
    */
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueAdvance(NETPACKETQUEUE netPacketQueue)
{
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);

    POVPN_DEVICE device = OvpnGetDeviceContext(queue->Adapter->WdfDevice);
    bool packetSent = false;

    KIRQL kirql = ExAcquireSpinLockShared(&device->SpinLock);

    NET_RING_PACKET_ITERATOR pi = device->Socket.Tcp ?
        NetRingGetAllPackets(queue->Rings) : NetRingGetPostPackets(queue->Rings);

    if (!device->CryptoContext.Encrypt) {
        LOG_WARN("CryptoContext not initialized");
        goto done;
    }

    while (NetPacketIteratorHasAny(&pi)) {
        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        if (!packet->Ignore && !packet->Scratch) {

            OVPN_TX_WORKITEM* work = (OVPN_TX_WORKITEM*)OvpnBufferPoolGet(device->TxPool);
            if (work == NULL) {
                LOG_ERROR("TxPool exhausted");
                break;
            }

            NTSTATUS status;
            LOG_IF_NOT_NT_SUCCESS(status = device->Socket.Tcp ?
                OvpnTxTransmitTCPPacket(device, work, &pi, queue) : OvpnTxTransmitUDPPacket(device, work, &pi, queue));
            if (!NT_SUCCESS(status)) {
                InterlockedIncrementNoFence(&device->Stats.LostOutDataPackets);
                break;
            }
            else {
                packetSent = true;
            }
        }

        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // reset keepalive timer
    if (packetSent)
        OvpnTimerReset(device->KeepaliveXmitTimer, device->KeepaliveInterval);

done:
    ExReleaseSpinLockShared(&device->SpinLock, kirql);

    if (!device->Socket.Tcp)
        OvpnTxComplete(queue);
}

_Use_decl_annotations_
VOID
OvpnTxQueueInitialize(NETPACKETQUEUE netPacketQueue, POVPN_ADAPTER adapter)
{
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);
    queue->Adapter = adapter;
    queue->Rings = NetTxQueueGetRingCollection(netPacketQueue);

    NET_EXTENSION_QUERY extension;
    NET_EXTENSION_QUERY_INIT(&extension, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetTxQueueGetExtension(netPacketQueue, &extension, &queue->VirtualAddressExtension);

    NET_EXTENSION_QUERY extension1;
    NET_EXTENSION_QUERY_INIT(&extension1, NET_FRAGMENT_EXTENSION_MDL_NAME, NET_FRAGMENT_EXTENSION_MDL_VERSION_1, NetExtensionTypeFragment);
    NetTxQueueGetExtension(netPacketQueue, &extension1, &queue->MdlExtension);
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueSetNotificationEnabled(NETPACKETQUEUE queue, BOOLEAN notificationEnabled)
{
    UNREFERENCED_PARAMETER(queue);
    UNREFERENCED_PARAMETER(notificationEnabled);
}

_Use_decl_annotations_
VOID
OvpnEvtTxQueueCancel(NETPACKETQUEUE netPacketQueue)
{
    // mark all packets as "ignore"
    POVPN_TXQUEUE queue = OvpnGetTxQueueContext(netPacketQueue);
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    while (NetPacketIteratorHasAny(&pi)) {
        // we cannot modify Ignore here, otherwise Verifier will bark on us
        NetPacketIteratorGetPacket(&pi)->Scratch = 1;
        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // return all fragments' ownership back to netadapter
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(queue->Rings);
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
}
