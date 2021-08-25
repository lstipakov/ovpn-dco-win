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
#include <net/returncontext.h>

#include "driver.h"
#include "rxqueue.h"
#include "netringiterator.h"
#include "trace.h"

EVT_PACKET_QUEUE_ADVANCE OvpnEvtRxQueueAdvance;

_Use_decl_annotations_
VOID
OvpnEvtRxQueueAdvance(NETPACKETQUEUE netPacketQueue)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    OVPN_DEVICE* device = OvpnGetDeviceContext(queue->Adapter->WdfDevice);

    NET_RING_FRAGMENT_ITERATOR fi = NetRingGetAllFragments(queue->Rings);
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);

    NET_FRAGMENT* fragment = NULL;
    NET_FRAGMENT_RETURN_CONTEXT* returnCtx = NULL;

    while (NetFragmentIteratorHasAny(&fi)) {
        // get RX workitem, if any
        LIST_ENTRY* entry = OvpnBufferQueueDequeue(device->RxDataQueue);
        if (entry == NULL)
            break;
        OVPN_RX_WORKITEM* workItem = CONTAINING_RECORD(entry, OVPN_RX_WORKITEM, ListEntry);

        fragment = NetFragmentIteratorGetFragment(&fi);

        fragment->ValidLength = workItem->Length;
        fragment->Offset = workItem->Offset;
        fragment->Capacity = fragment->ValidLength + workItem->Offset;

        NET_FRAGMENT_VIRTUAL_ADDRESS* virtualAddr = NetExtensionGetFragmentVirtualAddress(&queue->VirtualAddressExtension, NetFragmentIteratorGetIndex(&fi));
        virtualAddr->VirtualAddress = (PUCHAR)MmGetSystemAddressForMdlSafe(workItem->Mdl, LowPagePriority | MdlMappingNoExecute);

        // TODO: handle case when packet (DataIndication) contains multiple fragments
        NET_PACKET* packet = NetPacketIteratorGetPacket(&pi);
        packet->FragmentIndex = NetFragmentIteratorGetIndex(&fi);
        packet->FragmentCount = 1;

        packet->Layout = {};

        // NetAdapter will call ReturnRxBuffer callback when it is done with buffers, there we return RX workitem back to the pool
        returnCtx = NetExtensionGetFragmentReturnContext(&queue->ReturnContextExtension, NetFragmentIteratorGetIndex(&fi));
        returnCtx->Handle = (NET_FRAGMENT_RETURN_CONTEXT_HANDLE)workItem;

        NetFragmentIteratorAdvance(&fi);
        NetPacketIteratorAdvance(&pi);
    }

    NetFragmentIteratorSet(&fi);
    NetPacketIteratorSet(&pi);
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueSetNotificationEnabled(NETPACKETQUEUE queue, BOOLEAN notificationEnabled)
{
    POVPN_RXQUEUE rxQueue = OvpnGetRxQueueContext(queue);

    InterlockedExchangeNoFence(&rxQueue->NotificationEnabled, notificationEnabled);
}

_Use_decl_annotations_
VOID
OvpnEvtRxQueueCancel(NETPACKETQUEUE netPacketQueue)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);

    // mark all packets as "ignore"
    NET_RING_PACKET_ITERATOR pi = NetRingGetAllPackets(queue->Rings);
    while (NetPacketIteratorHasAny(&pi)) {
        NetPacketIteratorGetPacket(&pi)->Ignore = 1;
        NetPacketIteratorAdvance(&pi);
    }
    NetPacketIteratorSet(&pi);

    // return all fragments' ownership back to netadapter
    NET_RING* fragmentRing = NetRingCollectionGetFragmentRing(queue->Rings);
    fragmentRing->BeginIndex = fragmentRing->EndIndex;
}

_Use_decl_annotations_
VOID
OvpnRxQueueInitialize(NETPACKETQUEUE netPacketQueue, POVPN_ADAPTER adapter)
{
    POVPN_RXQUEUE queue = OvpnGetRxQueueContext(netPacketQueue);
    queue->Adapter = adapter;
    queue->Rings = NetRxQueueGetRingCollection(netPacketQueue);

    NET_EXTENSION_QUERY vaExtension;
    NET_EXTENSION_QUERY_INIT(&vaExtension, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_NAME, NET_FRAGMENT_EXTENSION_VIRTUAL_ADDRESS_VERSION_1, NetExtensionTypeFragment);
    NetRxQueueGetExtension(netPacketQueue, &vaExtension, &queue->VirtualAddressExtension);

    NET_EXTENSION_QUERY returnCtxExtension;
    NET_EXTENSION_QUERY_INIT(&returnCtxExtension, NET_FRAGMENT_EXTENSION_RETURN_CONTEXT_NAME, NET_FRAGMENT_EXTENSION_RETURN_CONTEXT_VERSION_1, NetExtensionTypeFragment);
    NetRxQueueGetExtension(netPacketQueue, &returnCtxExtension, &queue->ReturnContextExtension);
}
