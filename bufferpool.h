#pragma once

#include "bufferpool.h"

DECLARE_HANDLE(OVPN_BUFFER_POOL);
DECLARE_HANDLE(OVPN_BUFFER_QUEUE);

NTSTATUS
OvpnBufferPoolCreate(OVPN_BUFFER_POOL* handle, UINT32 itemSize, UINT32 itemsCount);

VOID*
OvpnBufferPoolGet(OVPN_BUFFER_POOL handle);

VOID
OvpnBufferPoolPut(OVPN_BUFFER_POOL handle, VOID* data);

NTSTATUS
OvpnBufferQueueCreate(OVPN_BUFFER_QUEUE* handle);

VOID
OvpnBufferQueueEnqueue(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry);

VOID
OvpnBufferQueueEnqueueHead(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry);

LIST_ENTRY*
OvpnBufferQueueDequeue(OVPN_BUFFER_QUEUE handle);

VOID
OvpnBufferPoolDelete(OVPN_BUFFER_POOL handle);

VOID
OvpnBufferQueueDelete(OVPN_BUFFER_QUEUE handle);