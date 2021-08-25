#pragma once

#include <wdm.h>

#include "bufferpool.h"
#include "trace.h"

struct OVPN_BUFFER_POOL_IMPL
{
    LIST_ENTRY ListHead;
    KSPIN_LOCK Lock;
    UINT32 ItemSize;
};

struct OVPN_BUFFER_QUEUE_IMPL
{
    LIST_ENTRY ListHead;
    KSPIN_LOCK Lock;
};

NTSTATUS
OvpnBufferQueueCreate(OVPN_BUFFER_QUEUE* handle)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OVPN_BUFFER_QUEUE_IMPL), 'ovpn');
    if (!queue)
        return STATUS_MEMORY_NOT_ALLOCATED;

    InitializeListHead(&queue->ListHead);
    KeInitializeSpinLock(&queue->Lock);

    *handle = (OVPN_BUFFER_QUEUE)queue;
    return STATUS_SUCCESS;
}

VOID
OvpnBufferQueueEnqueue(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExInterlockedInsertTailList(&queue->ListHead, listEntry, &queue->Lock);
}

VOID
OvpnBufferQueueEnqueueHead(OVPN_BUFFER_QUEUE handle, PLIST_ENTRY listEntry)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExInterlockedInsertHeadList(&queue->ListHead, listEntry, &queue->Lock);
}

LIST_ENTRY*
OvpnBufferQueueDequeue(OVPN_BUFFER_QUEUE handle)
{
    LIST_ENTRY* entry = NULL;
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    entry = ExInterlockedRemoveHeadList(&queue->ListHead, &queue->Lock);

    return entry;
}

NTSTATUS
OvpnBufferPoolCreate(OVPN_BUFFER_POOL* handle, UINT32 itemSize, UINT32 itemsCount)
{
    NTSTATUS status = STATUS_SUCCESS;
    *handle = NULL;
    OVPN_BUFFER_POOL_IMPL* pool = NULL;
    UCHAR* mem = NULL;

    pool = (OVPN_BUFFER_POOL_IMPL*)ExAllocatePool2(POOL_FLAG_NON_PAGED, sizeof(OVPN_BUFFER_POOL_IMPL), 'ovpn');
    if (!pool) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto error;
    }

    InitializeListHead(&pool->ListHead);
    KeInitializeSpinLock(&pool->Lock);

    mem = (UCHAR*)ExAllocatePool2(POOL_FLAG_NON_PAGED, itemsCount * (sizeof(LIST_ENTRY) + itemSize), 'ovpn');
    if (!mem) {
        status = STATUS_MEMORY_NOT_ALLOCATED;
        goto error;
    }

    for (UINT32 i = 0; i < itemsCount; ++i) {
        LIST_ENTRY* entry = (LIST_ENTRY*)(mem + ((sizeof(LIST_ENTRY) + itemSize) * i));
        ExInterlockedInsertTailList(&pool->ListHead, entry, &pool->Lock);
    }

    *handle = (OVPN_BUFFER_POOL)pool;

    pool->ItemSize = itemSize;

    goto done;

error:
    if (mem)
        ExFreePoolWithTag(mem, 'ovpn');

    if (pool)
        ExFreePoolWithTag(pool, 'ovpn');

done:
    return status;
}

VOID*
OvpnBufferPoolGet(OVPN_BUFFER_POOL handle) {
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;
    LIST_ENTRY* entry = NULL;

    entry = ExInterlockedRemoveHeadList(&pool->ListHead, &pool->Lock);

    if (entry != NULL) {
        UCHAR* buf = (UCHAR*)entry + sizeof(LIST_ENTRY);
        RtlZeroMemory(buf, pool->ItemSize);
        return buf;
    }
    else
        return NULL;
}

VOID
OvpnBufferPoolPut(OVPN_BUFFER_POOL handle, VOID* data)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    LIST_ENTRY* entry = (LIST_ENTRY*)((PUCHAR)data - sizeof(LIST_ENTRY));
    ExInterlockedInsertTailList(&pool->ListHead, entry, &pool->Lock);
}

VOID
OvpnBufferPoolDelete(OVPN_BUFFER_POOL handle)
{
    OVPN_BUFFER_POOL_IMPL* pool = (OVPN_BUFFER_POOL_IMPL*)handle;

    ExFreePoolWithTag(pool, 'ovpn');
}

VOID
OvpnBufferQueueDelete(OVPN_BUFFER_QUEUE handle)
{
    OVPN_BUFFER_QUEUE_IMPL* queue = (OVPN_BUFFER_QUEUE_IMPL*)handle;

    ExFreePoolWithTag(queue, 'ovpn');
}