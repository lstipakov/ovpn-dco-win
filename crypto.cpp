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
#include <bcrypt.h>

#include "adapter.h"
#include "crypto.h"
#include "trace.h"
#include "pktid.h"

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptNone;

static
UINT
OvpnCryptoOpCompose(UINT opcode, UINT keyId)
{
    return (opcode << OVPN_OPCODE_SHIFT) | keyId;
}

static
UINT
OvpnProtoOp32Compose(UINT opcode, UINT keyId, UINT opPeerId)
{
    UINT op8 = OvpnCryptoOpCompose(opcode, keyId);

    if (opcode == OVPN_OP_DATA_V2)
        return (op8 << 24) | (opPeerId & 0x00FFFFFF);

    return op8;
}

_Use_decl_annotations_
NTSTATUS OvpnCryptoDecryptNone(OvpnCryptoKeySlot* keySlot, PMDL mdl, SIZE_T len, SIZE_T offset)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(mdl);
    UNREFERENCED_PARAMETER(len);
    UNREFERENCED_PARAMETER(offset);

    return STATUS_SUCCESS;
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptNone;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptNone(OvpnCryptoKeySlot* keySlot, PMDL mdl, SIZE_T len, SIZE_T offset)
{
    UNREFERENCED_PARAMETER(keySlot);
    UNREFERENCED_PARAMETER(len);

    // prepend with opcode, key-id and peer-id
    UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, 0, 0);
    op = RtlUlongByteSwap(op);
    *(UINT32*)((UCHAR*)MmGetMdlVirtualAddress(mdl) + offset) = op;

    // prepend with pktid
    static ULONG pktid;
    ULONG pktidNetwork = RtlUlongByteSwap(pktid++);
    *(UINT32*)((UCHAR*)MmGetMdlVirtualAddress(mdl) + offset + OVPN_DATA_V2_LEN) = pktidNetwork;

    return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoInitAlgHandle(BCRYPT_ALG_HANDLE* algHandle)
{
    NTSTATUS status;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptOpenAlgorithmProvider(algHandle, BCRYPT_AES_ALGORITHM, NULL, BCRYPT_PROV_DISPATCH));
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(*algHandle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM, sizeof(BCRYPT_CHAIN_MODE_GCM), 0));

done:
    return status;
}

OVPN_CRYPTO_DECRYPT OvpnCryptoDecryptAEAD;

struct WorkingBuf
{
    struct Chunk
    {
        PUCHAR Buf;
        ULONG Len;
    } Chunks[16];
    ULONG ChunksNum;

    ULONG Len;
    UCHAR Buf[16];
};

static VOID
OvpnCryptoAddChunk(WorkingBuf* workingBuf, ULONG chunkLen, UCHAR* buf)
{
    // add chunk data to working buf
    RtlCopyMemory((PVOID)(workingBuf->Buf + workingBuf->Len), (PVOID)buf, chunkLen);

    // update working buf chunks
    WorkingBuf::Chunk* chunk = &workingBuf->Chunks[workingBuf->ChunksNum];
    chunk->Len = chunkLen;
    chunk->Buf = buf;
    ++workingBuf->ChunksNum;

    // update working buf length
    workingBuf->Len += chunkLen;
}

static NTSTATUS
EncryptDecryptWorkingBuf(BOOLEAN encrypt, WorkingBuf* workingBuf, BCRYPT_KEY_HANDLE encKey, PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo, UCHAR* nonce)
{
    NTSTATUS status = STATUS_SUCCESS;

    // encrypt working buf
    ULONG bytesDone = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, encrypt ?
        BCryptEncrypt(encKey, workingBuf->Buf, workingBuf->Len, authInfo, nonce, AES_GCM_NONCE_LEN, workingBuf->Buf, workingBuf->Len, &bytesDone, 0) :
        BCryptDecrypt(encKey, workingBuf->Buf, workingBuf->Len, authInfo, nonce, AES_GCM_NONCE_LEN, workingBuf->Buf, workingBuf->Len, &bytesDone, 0));

    ULONG count = 0;
    // copy ciphertext back to corresponding MDLs
    for (ULONG i = 0; i < workingBuf->ChunksNum; ++i) {
        WorkingBuf::Chunk* chunk = &workingBuf->Chunks[i];
        RtlCopyMemory(chunk->Buf, workingBuf->Buf + count, chunk->Len);
        count += chunk->Len;
    }

    // clear working buffer
    workingBuf->Len = 0;
    workingBuf->ChunksNum = 0;

done:
    return status;
}

static NTSTATUS
OvpnCryptoEncryptDecryptMdl(BOOLEAN encrypt, PUCHAR buf, ULONG len, WorkingBuf* workingBuf, BCRYPT_KEY_HANDLE encKey, PBCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo, UCHAR* nonce, BOOLEAN last)
{
    NTSTATUS status = STATUS_SUCCESS;

    // try to fill working buf
    if (workingBuf->Len > 0) {
        ULONG workingBufCapacity = AES_BLOCK_SIZE - workingBuf->Len;
        BOOLEAN workingBufWillBeFull = len >= workingBufCapacity;
        ULONG chunkLen = workingBufWillBeFull ? workingBufCapacity : len;

        OvpnCryptoAddChunk(workingBuf, chunkLen, buf);

        len -= chunkLen;
        buf += chunkLen;

        // if the whole MDL will be encrypted as part of working buf and
        // this is the last MDL, remove CHAIN flag
        if (len == 0 && last)
            authInfo->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

        if (workingBufWillBeFull || ((len == 0) && last))
            GOTO_IF_NOT_NT_SUCCESS(done, status, EncryptDecryptWorkingBuf(encrypt, workingBuf, encKey, authInfo, nonce));

        if (len == 0) {
            goto done;
        }
    }

    // encrypt (part of) MDL

    if (last)
        authInfo->dwFlags &= ~BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

    ULONG bufLenToEncrypt = (len / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
    if ((bufLenToEncrypt == len) || last) {
        // MDL len is multiple of AES_BLOCK_SIZE or this is the last MDL, no need to use working buf
        ULONG bytesDone = 0;
        status = encrypt ? BCryptEncrypt(encKey, buf, len, authInfo, nonce, AES_GCM_NONCE_LEN, buf, len, &bytesDone, 0) :
            BCryptDecrypt(encKey, buf, len, authInfo, nonce, AES_GCM_NONCE_LEN, buf, len, &bytesDone, 0);
        GOTO_IF_NOT_NT_SUCCESS(done, status, status);
    }
    else {
        // partially encrypt MDL, copy rest into working buf
        ULONG bytesDone = 0;
        status = encrypt ? BCryptEncrypt(encKey, buf, bufLenToEncrypt, authInfo, nonce, AES_GCM_NONCE_LEN, buf, bufLenToEncrypt, &bytesDone, 0) :
            BCryptDecrypt(encKey, buf, bufLenToEncrypt, authInfo, nonce, AES_GCM_NONCE_LEN, buf, bufLenToEncrypt, &bytesDone, 0);
        GOTO_IF_NOT_NT_SUCCESS(done, status, status);
        buf += bufLenToEncrypt;

        OvpnCryptoAddChunk(workingBuf, len - bufLenToEncrypt, buf);
    }

done:
    if (status != STATUS_SUCCESS) {
        workingBuf->Len = 0;
        workingBuf->ChunksNum = 0;
    }

    return status;
}

#define GET_SYSTEM_ADDRESS_MDL(buf, mdl) { \
    buf = (PUCHAR)MmGetSystemAddressForMdlSafe(mdl, LowPagePriority | MdlMappingNoExecute); \
    if (buf == NULL) { \
        LOG_ERROR("MmGetSystemAddressForMdlSafe() returned NULL"); \
        return STATUS_DATA_ERROR; \
    } \
}

static
NTSTATUS
OvpnCryptoAEADDoWork(BOOLEAN encrypt, OvpnCryptoKeySlot* keySlot, PMDL mdl, SIZE_T len, SIZE_T offset)
{
    /*
    AEAD Nonce :

     [Packet ID] [HMAC keying material]
     [4 bytes  ] [8 bytes             ]
     [AEAD nonce total : 12 bytes     ]

    TLS wire protocol :

     [DATA_V2 opcode] [Packet ID] [AEAD Auth tag] [ciphertext]
     [4 bytes       ] [4 bytes  ] [16 bytes     ]
     [AEAD additional data(AD)  ]
    */

    NTSTATUS status = STATUS_SUCCESS;

    if (len < AEAD_CRYPTO_OVERHEAD) {
        LOG_WARN("Packet too short", TraceLoggingValue(len, "len"));
        return STATUS_DATA_ERROR;
    }

    PUCHAR buf;
    GET_SYSTEM_ADDRESS_MDL(buf, mdl);

    buf += offset;

    UCHAR nonce[OVPN_PKTID_LEN + OVPN_NONCE_TAIL_LEN];
    if (encrypt) {
        // prepend with opcode, key-id and peer-id
        UINT32 op = OvpnProtoOp32Compose(OVPN_OP_DATA_V2, keySlot->KeyId, keySlot->PeerId);
        op = RtlUlongByteSwap(op);
        *(UINT32*)(buf) = op;

        // calculate pktid
        UINT32 pktid;
        GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnPktidXmitNext(&keySlot->PktidXmit, &pktid));
        ULONG pktidNetwork = RtlUlongByteSwap(pktid);

        // calculate nonce, which is pktid + nonce_tail
        RtlCopyMemory(nonce, &pktidNetwork, OVPN_PKTID_LEN);
        RtlCopyMemory(nonce + OVPN_PKTID_LEN, keySlot->EncNonceTail, OVPN_NONCE_TAIL_LEN);

        // prepend with pktid
        *(UINT32*)(buf + OVPN_DATA_V2_LEN) = pktidNetwork;
    }
    else {
        RtlCopyMemory(nonce, buf + OVPN_DATA_V2_LEN, OVPN_PKTID_LEN);
        RtlCopyMemory(nonce + OVPN_PKTID_LEN, &keySlot->DecNonceTail, sizeof(keySlot->DecNonceTail));

        // TODO: verify pktid
    }

    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
    BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
    authInfo.pbNonce = nonce;
    authInfo.cbNonce = sizeof(nonce);
    authInfo.pbTag = buf + OVPN_DATA_V2_LEN + OVPN_PKTID_LEN;
    authInfo.cbTag = AEAD_AUTH_TAG_LEN;
    authInfo.pbAuthData = buf;
    authInfo.cbAuthData = OVPN_DATA_V2_LEN + OVPN_PKTID_LEN;

    buf += AEAD_CRYPTO_OVERHEAD;

    len -= AEAD_CRYPTO_OVERHEAD;

    if ((mdl->Next == NULL) || (!encrypt)) {
        // TODO: while on RX path packets seem to come in one fragment/MDL
        // and chaining decryption is not needed, figure out why on some machines (like AWS)
        // TCP performance drops dramatically when chaining decryption is used.

        if ((len + AEAD_CRYPTO_OVERHEAD) > MmGetMdlByteCount(mdl)) {
            LOG_WARN("Length exceeds MDL length", TraceLoggingValue(len + AEAD_CRYPTO_OVERHEAD, "len"), TraceLoggingValue(MmGetMdlByteCount(mdl), "mdlByteCount"));
            status = STATUS_BAD_DATA;
            goto done;
        }

        // non-chaining mode
        ULONG bytesDone = 0;
        GOTO_IF_NOT_NT_SUCCESS(done, status, encrypt ?
            BCryptEncrypt(keySlot->EncKey, buf, (ULONG)len, &authInfo, NULL, 0, buf, (ULONG)len, &bytesDone, 0) :
            BCryptDecrypt(keySlot->DecKey, buf, (ULONG)len, &authInfo, NULL, 0, buf, (ULONG)len, &bytesDone, 0)
        );
    }
    else {
        UCHAR macContext[16];

        authInfo.pbMacContext = macContext;
        authInfo.cbMacContext = AEAD_AUTH_TAG_LEN;
        authInfo.dwFlags = BCRYPT_AUTH_MODE_CHAIN_CALLS_FLAG;

        WorkingBuf workingBuf;
        workingBuf.Len = 0;
        workingBuf.ChunksNum = 0;

        int mdlCount = 0;

        BOOLEAN firstMdl = TRUE;
        while (mdl != NULL) {
            ULONG mdlLen = MmGetMdlByteCount(mdl);
            if (firstMdl) {
                mdlLen -= AEAD_CRYPTO_OVERHEAD; // account for crypto overhead/openvpn wrapping
                mdlLen -= (ULONG)offset;
            }
            firstMdl = FALSE;

            ++mdlCount;

            BOOLEAN last = (mdl->Next == NULL) || (len == 0);
            ULONG bytesToCrypt = min((ULONG)len, mdlLen);
            OvpnCryptoEncryptDecryptMdl(encrypt, buf, bytesToCrypt, &workingBuf,
                encrypt ? keySlot->EncKey : keySlot->DecKey, &authInfo, nonce, last);

            len -= bytesToCrypt;

            mdl = len > 0 ? mdl->Next : NULL;

            if (mdl)
                GET_SYSTEM_ADDRESS_MDL(buf, mdl);
        }
    }

done:
    return status;
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoDecryptAEAD(OvpnCryptoKeySlot* keySlot, PMDL mdl, SIZE_T len, SIZE_T offset)
{
    return OvpnCryptoAEADDoWork(FALSE, keySlot, mdl, len, offset);
}

OVPN_CRYPTO_ENCRYPT OvpnCryptoEncryptAEAD;

_Use_decl_annotations_
NTSTATUS
OvpnCryptoEncryptAEAD(OvpnCryptoKeySlot* keySlot, PMDL mdl, SIZE_T len, SIZE_T offset)
{
    return OvpnCryptoAEADDoWork(TRUE, keySlot, mdl, len, offset);
}

_Use_decl_annotations_
NTSTATUS
OvpnCryptoNewKey(OvpnCryptoContext* cryptoContext, POVPN_CRYPTO_DATA cryptoData)
{
    OvpnCryptoKeySlot* keySlot = NULL;
    NTSTATUS status = STATUS_SUCCESS;

    if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_PRIMARY) {
        keySlot = &cryptoContext->Primary;
    }
    else if (cryptoData->KeySlot == OVPN_KEY_SLOT::OVPN_KEY_SLOT_SECONDARY) {
        keySlot = &cryptoContext->Secondary;
    }
    else {
        LOG_ERROR("Invalid key slot", TraceLoggingValue((int)cryptoData->KeySlot, "keySlot"));
        return STATUS_INVALID_DEVICE_REQUEST;
    }

    if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_AES_GCM) {
        // destroy previous keys
        if (keySlot->EncKey) {
            BCryptDestroyKey(keySlot->EncKey);
            keySlot->EncKey = NULL;
        }

        if (keySlot->DecKey) {
            BCryptDestroyKey(keySlot->DecKey);
            keySlot->DecKey = NULL;
        }

        // generate keys from key materials
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(cryptoContext->AlgHandle, &keySlot->EncKey, NULL, 0, cryptoData->Encrypt.Key, cryptoData->Encrypt.KeyLen, 0));
        GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(cryptoContext->AlgHandle, &keySlot->DecKey, NULL, 0, cryptoData->Decrypt.Key, cryptoData->Decrypt.KeyLen, 0));

        // copy nonce tails
        RtlCopyMemory(keySlot->EncNonceTail, cryptoData->Encrypt.NonceTail, sizeof(cryptoData->Encrypt.NonceTail));
        RtlCopyMemory(keySlot->DecNonceTail, cryptoData->Decrypt.NonceTail, sizeof(cryptoData->Decrypt.NonceTail));

        cryptoContext->Encrypt = OvpnCryptoEncryptAEAD;
        cryptoContext->Decrypt = OvpnCryptoDecryptAEAD;

        keySlot->KeyId = cryptoData->KeyId;
        keySlot->PeerId = cryptoData->PeerId;

        cryptoContext->CryptoOverhead = AEAD_CRYPTO_OVERHEAD;

        LOG_INFO("Key installed", TraceLoggingValue(cryptoData->KeyId, "KeyId"), TraceLoggingValue(cryptoData->KeyId, "PeerId"));
    }
    else if (cryptoData->CipherAlg == OVPN_CIPHER_ALG_NONE) {
        cryptoContext->Encrypt = OvpnCryptoEncryptNone;
        cryptoContext->Decrypt = OvpnCryptoDecryptNone;

        cryptoContext->CryptoOverhead = NONE_CRYPTO_OVERHEAD;

        LOG_INFO("Using cipher none");
    }
    else {
        status = STATUS_INVALID_DEVICE_REQUEST;
        LOG_ERROR("Unknown OVPN_CIPHER_ALG", TraceLoggingValue((int)cryptoData->CipherAlg, "CipherAlg"));
        goto done;
    }

    // reset pktid for a new key
    RtlZeroMemory(&keySlot->PktidXmit, sizeof(keySlot->PktidXmit));
    RtlZeroMemory(&keySlot->PktidRecv, sizeof(keySlot->PktidRecv));

done:
    return status;
}

_Use_decl_annotations_
OvpnCryptoKeySlot*
OvpnCryptoKeySlotFromKeyId(OvpnCryptoContext* cryptoContext, UINT keyId)
{
    if (cryptoContext->Primary.KeyId == keyId)
        return &cryptoContext->Primary;
    else if (cryptoContext->Secondary.KeyId == keyId) {
        return &cryptoContext->Secondary;
    }

    LOG_ERROR("No KeySlot for KeyId", TraceLoggingValue(keyId, "KeyId"));

    return NULL;
}

_Use_decl_annotations_
VOID
OvpnCryptoSwapKeys(OvpnCryptoContext* cryptoContext)
{
    OvpnCryptoKeySlot keySlot;

    RtlCopyMemory(&keySlot, &cryptoContext->Primary, sizeof(keySlot));
    RtlCopyMemory(&cryptoContext->Primary, &cryptoContext->Secondary, sizeof(keySlot));
    RtlCopyMemory(&cryptoContext->Secondary, &keySlot, sizeof(keySlot));

    LOG_INFO("Key swapped", TraceLoggingValue(cryptoContext->Primary.KeyId, "key1"), TraceLoggingValue(cryptoContext->Secondary.KeyId, "key2"));
}

_Use_decl_annotations_
VOID
OvpnCryptoUninit(OvpnCryptoContext* cryptoContext)
{
    if (cryptoContext->Primary.EncKey) {
        BCryptDestroyKey(cryptoContext->Primary.EncKey);
    }

    if (cryptoContext->Primary.DecKey) {
        BCryptDestroyKey(cryptoContext->Primary.DecKey);
    }

    if (cryptoContext->Secondary.EncKey) {
        BCryptDestroyKey(cryptoContext->Secondary.EncKey);
    }

    if (cryptoContext->Secondary.DecKey) {
        BCryptDestroyKey(cryptoContext->Secondary.DecKey);
    }

    RtlZeroMemory(cryptoContext, sizeof(OvpnCryptoContext));
}
