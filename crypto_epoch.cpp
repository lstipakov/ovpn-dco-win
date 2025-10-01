/*
 *  ovpn-dco-win OpenVPN protocol accelerator for Windows
 *
 *  Copyright (C) 2025- OpenVPN Inc <sales@openvpn.net>
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

#include "crypto_epoch.h"
#include "trace.h"

// Derive bytes via HKDF-Expand with PRK = E_i, using bcrypt HKDF.
// info = OvpnMakeLabel(L, label)
_Use_decl_annotations_
NTSTATUS OvpnCryptoExpandLabel(
    BCRYPT_ALG_HANDLE hkdfAlg,
    const UCHAR* E_i,       // PRK (32 bytes for SHA-256)
    USHORT outLen,          // bytes to derive
    const char* label,      // "data_key" / "data_iv" / "datakey upd"
    UCHAR* outBytes
)
{
    NTSTATUS status = STATUS_SUCCESS;

    BCRYPT_KEY_HANDLE hKey = NULL;

    // create key handle with PRK bytes
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptGenerateSymmetricKey(hkdfAlg, &hKey, NULL, 0, (PUCHAR)E_i, 32, 0));

    // select SHA-256
    // BCRYPT_SHA256_ALGORITHM is a wide literal; sizeof(..) includes the NUL in bytes.
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(hKey, BCRYPT_HKDF_HASH_ALGORITHM, (PUCHAR)BCRYPT_SHA256_ALGORITHM, (ULONG)sizeof(BCRYPT_SHA256_ALGORITHM), 0));

    // tell HKDF we're already supplying the PRK in the key handle:
    // passing NULL,0 just switches to "PRK is finalized" mode.
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptSetProperty(hKey, BCRYPT_HKDF_PRK_AND_FINALIZE, NULL, 0, 0));

    // build info = OvpnLabel(outLen, "data_key"/"data_iv")
    UCHAR info[2 + 1 + 64 + 1 + 255]; // enough for our labels
    ULONG infoLen = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, OvpnCryptoMakeLabel(info, (ULONG)sizeof(info), &infoLen, outLen, label));

    // prepare KDF params
    BCryptBuffer infoBuf;
    BCryptBufferDesc desc;

    RtlZeroMemory(&infoBuf, sizeof(infoBuf));
    RtlZeroMemory(&desc, sizeof(desc));

    infoBuf.cbBuffer = infoLen;
    infoBuf.BufferType = KDF_HKDF_INFO;
    infoBuf.pvBuffer = info;

    desc.ulVersion = BCRYPTBUFFER_VERSION;
    desc.cBuffers = 1;
    desc.pBuffers = &infoBuf;

    // derive
    ULONG got = 0;
    GOTO_IF_NOT_NT_SUCCESS(done, status, BCryptKeyDerivation(hKey, &desc, outBytes, outLen, &got, 0));
    if (got != outLen) {
        status = STATUS_INTERNAL_ERROR;
    }

done:
    if (hKey) BCryptDestroyKey(hKey);
    return status;
}

// Build TLS 1.3-style label with "ovpn " prefix, into caller buffer.
// struct {
//   uint16 length = L;
//   opaque label<6..255> = "ovpn " + Label;
//   opaque context<0..255>;
// } OvpnLabel;
_Use_decl_annotations_
NTSTATUS OvpnCryptoMakeLabel(
    UCHAR* out,
    ULONG cbOut,
    ULONG* pcbWritten,
    USHORT L,
    const char* label)
{
    NTSTATUS status = STATUS_SUCCESS;

    static const char prefix[] = "ovpn ";

    const size_t prefixLen = sizeof(prefix) - 1;
    size_t labelLen = 0;

    GOTO_IF_NOT_NT_SUCCESS(done, status, RtlStringCbLengthA(label, 256, &labelLen)); // labels are tiny, 256 is safe

    *pcbWritten = 0;

    // Total encoded label length = "ovpn " + label
    size_t totalLabelLen = prefixLen + labelLen;
    if (totalLabelLen < 6 || totalLabelLen > 255) {
        status = STATUS_INVALID_PARAMETER;
        goto done;
    }

    // total = 2(length) + 1(totalLabelLen) + totalLabelLen + 1(ctxLen=0)
    ULONG need = 2 + 1 + (ULONG)totalLabelLen + 1;
    if (cbOut < need) {
        status = STATUS_BUFFER_TOO_SMALL;
        goto done;
    }

    ULONG p = 0;
    out[p++] = (UCHAR)(L >> 8);
    out[p++] = (UCHAR)(L & 0xFF);
    out[p++] = (UCHAR)totalLabelLen;

    // "ovpn "
    RtlCopyMemory(out + p, prefix, prefixLen);
    p += (ULONG)prefixLen;


    // Label
    RtlCopyMemory(out + p, label, labelLen);
    p += (ULONG)labelLen;

    // context length = 0
    out[p++] = 0;

    *pcbWritten = p;

done:
    return status;
}