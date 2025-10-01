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

#if defined(_KERNEL_MODE)
#include <ntddk.h>
#include <ntstrsafe.h>
#include "trace.h"
#else
#define WIN32_NO_STATUS     // keep windows.h from redefining STATUS_*
#include <windows.h>
#undef WIN32_NO_STATUS
#include <winternl.h>
#include <ntstatus.h>       // exposes STATUS_SUCCESS, NT_SUCCESS, etc.
#include <strsafe.h>

#define RtlStringCbLengthA StringCbLengthA

#endif

#include <bcrypt.h>

NTSTATUS OvpnCryptoExpandLabel(
    BCRYPT_ALG_HANDLE hkdfAlg,
    _In_reads_bytes_(32) const UCHAR* E_i,       // PRK (32 bytes for SHA-256)
    _In_ USHORT outLen,                          // bytes to derive
    _In_z_ const char* label,                    // "data_key" / "data_iv" / "datakey upd"
    _Out_writes_bytes_(outLen) UCHAR* outBytes
);

_IRQL_requires_max_(PASSIVE_LEVEL)
static
NTSTATUS OvpnCryptoMakeLabel(
    _Out_writes_bytes_to_(cbOut, *pcbWritten) UCHAR* out,
    _In_ ULONG cbOut,
    _Out_ ULONG* pcbWritten,
    _In_ USHORT L,
    _In_z_ const char* label);
