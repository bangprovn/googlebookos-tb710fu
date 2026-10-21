// SPDX-License-Identifier: Apache-2.0
// Client subset for mica build16471258. This is not the public AOSP interface.
// Binder adds FIRST_CALL_TRANSACTION to the explicit zero-based ID below.
// The donor lookup uses transaction17 with a CID; no clear method is assumed.
package android.system.virtualizationservice_internal;
interface IVirtualizationServiceInternal {
    void setDisplayService(int cid, IBinder ibinder) = 15;
}
