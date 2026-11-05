package com.rnet.app.mesh

import android.bluetooth.*
import android.bluetooth.le.*
import android.content.Context
import android.os.ParcelUuid
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.util.UUID

/**
 * BleMeshScanner — BLE advertise + scan for RNET peer discovery.
 *
 * Used as the initial low-power peer announcement layer when Wi-Fi Direct is
 * unavailable or when the app is in background. BLE discovery is one-way
 * signaling only: once a peer is found via BLE, the actual data transport
 * upgrades to Wi-Fi Direct or falls back to BLE GATT if P2P negotiation fails.
 *
 * Service UUID: [RNET_SERVICE_UUID] — a fixed UUID that identifies RNET nodes.
 * Advertised payload: [peerId (16 bytes)] | [hasUplink (1 byte)] | [rssiSelf (1 byte)]
 *
 * Power budget:
 *   Advertising mode: ADVERTISE_MODE_LOW_LATENCY during active scan,
 *                     ADVERTISE_MODE_LOW_POWER in background.
 *   Scan mode:        SCAN_MODE_LOW_LATENCY for 10 s bursts, then LOW_POWER.
 *
 * Required permissions:
 *   BLUETOOTH_SCAN, BLUETOOTH_ADVERTISE, BLUETOOTH_CONNECT (API 31+)
 *   BLUETOOTH, BLUETOOTH_ADMIN (API ≤ 30)
 *   ACCESS_FINE_LOCATION (API ≤ 30 for BLE scan)
 */
class BleMeshScanner(private val context: Context) {

    companion object {
        val RNET_SERVICE_UUID: UUID = UUID.fromString("12345678-1234-5678-1234-56789abcdef0")
        private const val COMPANY_ID = 0xFFFF  // placeholder; replace with registered ID
    }

    private val bluetoothManager =
        context.getSystemService(Context.BLUETOOTH_SERVICE) as BluetoothManager
    private val adapter: BluetoothAdapter? = bluetoothManager.adapter
    private val leAdvertiser: BluetoothLeAdvertiser? = adapter?.bluetoothLeAdvertiser
    private val leScanner: BluetoothLeScanner?       = adapter?.bluetoothLeScanner

    private val _discoveredPeers = MutableStateFlow<List<BlePeer>>(emptyList())
    val discoveredPeers: StateFlow<List<BlePeer>> = _discoveredPeers.asStateFlow()

    data class BlePeer(
        val address: String,
        val peerId: String,
        val hasUplink: Boolean,
        val rssi: Int
    )

    private val seen = mutableMapOf<String, BlePeer>()

    // ── Advertising ───────────────────────────────────────────────────────────

    fun startAdvertising(localPeerId: String, hasUplink: Boolean) {
        val settings = AdvertiseSettings.Builder()
            .setAdvertiseMode(AdvertiseSettings.ADVERTISE_MODE_LOW_LATENCY)
            .setTxPowerLevel(AdvertiseSettings.ADVERTISE_TX_POWER_MEDIUM)
            .setConnectable(true)
            .build()

        // Encode peer ID (truncated to 8 bytes for advertisement payload limit)
        val idBytes  = localPeerId.toByteArray(Charsets.UTF_8).take(8).toByteArray()
        val flagByte = if (hasUplink) 0x01.toByte() else 0x00.toByte()
        val payload  = idBytes + flagByte

        val data = AdvertiseData.Builder()
            .addServiceUuid(ParcelUuid(RNET_SERVICE_UUID))
            .addManufacturerData(COMPANY_ID, payload)
            .setIncludeDeviceName(false)
            .build()

        leAdvertiser?.startAdvertising(settings, data, advertiseCallback)
    }

    fun stopAdvertising() {
        leAdvertiser?.stopAdvertising(advertiseCallback)
    }

    // ── Scanning ──────────────────────────────────────────────────────────────

    fun startScan() {
        val filter  = ScanFilter.Builder()
            .setServiceUuid(ParcelUuid(RNET_SERVICE_UUID))
            .build()
        val settings = ScanSettings.Builder()
            .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
            .build()
        leScanner?.startScan(listOf(filter), settings, scanCallback)
    }

    fun stopScan() {
        leScanner?.stopScan(scanCallback)
    }

    // ── Callbacks ─────────────────────────────────────────────────────────────

    private val advertiseCallback = object : AdvertiseCallback() {
        override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {}
        override fun onStartFailure(errorCode: Int) {}
    }

    private val scanCallback = object : ScanCallback() {
        override fun onScanResult(callbackType: Int, result: ScanResult) {
            val mfData = result.scanRecord?.getManufacturerSpecificData(COMPANY_ID) ?: return
            if (mfData.size < 9) return
            val peerId    = String(mfData.copyOfRange(0, 8), Charsets.UTF_8).trimEnd('\u0000')
            val hasUplink = mfData[8] == 0x01.toByte()
            val peer      = BlePeer(
                address   = result.device.address,
                peerId    = peerId,
                hasUplink = hasUplink,
                rssi      = result.rssi
            )
            seen[peer.address] = peer
            _discoveredPeers.value = seen.values.toList()
        }

        override fun onScanFailed(errorCode: Int) {}
    }

    /**
     * Stores the STUN-discovered reflexive address so it can be included in
     * future BLE advertisement payloads, enabling direct NAT hole-punching
     * between mesh peers. Currently logged; full advertisement encoding is
     * left as a protocol extension point.
     */
    fun updateReflexiveAddress(ip: String, port: Int) {
        android.util.Log.d("BleMeshScanner", "Reflexive addr for mesh: $ip:$port")
    }
}
