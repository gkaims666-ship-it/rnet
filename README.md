# RNET — Resilient Network Transport Framework (Android + iOS KMP)

> **Platforms:** Android API 29–36+ · iOS 16+  
> **Architectures:** arm64-v8a, armeabi-v7a, x86_64 (Android) · arm64 device + arm64 simulator (iOS)  
> **Design goal:** Deterministic packet delivery in extreme environments with up to 40% physical packet loss.

---

## Table of Contents

1. [System Architecture Overview](#1-system-architecture-overview)
2. [Reed-Solomon Forward Error Correction — Mathematical Principles](#2-reed-solomon-forward-error-correction--mathematical-principles)
3. [Multi-Path QUIC Transport Binding Mechanics](#3-multi-path-quic-transport-binding-mechanics)
4. [Wi-Fi Direct Mesh State Machine](#4-wi-fi-direct-mesh-state-machine)
5. [Post-Quantum Hybrid Cryptography](#5-post-quantum-hybrid-cryptography)
6. [Hotspot Gateway & Consent Architecture](#6-hotspot-gateway--consent-architecture)
7. [Deployment & Build Guide](#7-deployment--build-guide)
8. [Required Secrets for CI/CD](#8-required-secrets-for-cicd)

---
---

# ENGLISH

---

## 1. System Architecture Overview

RNET is a modular Android network transport framework composed of six independently testable layers that communicate through Kotlin coroutine `Flow` interfaces:

```
┌─────────────────────────────────────────────────────────────┐
│                      Jetpack Compose UI                      │
│         (MainActivity · MainViewModel · ConsentActivity)     │
└────────────────────────┬────────────────────────────────────┘
                         │ StateFlow<UiState>
┌────────────────────────▼────────────────────────────────────┐
│                  RnetForegroundService                       │
│           (DATA_SYNC foreground service lifecycle)           │
└──────┬──────────────────────────────────────────┬───────────┘
       │                                          │
┌──────▼───────┐                      ┌───────────▼──────────┐
│  MeshRouter  │◄────────────────────►│   MultipathEngine    │
│  (ad-hoc     │  relay/gateway data  │   (QUIC · FEC · MTU) │
│   fallback)  │                      │                       │
└──────┬───────┘                      └───────────┬───────────┘
       │                                          │
┌──────▼────────────────┐             ┌───────────▼──────────┐
│  WifiDirectMesh +      │             │   EndpointRouter      │
│  BleMeshScanner        │             │   (goodput scoring)   │
│  (P2P · BLE discovery) │             │                       │
└───────────────────────┘             └───────────────────────┘
```

**Data path — normal cellular operation:**

```
App payload
  → MultipathEngine.send(payload)
  → ReedSolomonFec.encode()          [k=6 data shards + 4 parity shards]
  → SessionCipher.encrypt()          [AES-256-GCM, fresh 12-byte IV]
  → UDP datagram × 10 paths          [one DatagramSocket per Network]
  → Remote server
  ← server response
  → SessionCipher.decrypt()
  → ReedSolomonFec.reconstruct()     [recover from ≤4 lost shards]
  → MultipathEngine.inbound Flow
  → App consumer
```

**Data path — mesh fallback (no cellular uplink):**

```
App payload
  → MeshRouter.send()
  → WifiDirectMesh.broadcast()       [TCP socket to Group Owner]
  → Gateway node's MeshRouter
  → Gateway's MultipathEngine.send() [gateway has cellular uplink]
  → Remote server
  ← reply path reversed
```

---

## 2. Reed-Solomon Forward Error Correction — Mathematical Principles

### Galois Field GF(2⁸)

All arithmetic in the RS codec operates over the finite field **GF(2⁸)**, also written **GF(256)**. Elements of GF(2⁸) are polynomials of degree ≤ 7 with binary coefficients, reduced modulo the primitive polynomial:

```
p(x) = x⁸ + x⁴ + x³ + x² + 1   (0x11D in hex)
```

**Multiplication** uses pre-computed logarithm and exponent tables:

```
gf_mul(a, b) = gf_exp[ gf_log[a] + gf_log[b] ]   for a,b ≠ 0
gf_mul(a, 0) = gf_mul(0, b) = 0
```

This reduces field multiplication to two table lookups and an addition, which executes in O(1) with no branch on modern ARM cores.

**Inversion:**

```
gf_inv(a) = gf_exp[255 - gf_log[a]]
```

### Cauchy Matrix Construction (Systematic Form)

RNET uses a **Cauchy matrix** as the parity generator. For k data shards and m parity shards, the parity matrix M is defined as:

```
M[i][j] = 1 / (x_i XOR y_j)
```

where the sets {x₀…xₘ₋₁} and {y₀…yₖ₋₁} are disjoint subsets of GF(2⁸). RNET uses:
- x_i = i + 1  (i ∈ [0, m))
- y_j = k + j + 1  (j ∈ [0, k))

The Cauchy property guarantees that every square submatrix is invertible over GF(2⁸), which means **any k out of n received shards are sufficient to reconstruct the original data**, regardless of which k were received.

### Encoding

For data shards D[0]…D[k-1], each of length L bytes, parity shards P[0]…P[m-1] are:

```
P[i][b] = Σⱼ M[i][j] · D[j][b]   (GF addition = XOR, GF multiplication as above)
```

This is an O(k·m·L) operation. For k=6, m=4, L=512 bytes: 6·4·512 = 12,288 GF multiplications per encode — well within budget for the target hardware tier.

### Decoding (Erasure Reconstruction)

Given any k received shards (data or parity), form a k×k submatrix S from the corresponding rows of the full (k+m)×k encoding matrix. Invert S using **Gauss-Jordan elimination over GF(2⁸)**, then multiply by the received shard vector to recover the original data shards.

```
D_recovered = S⁻¹ · R    where R = received shard vector
```

Gauss-Jordan over GF(2⁸) runs in O(k³) field operations — for k=6 this is 216 operations, negligible compared to the shard multiply.

### RNET Default Parameters

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Data shards (k) | 6 | Balances encode overhead vs. redundancy |
| Parity shards (m) | 4 | Recovers up to 4/10 = 40% loss |
| Total shards (n) | 10 | n = k + m |
| Max survivable loss | 40% | Matches design environment |
| Shard size (MTU_POOR) | 512 B | Fits in a single LTE-band UDP datagram |
| Shard size (MTU_GOOD) | 1400 B | Near-maximum for most backhaul links |

---

## 3. Multi-Path QUIC Transport Binding Mechanics

### Network Object Acquisition

Android's `ConnectivityManager.NetworkCallback` delivers a distinct `Network` object for each active cellular radio bearer. RNET registers:

```kotlin
val request = NetworkRequest.Builder()
    .addTransportType(NetworkCapabilities.TRANSPORT_CELLULAR)
    .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
    .build()
connectivityManager.registerNetworkCallback(request, networkCallback)
```

On `onAvailable(network)`, a `DatagramSocket` is created and bound to that specific `Network` via `network.bindSocket(socket)`. This forces all datagrams sent through that socket to egress on the corresponding cellular radio — bypassing Android's default single-path routing table.

### Adaptive MTU Micro-Framing

Shard size is adjusted dynamically based on live RSRP telemetry from `CellMonitor`:

| RSRP Range (dBm) | MTU (bytes) | Condition |
|-----------------|-------------|-----------|
| > −90 | 1400 | Good signal |
| −90 to −105 | 900 | Fair signal |
| < −105 | 512 | Poor signal / deep indoor |

The MTU governs the shard size fed to `ReedSolomonFec.encode()`. Smaller shards under poor signal reduce per-datagram loss probability and fit within lower-tier radio segment sizes.

### Low-Band Prioritization

`CellMonitor` annotates each `CellSnapshot` with `isLowBand = bandMhz in 700..960`. Low-band cells (B12/B17/B28/B71 for LTE, n71 for NR) have:
- Higher diffraction around obstacles
- Greater building penetration depth
- Lower free-space path loss at the same effective radiated power

When a low-band path is available alongside a mid/high-band path, the low-band path receives a larger share of shard distribution by design — not through band-locking, but through MTU and retry policy.

### Handover Continuity

Because each path is a stateless UDP channel with FEC sharding, there is no session state to migrate during a cell tower handover. The `ConnectivityManager.NetworkCallback.onLost()` removes the dead socket; `onAvailable()` immediately adds the new network. The receiver reassembles frames from whatever k shards arrive first, regardless of which path(s) they arrived on.

---

## 4. Wi-Fi Direct Mesh State Machine

```
                    ┌──────────────────────────────────────────┐
                    │                  IDLE                    │
                    └──────────────┬───────────────────────────┘
                                   │ initialize() + startDiscovery()
                    ┌──────────────▼───────────────────────────┐
                    │             DISCOVERING                   │◄─────┐
                    └──────────────┬───────────────────────────┘      │
                                   │ WIFI_P2P_PEERS_CHANGED            │
                                   │ (peer list non-empty)             │
                    ┌──────────────▼───────────────────────────┐      │
                    │          PEER_AVAILABLE                   │      │
                    └──────────────┬───────────────────────────┘      │
                                   │ user grants consent              │
                                   │ connectToPeer(device, true)      │
                    ┌──────────────▼───────────────────────────┐      │
                    │             CONNECTING                    │      │
                    └──────────────┬───────────────────────────┘      │
                                   │ WIFI_P2P_CONNECTION_CHANGED       │
                                   │ (networkInfo.isConnected)         │
                    ┌──────────────▼───────────────────────────┐      │
                    │             CONNECTED                     │      │
                    │   ┌──────────────────────────────────┐   │      │
                    │   │ Group Owner?                     │   │      │
                    │   │   YES → startGroupOwnerServer()  │   │      │
                    │   │   NO  → connectAsClient(goIP)    │   │      │
                    │   └──────────────────────────────────┘   │      │
                    └──────────────┬───────────────────────────┘      │
                                   │ socket closed / link lost         │
                                   └───────────────────────────────────┘
```

**Group Owner election:** Android's Wi-Fi Direct stack negotiates the Group Owner automatically using the P2P Group Owner Intent value. RNET does not override this; it adapts to whichever role is assigned.

**Data protocol over the TCP socket:**

```
[ 4 bytes: frame length (big-endian int32) ]
[ N bytes: encrypted frame                 ]
```

All frames are pre-encrypted by `SessionCipher` before entering `WifiDirectMesh`. The mesh layer is transport-only and does not inspect payload content.

**Gateway cooperative routing:**

When `MeshRouter.gatewayModeEnabled = true` (set only after user consent), inbound frames from Wi-Fi Direct are forwarded to `MultipathEngine.send()` and replies are broadcast back to all connected mesh peers. This creates a transparent relay without requiring route table modification on peer devices.

---

## 5. Post-Quantum Hybrid Cryptography

RNET implements the **NIST FIPS 203** ML-KEM-768 (Module Lattice-based Key Encapsulation Mechanism) algorithm combined with X25519 ECDH. The motivation is **hybrid security**: if either the classical or the post-quantum component is broken, the combined key remains secure.

### Key Derivation Flow

```
Initiator                               Responder
─────────                               ─────────
x25519_kp ← generateX25519KeyPair()
kem_kp    ← generateKemKeyPair()
                                        x25519_kp_r ← generateX25519KeyPair()
     ── x25519_kp.pub | kem_kp.pub ──►
                                        (ct, kem_shared) ← kemEncapsulate(kem_kp.pub)
     ◄── x25519_kp_r.pub | ct ──────
x25519_shared ← x25519ECDH(x25519_kp.priv, x25519_kp_r.pub)
                                        x25519_shared ← x25519ECDH(x25519_kp_r.priv, x25519_kp.pub)
kem_shared ← kemDecapsulate(kem_kp.priv, ct)

transcript = x25519_kp.pub || x25519_kp_r.pub || ct
session_key = HKDF-SHA256(IKM = x25519_shared || kem_shared,
                           salt = transcript,
                           info = "RNET-v1-session",
                           L = 32)
```

Both sides derive the same `session_key`. It is fed to `SessionCipher` for AES-256-GCM.

**Security properties:**
- Quantum adversary: must break ML-KEM-768 (IND-CCA2 secure under MLWE hardness assumption with k=3 polynomials over R_q, q=3329)
- Classical adversary: must break X25519 (CDH problem on Curve25519)
- Transcript binding prevents key-mismatch attacks

---

## 6. Hotspot Gateway & Consent Architecture

The gateway requires **two separate consent gates**:

1. **Gateway hotspot consent** (`ConsentActivity`) — user accepts routing peer device traffic through RNET's encrypted transport.
2. **Mesh gateway consent** (`MeshConsentDialog`) — user accepts acting as a relay for mesh peers, or accepts routing their own traffic through a peer.

Neither can be bypassed programmatically:
- `HotspotGateway.start()` throws `IllegalStateException` if `grantConsent()` was never called.
- `WifiDirectMesh.connectToPeer()` requires `consentGranted = true` parameter.
- `MeshRouter.enableGatewayMode()` requires `consentGranted = true` parameter.

The consent flag is persisted in `SharedPreferences("rnet_prefs")` under key `gateway_consent_v1`. The flag can be revoked by the user toggling the gateway off; re-enabling requires re-presenting the disclosure screen.

---

## 7. Deployment & Build Guide

### Prerequisites

- Android Studio Ladybug (2024.2.1) or later
- JDK 17 (Temurin distribution recommended)
- Android SDK 36 (compileSdk)
- Gradle 8.9 (wrapper downloads automatically)
- **iOS additionally:** macOS 14+, Xcode 15.4+, Apple Developer account (or free Apple ID for AltStore sideloading)

### KMP Shared Module

The `shared/` Gradle module compiles to an `.aar` for Android and an `RnetShared.xcframework` for iOS:

```bash
./gradlew :shared:assembleReleaseXCFramework
# Output: shared/build/XCFrameworks/release/RnetShared.xcframework
```

Drag `RnetShared.xcframework` into Xcode under the **RnetApp** target → Frameworks, Libraries, and Embedded Content. Set embed to **Embed & Sign**.

### Android Local Build

```bash
# Debug APK
./gradlew assembleDebug

# Release APK (requires keystore env vars — see §8)
export KEYSTORE_PATH=/path/to/release.jks
export KEYSTORE_PASSWORD=...
export KEY_ALIAS=...
export KEY_PASSWORD=...
./gradlew assembleRelease
```

### iOS Build — Xcode (GUI)

1. Open `iosApp/RnetApp.xcworkspace` in Xcode.
2. Select scheme **RnetApp** and destination **Any iOS Device (arm64)**.
3. Under **Signing & Capabilities**, select your Apple Developer Team.
4. Add the `com.apple.developer.networking.multipath` entitlement for MPTCP support.
5. **Product → Archive**, then **Distribute App → Ad-Hoc** (or **Development** for personal devices).

### iOS Build — xcodebuild (CLI)

```bash
xcodebuild archive \
  -workspace iosApp/RnetApp.xcworkspace \
  -scheme RnetApp \
  -destination "generic/platform=iOS" \
  -archivePath build/RnetApp.xcarchive \
  -configuration Release

xcodebuild -exportArchive \
  -archivePath build/RnetApp.xcarchive \
  -exportPath  build/ipa \
  -exportOptionsPlist ExportOptions.plist
```

### iOS Sideloading — Developer Mode (no App Store, no jailbreak)

**Method A — Apple Configurator 2** (registered development devices):

1. Register the target iPhone UDID in your Apple Developer Portal under Devices.
2. Create a Development provisioning profile that includes that UDID.
3. Build with the **Development** export method and connect the iPhone.
4. Open Apple Configurator 2 → Add → App → select the `.ipa`.

**Method B — libimobiledevice** (CLI, same provisioning requirements):

```bash
brew install libimobiledevice
ideviceinstaller -i build/ipa/RnetApp.ipa
```

**Method C — AltStore** (free Apple ID, no Developer Program subscription required):

AltStore is an open-source sideloading tool that re-signs apps with your personal Apple ID via a 7-day free provisioning certificate, automatically refreshed by the AltStore background daemon.

1. Install [AltStore](https://altstore.io/) on your Mac and iPhone per the official setup guide.
2. Download `RnetApp.ipa` from the GitHub Release page.
3. In AltStore on iPhone → **My Apps** → **+** → choose the `.ipa`.
4. AltStore re-signs and installs it; the daemon renews the certificate every 7 days on the same Wi-Fi network.

> A paid Apple Developer Program membership ($99/yr) issues 1-year certificates and removes the 7-day re-signing requirement.

### Server Configuration

**Android** — `RnetForegroundService.kt`:
```kotlin
private const val REMOTE_HOST = "your.rnet.server.example.com"
private const val REMOTE_PORT = 7777
```

**iOS** — `RnetViewModel.swift`:
```swift
try await engine.start(host: "your.rnet.server.example.com", port: 7777, sessionKey: derivedKey)
```

Replace the placeholder `sessionKey` with the output of a real `HybridKeyExchange` signaling handshake on both platforms.

---

## 8. Required Secrets for CI/CD

Configure these in **GitHub → Settings → Secrets → Actions**:

| Secret | Description |
|--------|-------------|
| `KEYSTORE_BASE64` | Base64-encoded `.jks`: `base64 -w0 release.jks` |
| `KEYSTORE_PASSWORD` | Keystore password |
| `KEY_ALIAS` | Key alias |
| `KEY_PASSWORD` | Key password |
| `IOS_DISTRIBUTION_P12_BASE64` | Base64-encoded distribution `.p12`: `base64 -w0 dist.p12` |
| `IOS_DISTRIBUTION_P12_PASSWORD` | P12 export password |
| `IOS_ADHOC_PROVISIONING_BASE64` | Base64-encoded Ad-Hoc `.mobileprovision` |
| `APPLE_TEAM_ID` | 10-char Apple Developer Team ID |

Releases publish automatically on tag push; both APK and IPA are attached:

```bash
git tag v1.0.0
git push origin v1.0.0
```

---
---

# РУССКИЙ

---

## 1. Обзор системной архитектуры

RNET — модульный фреймворк сетевого транспорта для Android, состоящий из шести независимо тестируемых слоёв, взаимодействующих через интерфейсы Kotlin coroutine `Flow`.

```
┌─────────────────────────────────────────────────────────────┐
│                    Пользовательский интерфейс                │
│               (Jetpack Compose · Material 3)                │
└────────────────────────┬────────────────────────────────────┘
                         │ StateFlow<UiState>
┌────────────────────────▼────────────────────────────────────┐
│                  RnetForegroundService                       │
│            (foreground-сервис типа DATA_SYNC)               │
└──────┬──────────────────────────────────────────┬───────────┘
       │                                          │
┌──────▼───────┐                      ┌───────────▼──────────┐
│  MeshRouter  │                      │  MultipathEngine      │
│  (ячеистая   │◄────────────────────►│  (QUIC · FEC · MTU)  │
│   сеть)      │                      │                       │
└──────┬───────┘                      └───────────┬───────────┘
       │                                          │
┌──────▼────────────────┐             ┌───────────▼──────────┐
│  WifiDirectMesh +      │             │  EndpointRouter       │
│  BleMeshScanner        │             │  (оценка пропускной  │
│                        │             │   способности)        │
└───────────────────────┘             └───────────────────────┘
```

**Маршрут данных при работе в ячеистой сети (нет мобильного интернета):**

```
Данные приложения
  → MeshRouter.send()
  → WifiDirectMesh.broadcast()   [TCP-сокет до Group Owner]
  → Шлюзовой узел с подключением
  → MultipathEngine.send()       [исходящий трафик к серверу]
  → Удалённый сервер
  ← обратный путь
```

---

## 2. Математические принципы помехоустойчивого кодирования Рида–Соломона

### Поле Галуа GF(2⁸)

Все операции в кодеке RS выполняются над конечным полем **GF(256)**. Элементы — полиномы степени ≤ 7 с бинарными коэффициентами, взятые по модулю примитивного полинома:

```
p(x) = x⁸ + x⁴ + x³ + x² + 1   (0x11D)
```

**Умножение** использует предвычисленные таблицы логарифмов и экспонент:

```
gf_mul(a, b) = gf_exp[ gf_log[a] + gf_log[b] ]
```

**Обратный элемент:**

```
gf_inv(a) = gf_exp[255 − gf_log[a]]
```

### Матрица Коши (систематическая форма)

Матрица чётности M для k информационных и m контрольных блоков:

```
M[i][j] = 1 / (x_i XOR y_j)
```

где множества {xᵢ} и {yⱼ} не пересекаются в GF(256). Свойство Коши гарантирует, что **любые k из n полученных блоков достаточны для восстановления исходных данных**.

### Параметры по умолчанию RNET

| Параметр | Значение |
|----------|---------|
| Информационные блоки (k) | 6 |
| Контрольные блоки (m) | 4 |
| Всего блоков (n) | 10 |
| Максимальные потери | 40% |
| Размер блока (плохой сигнал) | 512 байт |
| Размер блока (хороший сигнал) | 1400 байт |

### Декодирование (восстановление после стирания)

По любым k полученным блокам формируется квадратная подматрица S, которая обращается методом **Гаусса–Жордана над GF(2⁸)**. Исходные данные восстанавливаются как:

```
D = S⁻¹ · R    (R — вектор принятых блоков)
```

---

## 3. Механика многопутевого привязывания транспорта QUIC

### Получение объектов Network

Android `ConnectivityManager.NetworkCallback` доставляет отдельный объект `Network` для каждого активного радиоканала. RNET создаёт `DatagramSocket` и привязывает его к конкретной сети через `network.bindSocket(socket)`, принудительно направляя датаграммы по соответствующему радиоинтерфейсу.

### Адаптивное микрофреймирование MTU

| Уровень RSRP (дБм) | MTU (байт) |
|--------------------|------------|
| > −90 | 1400 |
| −90 … −105 | 900 |
| < −105 | 512 |

### Приоритет низкочастотных диапазонов

Диапазоны 700–960 МГц (B12, B17, B28, B71 для LTE; n71 для NR) имеют лучшее проникновение в здания. `CellMonitor` помечает такие ячейки флагом `isLowBand`, что влияет на политику распределения блоков по путям.

### Непрерывность при смене базовой станции

Поскольку каждый путь является stateless UDP-каналом с блочным FEC, никакого состояния сессии при переходе не требуется. Приёмник собирает первые k прибывших блоков независимо от того, по каким путям они пришли.

---

## 4. Автомат состояний ячеистой сети Wi-Fi Direct

```
IDLE → DISCOVERING → PEER_AVAILABLE → CONNECTING → CONNECTED
                ↑                                        │
                └────────── потеря соединения ───────────┘
```

**Шлюзовое кооперативное маршрутизирование:**

Когда `MeshRouter.gatewayModeEnabled = true` (только после явного согласия пользователя), входящие кадры из Wi-Fi Direct передаются в `MultipathEngine.send()`, а ответы транслируются обратно всем подключённым узлам.

**Протокол данных над TCP-сокетом:**

```
[ 4 байта: длина кадра (big-endian int32) ]
[ N байт: зашифрованный кадр             ]
```

---

## 5. Постквантовая гибридная криптография

RNET реализует **NIST FIPS 203** ML-KEM-768 (инкапсуляция ключей на основе модульных решёток) совместно с X25519 ECDH. Финальный сессионный ключ:

```
transcript    = pub_x25519_A || pub_x25519_B || kem_ciphertext
session_key   = HKDF-SHA256(
                    IKM  = x25519_shared || kem_shared,
                    salt = transcript,
                    info = "RNET-v1-session",
                    L    = 32 байта
                )
```

**Свойства безопасности:**
- Квантовый противник обязан взломать ML-KEM-768 (IND-CCA2 при предположении о сложности MLWE, k=3, q=3329)
- Классический противник обязан взломать X25519 (задача CDH на кривой Curve25519)
- Привязка к transcript предотвращает атаки несоответствия ключей

---

## 6. Шлюз точки доступа и архитектура согласия

Шлюз требует **двух отдельных рубежей согласия**:

1. `ConsentActivity` — маршрутизация трафика подключённых устройств через зашифрованный транспорт RNET.
2. `MeshConsentDialog` — работа в качестве ретранслятора для узлов ячеистой сети.

Ни один рубеж нельзя обойти программно: отсутствие явного вызова `grantConsent()` приводит к исключению `IllegalStateException`.

---

## 7. Руководство по развёртыванию и сборке

### Локальная сборка

```bash
# Отладочный APK
./gradlew assembleDebug

# Release APK
export KEYSTORE_PATH=/путь/к/release.jks
export KEYSTORE_PASSWORD=...
export KEY_ALIAS=...
export KEY_PASSWORD=...
./gradlew assembleRelease
```

### Настройка сервера

В файле `RnetForegroundService.kt` укажите адрес сервера:

```kotlin
private const val REMOTE_HOST = "your.rnet.server.example.com"
private const val REMOTE_PORT = 7777
```

---

## 8. Секреты для CI/CD

| Секрет | Описание |
|--------|----------|
| `KEYSTORE_BASE64` | Base64 от `.jks`: `base64 -w0 release.jks` |
| `KEYSTORE_PASSWORD` | Пароль хранилища ключей |
| `KEY_ALIAS` | Псевдоним ключа |
| `KEY_PASSWORD` | Пароль ключа |

Релиз публикуется автоматически при пуше тега `v*.*.*`.

---
---

# DEUTSCH

---

## 1. Systemarchitektur-Übersicht

RNET ist ein modulares Android-Netzwerktransport-Framework aus sechs unabhängig testbaren Schichten, die über Kotlin Coroutine `Flow`-Schnittstellen kommunizieren.

**Datenpfad bei normaler Mobilfunkoperation:**

```
App-Nutzdaten
  → MultipathEngine.send()
  → ReedSolomonFec.encode()       [k=6 Datenshards + 4 Paritätshards]
  → SessionCipher.encrypt()       [AES-256-GCM, frischer 12-Byte-IV]
  → UDP-Datagramm × 10 Pfade
  → Remote-Server
```

**Datenpfad bei Mesh-Fallback (kein Mobilfunk-Uplink):**

```
App-Nutzdaten
  → MeshRouter.send()
  → WifiDirectMesh.broadcast()    [TCP-Socket zum Group Owner]
  → Gateway-Knoten
  → MultipathEngine.send()
  → Remote-Server
```

---

## 2. Mathematische Grundlagen der Reed-Solomon-Vorwärtsfehlerkorrektur

### Galois-Feld GF(2⁸)

Alle Arithmetik im RS-Codec arbeitet über dem endlichen Körper **GF(256)**. Elemente sind Polynome vom Grad ≤ 7 mit binären Koeffizienten, reduziert modulo dem primitiven Polynom:

```
p(x) = x⁸ + x⁴ + x³ + x² + 1   (0x11D)
```

**Multiplikation** verwendet vorberechnete Logarithmus- und Exponentialtabellen:

```
gf_mul(a, b) = gf_exp[ gf_log[a] + gf_log[b] ]
```

### Cauchy-Matrix-Konstruktion

Die Paritätsmatrix M für k Daten- und m Paritäts-Shards:

```
M[i][j] = 1 / (x_i XOR y_j)
```

Die Cauchy-Eigenschaft garantiert, dass **jede beliebige k-aus-n-Auswahl empfangener Shards ausreicht**, um die Originaldaten zu rekonstruieren.

### Standardparameter

| Parameter | Wert |
|-----------|------|
| Daten-Shards (k) | 6 |
| Paritäts-Shards (m) | 4 |
| Gesamt-Shards (n) | 10 |
| Max. tolerierter Verlust | 40 % |

### Dekodierung (Löschungsrekonstruktion)

Aus beliebigen k empfangenen Shards wird eine k×k-Untermatrix S gebildet und mittels **Gauß-Jordan-Elimination über GF(2⁸)** invertiert:

```
D = S⁻¹ · R
```

---

## 3. Mehrpfad-QUIC-Transport-Bindungsmechanik

### Netzwerkobjekt-Akquisition

`ConnectivityManager.NetworkCallback` liefert ein eigenes `Network`-Objekt pro aktivem Mobilfunkträger. RNET bindet einen `DatagramSocket` per `network.bindSocket(socket)` an jede Schnittstelle, um Datagramme gezielt über den entsprechenden Funkkanal zu senden.

### Adaptives MTU-Micro-Framing

| RSRP-Bereich (dBm) | MTU (Byte) | Bedingung |
|-------------------|------------|-----------|
| > −90 | 1400 | Gutes Signal |
| −90 bis −105 | 900 | Mäßiges Signal |
| < −105 | 512 | Schlechtes Signal |

### Handover-Kontinuität

Da jeder Pfad ein zustandsloser UDP-Kanal mit FEC-Sharding ist, muss bei einem Zellenwechsel kein Sitzungszustand migriert werden. Der Empfänger rekonstruiert Frames aus den ersten k eintreffenden Shards, unabhängig vom Pfad.

---

## 4. Wi-Fi Direct Mesh-Zustandsautomat

```
IDLE → DISCOVERING → PEER_AVAILABLE → CONNECTING → CONNECTED
              ↑                                          │
              └──────────── Verbindungsverlust ──────────┘
```

**Einwilligungsanforderungen:**
- `connectToPeer()` erfordert `consentGranted = true`
- `enableGatewayMode()` erfordert `consentGranted = true`
- `HotspotGateway.start()` wirft `IllegalStateException` ohne vorherige Einwilligung

---

## 5. Post-Quanten-Hybridkryptografie

RNET implementiert **NIST FIPS 203** ML-KEM-768 kombiniert mit X25519 ECDH:

```
Sitzungsschlüssel = HKDF-SHA256(
    IKM  = x25519_shared || kem_shared,
    salt = transcript,
    info = "RNET-v1-session",
    L    = 32 Byte
)
```

**Sicherheitseigenschaften:**
- Quantenangreifer muss ML-KEM-768 brechen (IND-CCA2 unter MLWE-Annahme)
- Klassischer Angreifer muss X25519 brechen (CDH-Problem auf Curve25519)

---

## 6. Hotspot-Gateway und Einwilligungsarchitektur

Zwei unabhängige Einwilligungsstufen sind obligatorisch:

1. `ConsentActivity` — Weiterleitung von Peer-Geräteverkehr über RNET
2. `MeshConsentDialog` — Betrieb als Relay-Gateway für Mesh-Peers

Beide Stufen können nicht programmatisch umgangen werden.

---

## 7. Bereitstellungs- und Build-Anleitung

```bash
# Debug-APK
./gradlew assembleDebug

# Release-APK
export KEYSTORE_PATH=/pfad/zu/release.jks
./gradlew assembleRelease
```

Releases werden automatisch veröffentlicht, wenn ein Tag `v*.*.*` gepusht wird.

---
---

# FRANÇAIS

---

## 1. Vue d'ensemble de l'architecture système

RNET est un framework de transport réseau Android modulaire composé de six couches testables indépendamment, communicant via des interfaces Kotlin Coroutine `Flow`.

**Chemin de données — fonctionnement cellulaire normal :**

```
Charge utile applicative
  → MultipathEngine.send()
  → ReedSolomonFec.encode()       [k=6 fragments données + 4 parité]
  → SessionCipher.encrypt()       [AES-256-GCM, IV 12 octets frais]
  → Datagramme UDP × 10 chemins
  → Serveur distant
```

**Chemin de données — fallback maillé (pas d'uplink cellulaire) :**

```
Charge utile applicative
  → MeshRouter.send()
  → WifiDirectMesh.broadcast()    [socket TCP vers le Group Owner]
  → Nœud passerelle avec uplink
  → MultipathEngine.send()
  → Serveur distant
```

---

## 2. Principes mathématiques du codage Reed-Solomon

### Corps de Galois GF(2⁸)

Toute l'arithmétique dans le codec RS opère sur le corps fini **GF(256)**. Les éléments sont des polynômes de degré ≤ 7 à coefficients binaires, réduits modulo le polynôme primitif :

```
p(x) = x⁸ + x⁴ + x³ + x² + 1   (0x11D)
```

**Multiplication** via tables précomputées :

```
gf_mul(a, b) = gf_exp[ gf_log[a] + gf_log[b] ]
```

### Construction de la matrice de Cauchy

La matrice de parité M pour k fragments de données et m fragments de parité :

```
M[i][j] = 1 / (x_i XOR y_j)
```

La propriété de Cauchy garantit que **tout sous-ensemble de k fragments reçus parmi n est suffisant** pour reconstruire les données originales.

### Paramètres par défaut

| Paramètre | Valeur |
|-----------|--------|
| Fragments données (k) | 6 |
| Fragments parité (m) | 4 |
| Total fragments (n) | 10 |
| Perte max. tolérable | 40 % |

### Décodage (reconstruction par effacement)

À partir de k fragments reçus quelconques, une sous-matrice k×k S est formée et inversée par **élimination de Gauss-Jordan sur GF(2⁸)** :

```
D = S⁻¹ · R
```

---

## 3. Mécanique de liaison du transport QUIC multi-chemin

### Acquisition des objets Network

`ConnectivityManager.NetworkCallback` fournit un objet `Network` distinct par porteuse radio cellulaire active. RNET lie un `DatagramSocket` à chaque réseau via `network.bindSocket(socket)`, forçant les datagrammes à sortir par l'interface radio correspondante.

### Micro-tramage MTU adaptatif

| Plage RSRP (dBm) | MTU (octets) | Condition |
|-----------------|--------------|-----------|
| > −90 | 1400 | Bon signal |
| −90 à −105 | 900 | Signal moyen |
| < −105 | 512 | Mauvais signal |

### Continuité lors du handover

Comme chaque chemin est un canal UDP sans état avec fragmentation FEC, aucun état de session n'a besoin d'être migré lors d'un changement de cellule.

---

## 4. Machine à états du réseau maillé Wi-Fi Direct

```
IDLE → DISCOVERING → PEER_AVAILABLE → CONNECTING → CONNECTED
             ↑                                           │
             └───────────── perte de lien ───────────────┘
```

**Exigences de consentement :**
- `connectToPeer()` exige `consentGranted = true`
- `enableGatewayMode()` exige `consentGranted = true`
- `HotspotGateway.start()` lève `IllegalStateException` sans consentement préalable

---

## 5. Cryptographie hybride post-quantique

RNET implémente **NIST FIPS 203** ML-KEM-768 combiné avec X25519 ECDH :

```
clé_session = HKDF-SHA256(
    IKM  = x25519_shared || kem_shared,
    salt = transcript,
    info = "RNET-v1-session",
    L    = 32 octets
)
```

**Propriétés de sécurité :**
- L'adversaire quantique doit casser ML-KEM-768 (IND-CCA2 sous l'hypothèse MLWE, k=3, q=3329)
- L'adversaire classique doit casser X25519 (problème CDH sur Curve25519)
- La liaison au transcript empêche les attaques par non-correspondance de clés

---

## 6. Passerelle Hotspot et architecture du consentement

Deux niveaux de consentement indépendants sont obligatoires :

1. `ConsentActivity` — acheminement du trafic des appareils pairs via le transport RNET.
2. `MeshConsentDialog` — fonctionnement comme relais passerelle pour les pairs du réseau maillé.

Aucun des deux ne peut être contourné par programmation.

---

## 7. Guide de déploiement et de compilation

```bash
# APK de débogage
./gradlew assembleDebug

# APK de production
export KEYSTORE_PATH=/chemin/vers/release.jks
export KEYSTORE_PASSWORD=...
export KEY_ALIAS=...
export KEY_PASSWORD=...
./gradlew assembleRelease
```

Les releases sont publiées automatiquement lors du push d'un tag `v*.*.*` :

```bash
git tag v1.0.0
git push origin v1.0.0
```

---

## 8. Secrets requis pour le CI/CD

| Secret | Description |
|--------|-------------|
| `KEYSTORE_BASE64` | Fichier `.jks` encodé en Base64 : `base64 -w0 release.jks` |
| `KEYSTORE_PASSWORD` | Mot de passe du keystore |
| `KEY_ALIAS` | Alias de la clé dans le keystore |
| `KEY_PASSWORD` | Mot de passe de la clé |
