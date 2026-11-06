package com.rnet.app.service

/** Connection phase of the VPN engine. Polled by MainViewModel every second. */
enum class ConnectionPhase { IDLE, STARTING, FINDING_PROXY, ACTIVE }
