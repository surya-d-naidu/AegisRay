# Flutter Mobile App Integration

Complete guide for integrating AegisRay P2P mesh VPN with Flutter mobile applications, including SDK usage, UI components, and platform-specific implementations.

## 📋 Table of Contents

- [Flutter SDK Overview](#flutter-sdk-overview)
- [Installation & Setup](#installation--setup)
- [Core Integration](#core-integration)
- [UI Components](#ui-components)
- [Platform-Specific Features](#platform-specific-features)
- [State Management](#state-management)
- [Advanced Features](#advanced-features)
- [Deployment](#deployment)

## 📱 Flutter SDK Overview

The AegisRay Flutter SDK provides native mobile integration for P2P mesh VPN functionality with a clean, reactive API.

### SDK Architecture

```
┌─── Flutter Application Layer ───────┐
│  • UI Widgets                       │
│  • State Management (Bloc/Riverpod) │
│  • Navigation & Routing             │
└─────────────────────────────────────┘
             ↕ Dart API
┌─── AegisRay Flutter SDK ────────────┐
│  • Connection Management            │
│  • Network State                    │
│  • Settings & Configuration         │
└─────────────────────────────────────┘
             ↕ Platform Channel
┌─── Native Integration Layer ────────┐
│  Android: Kotlin/Java               │
│  iOS: Swift/Objective-C             │
│  • VPN Service Integration          │
│  • System Permission Handling       │
└─────────────────────────────────────┘
             ↕ FFI/Native
┌─── AegisRay Core (Go) ──────────────┐
│  • Mesh Networking                  │
│  • P2P Discovery                    │
│  • Encryption & Security            │
└─────────────────────────────────────┘
```

---

## 🚀 Installation & Setup

### Add Dependencies

**pubspec.yaml:**
```yaml
name: aegisray_mobile
description: AegisRay P2P VPN Mobile App

dependencies:
  flutter:
    sdk: flutter
  
  # AegisRay SDK
  aegisray_flutter: ^1.0.0
  
  # State Management
  flutter_bloc: ^8.1.3
  equatable: ^2.0.5
  
  # UI & Navigation
  flutter_screenutil: ^5.9.0
  go_router: ^12.1.3
  
  # Network & Storage
  dio: ^5.3.2
  shared_preferences: ^2.2.2
  connectivity_plus: ^5.0.1
  
  # Utilities
  permission_handler: ^11.0.1
  package_info_plus: ^4.2.0
  device_info_plus: ^9.1.0

dev_dependencies:
  flutter_test:
    sdk: flutter
  flutter_lints: ^3.0.0
  mockito: ^5.4.2
  bloc_test: ^9.1.5
```

### Platform Configuration

**Android (android/app/src/main/AndroidManifest.xml):**
```xml
<manifest xmlns:android="http://schemas.android.com/apk/res/android">
    <!-- Network permissions -->
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.ACCESS_NETWORK_STATE" />
    <uses-permission android:name="android.permission.CHANGE_NETWORK_STATE" />
    
    <!-- VPN permissions -->
    <uses-permission android:name="android.net.VpnService" />
    <uses-permission android:name="android.permission.BIND_VPN_SERVICE" />
    
    <!-- Background processing -->
    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
    <uses-permission android:name="android.permission.WAKE_LOCK" />
    
    <application
        android:label="AegisRay"
        android:name="${applicationName}"
        android:icon="@mipmap/ic_launcher">
        
        <activity
            android:name=".MainActivity"
            android:exported="true"
            android:launchMode="singleTop"
            android:theme="@style/LaunchTheme"
            android:configChanges="orientation|keyboardHidden|keyboard|screenSize|smallestScreenSize|locale|layoutDirection|fontScale|screenLayout|density|uiMode"
            android:hardwareAccelerated="true"
            android:windowSoftInputMode="adjustResize">
            
            <meta-data
              android:name="io.flutter.embedding.android.NormalTheme"
              android:resource="@style/NormalTheme" />
              
            <intent-filter android:autoVerify="true">
                <action android:name="android.intent.action.MAIN"/>
                <category android:name="android.intent.category.LAUNCHER"/>
            </intent-filter>
        </activity>
        
        <!-- VPN Service -->
        <service
            android:name="com.aegisray.flutter.VpnService"
            android:permission="android.permission.BIND_VPN_SERVICE">
            <intent-filter>
                <action android:name="android.net.VpnService"/>
            </intent-filter>
        </service>
        
        <!-- Don't delete the meta-data below. This is used by the Flutter tool to generate GeneratedPluginRegistrant.java -->
        <meta-data
            android:name="flutterEmbedding"
            android:value="2" />
    </application>
</manifest>
```

**iOS (ios/Runner/Info.plist):**
```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Network Extension capability -->
    <key>NSExtension</key>
    <dict>
        <key>NSExtensionPointIdentifier</key>
        <string>com.apple.networkextension.packet-tunnel</string>
        <key>NSExtensionPrincipalClass</key>
        <string>AegisRayTunnelProvider</string>
    </dict>
    
    <!-- Network usage description -->
    <key>NSNetworkUsageDescription</key>
    <string>AegisRay needs network access to provide secure VPN connectivity</string>
    
    <!-- Background modes -->
    <key>UIBackgroundModes</key>
    <array>
        <string>network-extension</string>
        <string>background-processing</string>
    </array>
    
    <!-- Required capabilities -->
    <key>com.apple.developer.networking.networkextension</key>
    <array>
        <string>packet-tunnel-provider</string>
    </array>
</dict>
</plist>
```

---

## 🔧 Core Integration

### Initialize AegisRay SDK

**lib/main.dart:**
```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:aegisray_flutter/aegisray_flutter.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';

import 'app/app.dart';
import 'core/injection/injection.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  
  // Initialize dependency injection
  await configureDependencies();
  
  // Initialize AegisRay SDK
  await AegisRay.initialize(
    config: AegisRayConfig(
      networkName: 'mobile-mesh',
      networkCidr: '100.64.0.0/16',
      logLevel: LogLevel.info,
      enableStealth: true,
      stealthDomains: [
        'googleapis.com',
        'cloudflare.com',
      ],
    ),
  );
  
  runApp(const AegisRayApp());
}

class AegisRayApp extends StatelessWidget {
  const AegisRayApp({super.key});

  @override
  Widget build(BuildContext context) {
    return ScreenUtilInit(
      designSize: const Size(375, 812),
      minTextAdapt: true,
      builder: (context, child) {
        return MultiBlocProvider(
          providers: [
            BlocProvider<ConnectionBloc>(
              create: (context) => getIt<ConnectionBloc>(),
            ),
            BlocProvider<NetworkBloc>(
              create: (context) => getIt<NetworkBloc>(),
            ),
            BlocProvider<SettingsBloc>(
              create: (context) => getIt<SettingsBloc>(),
            ),
          ],
          child: MaterialApp.router(
            title: 'AegisRay',
            theme: AppTheme.light,
            darkTheme: AppTheme.dark,
            routerConfig: appRouter,
            debugShowCheckedModeBanner: false,
          ),
        );
      },
    );
  }
}
```

### AegisRay Service Layer

**lib/core/services/aegisray_service.dart:**
```dart
import 'dart:async';
import 'package:aegisray_flutter/aegisray_flutter.dart';

class AegisRayService {
  static final AegisRayService _instance = AegisRayService._internal();
  factory AegisRayService() => _instance;
  AegisRayService._internal();

  final AegisRay _aegisRay = AegisRay.instance;
  
  // Connection state streams
  Stream<ConnectionState> get connectionStateStream => 
      _aegisRay.connectionStateStream;
  
  Stream<List<Peer>> get peersStream => 
      _aegisRay.peersStream;
  
  Stream<NetworkStats> get networkStatsStream => 
      _aegisRay.networkStatsStream;

  // Connection management
  Future<void> connect({
    required List<String> staticPeers,
    String? exitNodeId,
  }) async {
    try {
      await _aegisRay.connect(
        staticPeers: staticPeers,
        exitNodeId: exitNodeId,
      );
    } catch (e) {
      throw AegisRayException('Connection failed: $e');
    }
  }

  Future<void> disconnect() async {
    try {
      await _aegisRay.disconnect();
    } catch (e) {
      throw AegisRayException('Disconnect failed: $e');
    }
  }

  // Peer management
  Future<List<Peer>> getAvailablePeers() async {
    return await _aegisRay.getAvailablePeers();
  }

  Future<void> addPeer(String address) async {
    await _aegisRay.addPeer(address);
  }

  Future<void> removePeer(String peerId) async {
    await _aegisRay.removePeer(peerId);
  }

  // Network information
  Future<NodeStatus> getNodeStatus() async {
    return await _aegisRay.getNodeStatus();
  }

  Future<NetworkStats> getNetworkStats() async {
    return await _aegisRay.getNetworkStats();
  }

  // Configuration
  Future<void> updateConfiguration(AegisRayConfig config) async {
    await _aegisRay.updateConfiguration(config);
  }

  Future<AegisRayConfig> getConfiguration() async {
    return await _aegisRay.getConfiguration();
  }
}
```

---

## 🎨 UI Components

### Connection Widget

**lib/presentation/widgets/connection_widget.dart:**
```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import '../bloc/connection/connection_bloc.dart';

class ConnectionWidget extends StatelessWidget {
  const ConnectionWidget({super.key});

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<ConnectionBloc, ConnectionState>(
      builder: (context, state) {
        return Card(
          margin: EdgeInsets.all(16.w),
          child: Padding(
            padding: EdgeInsets.all(20.w),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    _buildStatusIndicator(state.connectionStatus),
                    SizedBox(width: 12.w),
                    Expanded(
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(
                            _getStatusText(state.connectionStatus),
                            style: Theme.of(context).textTheme.titleMedium,
                          ),
                          if (state.connectionStatus == ConnectionStatus.connected)
                            Text(
                              'Connected to ${state.connectedPeers.length} peers',
                              style: Theme.of(context).textTheme.bodySmall,
                            ),
                        ],
                      ),
                    ),
                  ],
                ),
                
                SizedBox(height: 20.h),
                
                // Connection button
                SizedBox(
                  width: double.infinity,
                  child: ElevatedButton(
                    onPressed: state.connectionStatus == ConnectionStatus.connecting
                        ? null
                        : () => _handleConnectionToggle(context, state),
                    child: state.connectionStatus == ConnectionStatus.connecting
                        ? Row(
                            mainAxisAlignment: MainAxisAlignment.center,
                            children: [
                              SizedBox(
                                width: 20.w,
                                height: 20.h,
                                child: const CircularProgressIndicator(strokeWidth: 2),
                              ),
                              SizedBox(width: 8.w),
                              const Text('Connecting...'),
                            ],
                          )
                        : Text(_getButtonText(state.connectionStatus)),
                  ),
                ),
                
                // Network information
                if (state.connectionStatus == ConnectionStatus.connected) ...[
                  SizedBox(height: 16.h),
                  _buildNetworkInfo(context, state),
                ],
              ],
            ),
          ),
        );
      },
    );
  }

  Widget _buildStatusIndicator(ConnectionStatus status) {
    Color color;
    IconData icon;
    
    switch (status) {
      case ConnectionStatus.connected:
        color = Colors.green;
        icon = Icons.check_circle;
        break;
      case ConnectionStatus.connecting:
        color = Colors.orange;
        icon = Icons.sync;
        break;
      case ConnectionStatus.disconnected:
        color = Colors.red;
        icon = Icons.circle;
        break;
      case ConnectionStatus.error:
        color = Colors.red;
        icon = Icons.error;
        break;
    }
    
    return Icon(
      icon,
      color: color,
      size: 24.w,
    );
  }

  Widget _buildNetworkInfo(BuildContext context, ConnectionState state) {
    return Container(
      padding: EdgeInsets.all(12.w),
      decoration: BoxDecoration(
        color: Theme.of(context).colorScheme.surfaceVariant,
        borderRadius: BorderRadius.circular(8.r),
      ),
      child: Column(
        children: [
          _buildInfoRow(context, 'Mesh IP', state.meshIp ?? 'Not assigned'),
          SizedBox(height: 8.h),
          _buildInfoRow(context, 'Exit Node', state.exitNode ?? 'Auto-select'),
          SizedBox(height: 8.h),
          _buildInfoRow(context, 'Data Usage', _formatBytes(state.bytesTransferred)),
        ],
      ),
    );
  }

  Widget _buildInfoRow(BuildContext context, String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(
          label,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
            color: Theme.of(context).colorScheme.onSurfaceVariant,
          ),
        ),
        Text(
          value,
          style: Theme.of(context).textTheme.bodyMedium?.copyWith(
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }

  void _handleConnectionToggle(BuildContext context, ConnectionState state) {
    final bloc = context.read<ConnectionBloc>();
    
    if (state.connectionStatus == ConnectionStatus.connected) {
      bloc.add(const DisconnectRequested());
    } else {
      bloc.add(const ConnectRequested());
    }
  }

  String _getStatusText(ConnectionStatus status) {
    switch (status) {
      case ConnectionStatus.connected:
        return 'Connected';
      case ConnectionStatus.connecting:
        return 'Connecting';
      case ConnectionStatus.disconnected:
        return 'Disconnected';
      case ConnectionStatus.error:
        return 'Connection Error';
    }
  }

  String _getButtonText(ConnectionStatus status) {
    switch (status) {
      case ConnectionStatus.connected:
        return 'Disconnect';
      case ConnectionStatus.connecting:
        return 'Connecting...';
      case ConnectionStatus.disconnected:
      case ConnectionStatus.error:
        return 'Connect';
    }
  }

  String _formatBytes(int bytes) {
    if (bytes < 1024) return '${bytes} B';
    if (bytes < 1024 * 1024) return '${(bytes / 1024).toStringAsFixed(1)} KB';
    if (bytes < 1024 * 1024 * 1024) return '${(bytes / (1024 * 1024)).toStringAsFixed(1)} MB';
    return '${(bytes / (1024 * 1024 * 1024)).toStringAsFixed(1)} GB';
  }
}
```

### Peer List Widget

**lib/presentation/widgets/peer_list_widget.dart:**
```dart
import 'package:flutter/material.dart';
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:flutter_screenutil/flutter_screenutil.dart';
import '../bloc/network/network_bloc.dart';

class PeerListWidget extends StatelessWidget {
  const PeerListWidget({super.key});

  @override
  Widget build(BuildContext context) {
    return BlocBuilder<NetworkBloc, NetworkState>(
      builder: (context, state) {
        if (state.peers.isEmpty) {
          return _buildEmptyState(context);
        }

        return Card(
          margin: EdgeInsets.all(16.w),
          child: Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Padding(
                padding: EdgeInsets.all(16.w),
                child: Row(
                  children: [
                    Icon(
                      Icons.people,
                      size: 24.w,
                      color: Theme.of(context).colorScheme.primary,
                    ),
                    SizedBox(width: 8.w),
                    Text(
                      'Connected Peers (${state.peers.length})',
                      style: Theme.of(context).textTheme.titleMedium,
                    ),
                  ],
                ),
              ),
              
              ListView.separated(
                shrinkWrap: true,
                physics: const NeverScrollableScrollPhysics(),
                itemCount: state.peers.length,
                separatorBuilder: (context, index) => const Divider(height: 1),
                itemBuilder: (context, index) {
                  final peer = state.peers[index];
                  return _buildPeerTile(context, peer);
                },
              ),
            ],
          ),
        );
      },
    );
  }

  Widget _buildEmptyState(BuildContext context) {
    return Card(
      margin: EdgeInsets.all(16.w),
      child: Padding(
        padding: EdgeInsets.all(32.w),
        child: Column(
          children: [
            Icon(
              Icons.people_outline,
              size: 48.w,
              color: Theme.of(context).colorScheme.onSurfaceVariant,
            ),
            SizedBox(height: 16.h),
            Text(
              'No Connected Peers',
              style: Theme.of(context).textTheme.titleMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            SizedBox(height: 8.h),
            Text(
              'Connect to the mesh network to see available peers',
              style: Theme.of(context).textTheme.bodyMedium?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              textAlign: TextAlign.center,
            ),
          ],
        ),
      ),
    );
  }

  Widget _buildPeerTile(BuildContext context, Peer peer) {
    return ListTile(
      leading: CircleAvatar(
        backgroundColor: _getPeerTypeColor(peer.type),
        child: Icon(
          _getPeerTypeIcon(peer.type),
          color: Colors.white,
          size: 20.w,
        ),
      ),
      
      title: Text(
        peer.name,
        style: Theme.of(context).textTheme.bodyMedium?.copyWith(
          fontWeight: FontWeight.w500,
        ),
      ),
      
      subtitle: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            peer.meshIp,
            style: Theme.of(context).textTheme.bodySmall,
          ),
          Row(
            children: [
              Icon(
                Icons.speed,
                size: 12.w,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              SizedBox(width: 4.w),
              Text(
                '${peer.latencyMs.toStringAsFixed(0)}ms',
                style: Theme.of(context).textTheme.bodySmall,
              ),
              SizedBox(width: 16.w),
              Icon(
                Icons.signal_cellular_alt,
                size: 12.w,
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
              SizedBox(width: 4.w),
              Text(
                _getSignalStrength(peer.reliability),
                style: Theme.of(context).textTheme.bodySmall,
              ),
            ],
          ),
        ],
      ),
      
      trailing: PopupMenuButton<String>(
        onSelected: (action) => _handlePeerAction(context, peer, action),
        itemBuilder: (context) => [
          const PopupMenuItem(
            value: 'info',
            child: ListTile(
              leading: Icon(Icons.info),
              title: Text('View Details'),
            ),
          ),
          if (peer.type != PeerType.exit)
            const PopupMenuItem(
              value: 'set_exit',
              child: ListTile(
                leading: Icon(Icons.vpn_lock),
                title: Text('Use as Exit Node'),
              ),
            ),
          const PopupMenuItem(
            value: 'disconnect',
            child: ListTile(
              leading: Icon(Icons.block),
              title: Text('Disconnect'),
            ),
          ),
        ],
      ),
    );
  }

  Color _getPeerTypeColor(PeerType type) {
    switch (type) {
      case PeerType.exit:
        return Colors.green;
      case PeerType.relay:
        return Colors.blue;
      case PeerType.client:
        return Colors.orange;
    }
  }

  IconData _getPeerTypeIcon(PeerType type) {
    switch (type) {
      case PeerType.exit:
        return Icons.vpn_lock;
      case PeerType.relay:
        return Icons.router;
      case PeerType.client:
        return Icons.devices;
    }
  }

  String _getSignalStrength(double reliability) {
    if (reliability > 0.9) return 'Excellent';
    if (reliability > 0.7) return 'Good';
    if (reliability > 0.5) return 'Fair';
    return 'Poor';
  }

  void _handlePeerAction(BuildContext context, Peer peer, String action) {
    final networkBloc = context.read<NetworkBloc>();
    
    switch (action) {
      case 'info':
        _showPeerDetails(context, peer);
        break;
      case 'set_exit':
        networkBloc.add(SetExitNodeRequested(peer.id));
        break;
      case 'disconnect':
        networkBloc.add(DisconnectPeerRequested(peer.id));
        break;
    }
  }

  void _showPeerDetails(BuildContext context, Peer peer) {
    showDialog(
      context: context,
      builder: (context) => AlertDialog(
        title: Text(peer.name),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildDetailRow('Type', peer.type.name.toUpperCase()),
            _buildDetailRow('Mesh IP', peer.meshIp),
            _buildDetailRow('Public Address', peer.publicAddress ?? 'N/A'),
            _buildDetailRow('Latency', '${peer.latencyMs.toStringAsFixed(0)}ms'),
            _buildDetailRow('Reliability', '${(peer.reliability * 100).toStringAsFixed(1)}%'),
            _buildDetailRow('Version', peer.version),
            _buildDetailRow('Connected', _formatDuration(peer.connectionTime)),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.of(context).pop(),
            child: const Text('Close'),
          ),
        ],
      ),
    );
  }

  Widget _buildDetailRow(String label, String value) {
    return Padding(
      padding: EdgeInsets.symmetric(vertical: 4.h),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Text(
            label,
            style: const TextStyle(fontWeight: FontWeight.w500),
          ),
          Text(value),
        ],
      ),
    );
  }

  String _formatDuration(DateTime connectionTime) {
    final duration = DateTime.now().difference(connectionTime);
    if (duration.inDays > 0) {
      return '${duration.inDays}d ${duration.inHours % 24}h';
    } else if (duration.inHours > 0) {
      return '${duration.inHours}h ${duration.inMinutes % 60}m';
    } else {
      return '${duration.inMinutes}m';
    }
  }
}
```

---

## 🏗️ State Management

### Connection Bloc

**lib/presentation/bloc/connection/connection_bloc.dart:**
```dart
import 'package:flutter_bloc/flutter_bloc.dart';
import 'package:equatable/equatable.dart';
import '../../../core/services/aegisray_service.dart';

// Events
abstract class ConnectionEvent extends Equatable {
  const ConnectionEvent();
  
  @override
  List<Object?> get props => [];
}

class ConnectRequested extends ConnectionEvent {
  const ConnectRequested();
}

class DisconnectRequested extends ConnectionEvent {
  const DisconnectRequested();
}

class ConnectionStatusChanged extends ConnectionEvent {
  final ConnectionStatus status;
  const ConnectionStatusChanged(this.status);
  
  @override
  List<Object?> get props => [status];
}

class NetworkStatsUpdated extends ConnectionEvent {
  final NetworkStats stats;
  const NetworkStatsUpdated(this.stats);
  
  @override
  List<Object?> get props => [stats];
}

// State
class ConnectionState extends Equatable {
  final ConnectionStatus connectionStatus;
  final String? meshIp;
  final String? exitNode;
  final List<Peer> connectedPeers;
  final int bytesTransferred;
  final String? errorMessage;
  
  const ConnectionState({
    this.connectionStatus = ConnectionStatus.disconnected,
    this.meshIp,
    this.exitNode,
    this.connectedPeers = const [],
    this.bytesTransferred = 0,
    this.errorMessage,
  });
  
  ConnectionState copyWith({
    ConnectionStatus? connectionStatus,
    String? meshIp,
    String? exitNode,
    List<Peer>? connectedPeers,
    int? bytesTransferred,
    String? errorMessage,
  }) {
    return ConnectionState(
      connectionStatus: connectionStatus ?? this.connectionStatus,
      meshIp: meshIp ?? this.meshIp,
      exitNode: exitNode ?? this.exitNode,
      connectedPeers: connectedPeers ?? this.connectedPeers,
      bytesTransferred: bytesTransferred ?? this.bytesTransferred,
      errorMessage: errorMessage ?? this.errorMessage,
    );
  }
  
  @override
  List<Object?> get props => [
    connectionStatus,
    meshIp,
    exitNode,
    connectedPeers,
    bytesTransferred,
    errorMessage,
  ];
}

// Bloc
class ConnectionBloc extends Bloc<ConnectionEvent, ConnectionState> {
  final AegisRayService _aegisRayService;
  
  ConnectionBloc(this._aegisRayService) : super(const ConnectionState()) {
    on<ConnectRequested>(_onConnectRequested);
    on<DisconnectRequested>(_onDisconnectRequested);
    on<ConnectionStatusChanged>(_onConnectionStatusChanged);
    on<NetworkStatsUpdated>(_onNetworkStatsUpdated);
    
    // Listen to service streams
    _aegisRayService.connectionStateStream.listen((status) {
      add(ConnectionStatusChanged(status));
    });
    
    _aegisRayService.networkStatsStream.listen((stats) {
      add(NetworkStatsUpdated(stats));
    });
  }
  
  Future<void> _onConnectRequested(
    ConnectRequested event,
    Emitter<ConnectionState> emit,
  ) async {
    try {
      emit(state.copyWith(
        connectionStatus: ConnectionStatus.connecting,
        errorMessage: null,
      ));
      
      // Get configured peers from settings
      final config = await _aegisRayService.getConfiguration();
      
      await _aegisRayService.connect(
        staticPeers: config.staticPeers,
        exitNodeId: config.preferredExitNode,
      );
      
    } catch (e) {
      emit(state.copyWith(
        connectionStatus: ConnectionStatus.error,
        errorMessage: e.toString(),
      ));
    }
  }
  
  Future<void> _onDisconnectRequested(
    DisconnectRequested event,
    Emitter<ConnectionState> emit,
  ) async {
    try {
      await _aegisRayService.disconnect();
    } catch (e) {
      emit(state.copyWith(
        errorMessage: e.toString(),
      ));
    }
  }
  
  void _onConnectionStatusChanged(
    ConnectionStatusChanged event,
    Emitter<ConnectionState> emit,
  ) {
    emit(state.copyWith(connectionStatus: event.status));
  }
  
  void _onNetworkStatsUpdated(
    NetworkStatsUpdated event,
    Emitter<ConnectionState> emit,
  ) {
    emit(state.copyWith(
      bytesTransferred: event.stats.totalBytesTransferred,
      meshIp: event.stats.meshIp,
    ));
  }
}
```

---

## 📱 Platform-Specific Features

### Android VPN Service

**android/app/src/main/kotlin/com/aegisray/flutter/VpnService.kt:**
```kotlin
package com.aegisray.flutter

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import java.io.FileInputStream
import java.io.FileOutputStream

class AegisRayVpnService : VpnService() {
    private var vpnInterface: ParcelFileDescriptor? = null
    private var isRunning = false
    
    companion object {
        private const val VPN_MTU = 1500
        private const val NOTIFICATION_ID = 1
        private const val CHANNEL_ID = "AegisRayVPN"
    }
    
    override fun onCreate() {
        super.onCreate()
        createNotificationChannel()
    }
    
    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            "START_VPN" -> startVpn()
            "STOP_VPN" -> stopVpn()
        }
        return START_STICKY
    }
    
    private fun startVpn() {
        if (isRunning) return
        
        // Establish VPN interface
        val builder = Builder()
            .setMtu(VPN_MTU)
            .addAddress("100.64.1.2", 16)  // Mesh IP
            .addRoute("0.0.0.0", 0)        // Route all traffic
            .addDnsServer("1.1.1.1")       // Cloudflare DNS
            .addDnsServer("8.8.8.8")       // Google DNS
            .setSession("AegisRay")
            .setConfigureIntent(getPendingIntent())
            
        vpnInterface = builder.establish()
        
        if (vpnInterface != null) {
            isRunning = true
            startForeground(NOTIFICATION_ID, createNotification())
            
            // Start packet processing thread
            Thread { processPackets() }.start()
        }
    }
    
    private fun stopVpn() {
        isRunning = false
        vpnInterface?.close()
        vpnInterface = null
        stopForeground(true)
        stopSelf()
    }
    
    private fun processPackets() {
        val inputStream = FileInputStream(vpnInterface!!.fileDescriptor)
        val outputStream = FileOutputStream(vpnInterface!!.fileDescriptor)
        
        val packet = ByteArray(32767)
        
        while (isRunning) {
            try {
                val length = inputStream.read(packet)
                if (length > 0) {
                    // Forward packet to AegisRay mesh network
                    forwardToMesh(packet.copyOfRange(0, length))
                }
            } catch (e: Exception) {
                if (isRunning) {
                    e.printStackTrace()
                }
                break
            }
        }
    }
    
    private fun forwardToMesh(packet: ByteArray) {
        // Send packet to AegisRay Go library via JNI
        // This would interface with the native AegisRay implementation
        AegisRayNative.forwardPacket(packet)
    }
    
    private fun createNotification(): Notification {
        return NotificationCompat.Builder(this, CHANNEL_ID)
            .setContentTitle("AegisRay VPN")
            .setContentText("Secure mesh network connection active")
            .setSmallIcon(R.drawable.ic_vpn)
            .setOngoing(true)
            .setContentIntent(getPendingIntent())
            .build()
    }
    
    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channel = NotificationChannel(
                CHANNEL_ID,
                "AegisRay VPN",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "AegisRay VPN service notifications"
            }
            
            val notificationManager = getSystemService(NotificationManager::class.java)
            notificationManager.createNotificationChannel(channel)
        }
    }
    
    private fun getPendingIntent(): PendingIntent {
        val intent = packageManager.getLaunchIntentForPackage(packageName)
        return PendingIntent.getActivity(
            this, 0, intent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )
    }
}

// Native interface
object AegisRayNative {
    init {
        System.loadLibrary("aegisray")
    }
    
    external fun initialize(config: String): Boolean
    external fun forwardPacket(packet: ByteArray): Boolean
    external fun getNodeStatus(): String
    external fun shutdown()
}
```

### iOS Network Extension

**ios/NetworkExtension/PacketTunnelProvider.swift:**
```swift
import NetworkExtension
import os.log

class PacketTunnelProvider: NEPacketTunnelProvider {
    private let logger = OSLog(subsystem: "com.aegisray.app", category: "VPN")
    private var isRunning = false
    
    override func startTunnel(options: [String : NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting AegisRay tunnel", log: logger, type: .info)
        
        // Configure network settings
        let networkSettings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "100.64.0.1")
        
        // IPv4 settings
        let ipv4Settings = NEIPv4Settings(addresses: ["100.64.1.2"], subnetMasks: ["255.255.0.0"])
        ipv4Settings.includedRoutes = [NEIPv4Route.default()]
        ipv4Settings.excludedRoutes = []
        
        networkSettings.ipv4Settings = ipv4Settings
        
        // DNS settings
        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        networkSettings.dnsSettings = dnsSettings
        
        // MTU
        networkSettings.mtu = 1420
        
        setTunnelNetworkSettings(networkSettings) { error in
            if let error = error {
                os_log("Failed to set network settings: %@", log: self.logger, type: .error, error.localizedDescription)
                completionHandler(error)
                return
            }
            
            // Initialize AegisRay
            self.initializeAegisRay()
            self.isRunning = true
            self.startPacketProcessing()
            
            completionHandler(nil)
        }
    }
    
    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping AegisRay tunnel", log: logger, type: .info)
        
        isRunning = false
        AegisRayNative.shutdown()
        
        completionHandler()
    }
    
    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app
        if let message = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any] {
            switch message["action"] as? String {
            case "getStatus":
                let status = AegisRayNative.getNodeStatus()
                let responseData = status.data(using: .utf8)
                completionHandler?(responseData)
            case "updateConfig":
                if let configData = message["config"] as? Data {
                    // Update configuration
                    completionHandler?(nil)
                }
            default:
                completionHandler?(nil)
            }
        }
    }
    
    private func initializeAegisRay() {
        let config = AegisRayConfig(
            networkName: "mobile-mesh",
            meshIp: "100.64.1.2",
            staticPeers: [
                "exit1.example.com:443",
                "exit2.example.com:443"
            ]
        )
        
        let configData = try! JSONEncoder().encode(config)
        let configString = String(data: configData, encoding: .utf8)!
        
        AegisRayNative.initialize(configString)
    }
    
    private func startPacketProcessing() {
        packetFlow.readPackets { packets, protocols in
            guard self.isRunning else { return }
            
            for (index, packet) in packets.enumerated() {
                let protocolNumber = protocols[index]
                
                // Forward packet to AegisRay mesh
                self.forwardPacketToMesh(packet, protocol: protocolNumber)
            }
            
            // Continue reading
            if self.isRunning {
                self.startPacketProcessing()
            }
        }
    }
    
    private func forwardPacketToMesh(_ packet: Data, protocol: NSNumber) {
        packet.withUnsafeBytes { bytes in
            let buffer = bytes.bindMemory(to: UInt8.self)
            AegisRayNative.forwardPacket(Array(buffer))
        }
    }
}

// Native bridge
@objc class AegisRayNative: NSObject {
    @objc static func initialize(_ config: String) -> Bool {
        // Call to native Go code
        return aegisray_initialize(config)
    }
    
    @objc static func forwardPacket(_ packet: [UInt8]) -> Bool {
        return aegisray_forward_packet(packet, UInt32(packet.count))
    }
    
    @objc static func getNodeStatus() -> String {
        return String(cString: aegisray_get_node_status())
    }
    
    @objc static func shutdown() {
        aegisray_shutdown()
    }
}

// C bridge to Go code
private func aegisray_initialize(_ config: UnsafePointer<CChar>) -> Bool { 
    // Implementation bridges to Go
    return true
}

private func aegisray_forward_packet(_ packet: UnsafePointer<UInt8>, _ length: UInt32) -> Bool {
    // Implementation bridges to Go
    return true
}

private func aegisray_get_node_status() -> UnsafePointer<CChar> {
    // Implementation bridges to Go
    return "{}".cString(using: .utf8)!
}

private func aegisray_shutdown() {
    // Implementation bridges to Go
}
```

---

This Flutter integration provides a complete mobile app foundation for AegisRay mesh VPN with native platform support, clean state management, and modern UI components. The implementation handles the complexity of VPN integration while providing a simple, reactive API for the Flutter application layer.
