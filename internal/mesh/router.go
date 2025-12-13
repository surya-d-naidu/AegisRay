package mesh

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	pb "github.com/aegisray/vpn-tunnel/proto/mesh"
	"github.com/sirupsen/logrus"
)

// MeshRouter handles packet routing through the P2P mesh network
type MeshRouter struct {
	node   *MeshNode
	logger *logrus.Logger

	// Routing table
	routes  map[string]*Route
	routeMu sync.RWMutex

	// Packet forwarding
	forwardingEnabled bool
	maxHops           int

	// Statistics
	stats *RoutingStats
}

// Route represents a route in the mesh network
type Route struct {
	Destination net.IPNet
	NextHop     string // Peer ID
	Metric      int
	Timestamp   time.Time
	Source      string // Who advertised this route
}

// RoutingStats tracks routing performance
type RoutingStats struct {
	PacketsForwarded int64
	PacketsDropped   int64
	RoutesAdvertised int64
	RoutesReceived   int64
	LastUpdate       time.Time
	mu               sync.RWMutex
}

// NewMeshRouter creates a new mesh router
func NewMeshRouter(node *MeshNode) *MeshRouter {
	return &MeshRouter{
		node:              node,
		logger:            node.logger,
		routes:            make(map[string]*Route),
		forwardingEnabled: true,
		maxHops:           16,
		stats:             &RoutingStats{},
	}
}

// Start starts the mesh router
func (mr *MeshRouter) Start() error {
	mr.logger.Info("Starting mesh router")

	// Add local routes
	mr.addLocalRoutes()

	// Start route advertisement
	go mr.routeAdvertisementLoop()
	go mr.routeMaintenanceLoop()

	mr.logger.Info("Mesh router started")
	return nil
}

// Stop stops the mesh router
func (mr *MeshRouter) Stop() error {
	mr.logger.Info("Stopping mesh router")
	mr.forwardingEnabled = false
	return nil
}

// addLocalRoutes adds routes for local mesh networks
func (mr *MeshRouter) addLocalRoutes() {
	// Add route for our own mesh IP
	_, meshNet, _ := net.ParseCIDR(fmt.Sprintf("%s/32", mr.node.MeshIP.String()))
	mr.routes[mr.node.MeshIP.String()+"/32"] = &Route{
		Destination: *meshNet,
		NextHop:     mr.node.ID, // Self
		Metric:      0,
		Timestamp:   time.Now(),
		Source:      mr.node.ID,
	}

	// If we're an exit node, advertise default route
	if mr.node.config.ExitNode {
		_, defaultRoute, _ := net.ParseCIDR("0.0.0.0/0")
		mr.routes["0.0.0.0/0"] = &Route{
			Destination: *defaultRoute,
			NextHop:     mr.node.ID,
			Metric:      1,
			Timestamp:   time.Now(),
			Source:      mr.node.ID,
		}
		mr.logger.Info("Advertising default route as exit node")
	}
}

// RoutePacket routes a packet through the mesh network
func (mr *MeshRouter) RoutePacket(packet *MeshPacket) error {
	if !mr.forwardingEnabled {
		return fmt.Errorf("routing disabled")
	}

	// Check if packet is for us
	if packet.DestID == mr.node.ID {
		return mr.deliverLocally(packet)
	}

	// Find route to destination
	route := mr.findBestRoute(packet.DestID)
	if route == nil {
		mr.incrementDropped()
		return fmt.Errorf("no route to destination %s", packet.DestID)
	}

	// Check hop limit
	if packet.Metadata == nil {
		packet.Metadata = &pb.PacketMetadata{Ttl: int32(mr.maxHops)}
	}

	packet.Metadata.Ttl--
	if packet.Metadata.Ttl <= 0 {
		mr.incrementDropped()
		return fmt.Errorf("packet TTL expired")
	}

	// Add our node to the path
	if packet.Metadata.Path == nil {
		packet.Metadata.Path = []string{}
	}
	packet.Metadata.Path = append(packet.Metadata.Path, mr.node.ID)

	// Forward to next hop
	return mr.forwardPacket(packet, route.NextHop)
}

// findBestRoute finds the best route to a destination
func (mr *MeshRouter) findBestRoute(destID string) *Route {
	mr.routeMu.RLock()
	defer mr.routeMu.RUnlock()

	var bestRoute *Route
	bestMetric := int(^uint(0) >> 1) // Max int

	// Look for specific host routes first
	for _, route := range mr.routes {
		if route.NextHop == destID || route.Source == destID {
			if route.Metric < bestMetric {
				bestRoute = route
				bestMetric = route.Metric
			}
		}
	}

	// If no specific route, try default route
	if bestRoute == nil {
		if defaultRoute, exists := mr.routes["0.0.0.0/0"]; exists {
			bestRoute = defaultRoute
		}
	}

	return bestRoute
}

// forwardPacket forwards a packet to the next hop
func (mr *MeshRouter) forwardPacket(packet *MeshPacket, nextHopID string) error {
	mr.incrementForwarded()

	// Get P2P client for next hop
	client, exists := mr.node.p2pDiscovery.GetPeerClient(nextHopID)
	if !exists {
		return fmt.Errorf("no connection to next hop %s", nextHopID)
	}

	// Convert to protobuf packet request
	packetReq := &pb.PacketRequest{
		SourceId:      packet.SourceID,
		DestId:        packet.DestID,
		EncryptedData: packet.Payload,
		PacketType:    pb.PacketType(packet.PacketType),
		Metadata:      packet.Metadata,
	}

	// Send packet
	_, err := client.SendPacket(nil, packetReq)
	if err != nil {
		mr.incrementDropped()
		return fmt.Errorf("failed to forward packet: %w", err)
	}

	mr.logger.WithFields(logrus.Fields{
		"source":   packet.SourceID,
		"dest":     packet.DestID,
		"next_hop": nextHopID,
		"ttl":      packet.Metadata.Ttl,
	}).Debug("Packet forwarded")

	return nil
}

// deliverLocally delivers a packet to the local node
func (mr *MeshRouter) deliverLocally(packet *MeshPacket) error {
	mr.logger.WithFields(logrus.Fields{
		"source": packet.SourceID,
		"type":   packet.PacketType,
	}).Debug("Packet delivered locally")

	// Send to mesh packet handler
	select {
	case mr.node.meshPackets <- packet:
		return nil
	default:
		return fmt.Errorf("local delivery queue full")
	}
}

// AdvertiseRoutes advertises routes to peers
func (mr *MeshRouter) AdvertiseRoutes() error {
	mr.routeMu.RLock()
	routes := make([]*pb.Route, 0, len(mr.routes))

	for _, route := range mr.routes {
		if route.Source == mr.node.ID { // Only advertise our own routes
			pbRoute := &pb.Route{
				Destination: route.Destination.String(),
				NextHop:     route.NextHop,
				Metric:      int32(route.Metric),
				RouteType:   pb.RouteType(1), // Mesh route type
			}
			routes = append(routes, pbRoute)
		}
	}
	mr.routeMu.RUnlock()

	if len(routes) == 0 {
		return nil
	}

	// Create route advertisement
	advertisement := &pb.RouteAdvertisement{
		NodeId:         mr.node.ID,
		Routes:         routes,
		SequenceNumber: uint32(time.Now().Unix()),
	}

	// Send to all connected peers
	peers := mr.node.p2pDiscovery.GetActivePeers()
	for peerID := range peers {
		client, exists := mr.node.p2pDiscovery.GetPeerClient(peerID)
		if !exists {
			continue
		}

		go func(c pb.MeshServiceClient, pid string) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			_, err := c.AdvertiseRoutes(ctx, advertisement)
			if err != nil {
				mr.logger.WithError(err).WithField("peer_id", pid).Warn("Failed to advertise routes")
			}
		}(client, peerID)
	}

	mr.incrementAdvertised(int64(len(routes)))
	mr.logger.WithField("route_count", len(routes)).Debug("Advertised routes to peers")

	return nil
}

// ProcessRouteAdvertisement processes incoming route advertisements
func (mr *MeshRouter) ProcessRouteAdvertisement(adv *pb.RouteAdvertisement) error {
	mr.logger.WithFields(logrus.Fields{
		"advertiser":  adv.NodeId,
		"route_count": len(adv.Routes),
		"sequence":    adv.SequenceNumber,
	}).Debug("Processing route advertisement")

	mr.routeMu.Lock()
	defer mr.routeMu.Unlock()

	for _, pbRoute := range adv.Routes {
		_, destNet, err := net.ParseCIDR(pbRoute.Destination)
		if err != nil {
			mr.logger.WithError(err).Warn("Invalid route destination")
			continue
		}

		route := &Route{
			Destination: *destNet,
			NextHop:     adv.NodeId,
			Metric:      int(pbRoute.Metric) + 1, // Add hop count
			Timestamp:   time.Now(),
			Source:      adv.NodeId,
		}

		// Check if we should update this route
		existingRoute, exists := mr.routes[pbRoute.Destination]
		if !exists || route.Metric < existingRoute.Metric {
			mr.routes[pbRoute.Destination] = route
			mr.logger.WithFields(logrus.Fields{
				"destination": pbRoute.Destination,
				"next_hop":    adv.NodeId,
				"metric":      route.Metric,
			}).Debug("Updated route")
		}
	}

	mr.incrementReceived(int64(len(adv.Routes)))
	return nil
}

// routeAdvertisementLoop periodically advertises routes
func (mr *MeshRouter) routeAdvertisementLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mr.AdvertiseRoutes()
		}
	}
}

// routeMaintenanceLoop cleans up old routes
func (mr *MeshRouter) routeMaintenanceLoop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			mr.cleanupOldRoutes()
		}
	}
}

// cleanupOldRoutes removes expired routes
func (mr *MeshRouter) cleanupOldRoutes() {
	mr.routeMu.Lock()
	defer mr.routeMu.Unlock()

	cutoff := time.Now().Add(-5 * time.Minute)

	for dest, route := range mr.routes {
		if route.Source != mr.node.ID && route.Timestamp.Before(cutoff) {
			delete(mr.routes, dest)
			mr.logger.WithField("destination", dest).Debug("Removed expired route")
		}
	}
}

// GetRoutes returns current routing table
func (mr *MeshRouter) GetRoutes() map[string]*Route {
	mr.routeMu.RLock()
	defer mr.routeMu.RUnlock()

	routes := make(map[string]*Route)
	for dest, route := range mr.routes {
		routes[dest] = route
	}
	return routes
}

// GetStats returns routing statistics
func (mr *MeshRouter) GetStats() RoutingStats {
	mr.stats.mu.RLock()
	defer mr.stats.mu.RUnlock()

	// Return a copy to avoid lock issues
	return RoutingStats{
		PacketsForwarded: mr.stats.PacketsForwarded,
		PacketsDropped:   mr.stats.PacketsDropped,
		RoutesAdvertised: mr.stats.RoutesAdvertised,
		RoutesReceived:   mr.stats.RoutesReceived,
		LastUpdate:       mr.stats.LastUpdate,
	}
}

// Statistics helpers
func (mr *MeshRouter) incrementForwarded() {
	mr.stats.mu.Lock()
	mr.stats.PacketsForwarded++
	mr.stats.LastUpdate = time.Now()
	mr.stats.mu.Unlock()
}

func (mr *MeshRouter) incrementDropped() {
	mr.stats.mu.Lock()
	mr.stats.PacketsDropped++
	mr.stats.LastUpdate = time.Now()
	mr.stats.mu.Unlock()
}

func (mr *MeshRouter) incrementAdvertised(count int64) {
	mr.stats.mu.Lock()
	mr.stats.RoutesAdvertised += count
	mr.stats.LastUpdate = time.Now()
	mr.stats.mu.Unlock()
}

func (mr *MeshRouter) incrementReceived(count int64) {
	mr.stats.mu.Lock()
	mr.stats.RoutesReceived += count
	mr.stats.LastUpdate = time.Now()
	mr.stats.mu.Unlock()
}
