package service

import (
	"context"
	"net"

	"github.com/p4gefau1t/trojan-go/api"
	"github.com/p4gefau1t/trojan-go/common"
	"github.com/p4gefau1t/trojan-go/config"
	"github.com/p4gefau1t/trojan-go/log"
	"github.com/p4gefau1t/trojan-go/statistic"
	"github.com/p4gefau1t/trojan-go/tunnel/trojan"
)

type ClientAPI struct {
	TrojanClientServiceServer

	auth          statistic.Authenticator
	ctx           context.Context
	uploadSpeed   uint64
	downloadSpeed uint64
	lastSent      uint64
	lastRecv      uint64
}

func (s *ClientAPI) GetTraffic(ctx context.Context, req *GetTrafficRequest) (*GetTrafficResponse, error) {
	log.Debug("API: GetTraffic")
	if req.User == nil {
		return nil, common.NewError("User is unspecified")
	}
	if req.User.Hash == "" {
		req.User.Hash = common.SHA224String(req.User.Password)
	}
	valid, user := s.auth.AuthUser(req.User.Hash)
	if !valid {
		return nil, common.NewError("User " + req.User.Hash + " not found")
	}
	sent, recv := user.GetTraffic()
	sentSpeed, recvSpeed := user.GetSpeed()
	resp := &GetTrafficResponse{
		Success: true,
		TrafficTotal: &Traffic{
			UploadTraffic:   sent,
			DownloadTraffic: recv,
		},
		SpeedCurrent: &Speed{
			UploadSpeed:   sentSpeed,
			DownloadSpeed: recvSpeed,
		},
	}
	return resp, nil
}

func (s *ClientAPI) GetUsersTraffic(ctx context.Context, req *GetUsersTrafficRequest) (*GetUsersTrafficResponse, error) {
	traffics := make(map[string]*Traffic)
	for _, user := range req.Users {
		if user.Hash == "" {
			user.Hash = common.SHA224String(user.Password)
		}
		valid, user := s.auth.AuthUser(user.Hash)
		if !valid {
			log.Warnf("User:%s not found", user.Hash())
		} else {
			sent, recv := user.GetTraffic()
			traffic := &Traffic{
				UploadTraffic:   sent,
				DownloadTraffic: recv,
			}
			traffics[user.Hash()] = traffic
		}
	}
	return &GetUsersTrafficResponse{Traffics: traffics}, nil
}

func (s *ClientAPI) ResetTraffics(ctx context.Context, req *ResetUsersTrafficRequest) (*ResetUsersTrafficResponse, error) {
	var resetUsers []*User
	for _, user := range req.Users {
		if user.Hash == "" {
			user.Hash = common.SHA224String(user.Password)
		}
		valid, auth := s.auth.AuthUser(user.Hash)
		if !valid {
			log.Warnf("User:%s not found,and reset failed", auth.Hash())
			resetUsers = append(resetUsers, user)
		} else {
			auth.ResetTraffic()
		}
	}
	return &ResetUsersTrafficResponse{Users: resetUsers}, nil
}
func RunClientAPI(ctx context.Context, auth statistic.Authenticator) error {
	cfg := config.FromContext(ctx, Name).(*Config)
	if !cfg.API.Enabled {
		return nil
	}
	server, err := newAPIServer(cfg)
	if err != nil {
		return err
	}
	defer server.Stop()
	service := &ClientAPI{
		ctx:  ctx,
		auth: auth,
	}
	RegisterTrojanClientServiceServer(server, service)
	addr, err := net.ResolveIPAddr("ip", cfg.API.APIHost)
	if err != nil {
		return common.NewError("api found invalid addr").Base(err)
	}
	listener, err := net.Listen("tcp", (&net.TCPAddr{
		IP:   addr.IP,
		Port: cfg.API.APIPort,
		Zone: addr.Zone,
	}).String())
	if err != nil {
		return common.NewError("client api failed to listen").Base(err)
	}
	defer listener.Close()
	log.Info("client-side api service is listening on", listener.Addr().String())
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Serve(listener)
	}()
	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Debug("closed")
		return nil
	}
}

func init() {
	api.RegisterHandler(trojan.Name+"_CLIENT", RunClientAPI)
}
