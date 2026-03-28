package clashapi

import (
	stdjson "encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/service"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/render"
)

// BindingInfo tracks a dynamically created inbound+outbound pair.
type BindingInfo struct {
	Tag         string `json:"tag"`
	InboundTag  string `json:"inbound_tag"`
	OutboundTag string `json:"outbound_tag"`
	ListenPort  uint16 `json:"listen_port"`
}

// BindingManager holds state for dynamic proxy bindings.
type BindingManager struct {
	server   *Server
	logger   log.ContextLogger
	bindings map[string]*BindingInfo
	mu       sync.Mutex
}

func newBindingManager(server *Server, logFactory log.Factory) *BindingManager {
	return &BindingManager{
		server:   server,
		logger:   logFactory.NewLogger("bindings"),
		bindings: make(map[string]*BindingInfo),
	}
}

func bindingRouter(bm *BindingManager) http.Handler {
	r := chi.NewRouter()
	r.Get("/", bm.listBindings)
	r.Post("/", bm.createBinding)
	r.Delete("/{tag}", bm.deleteBinding)
	return r
}

func (bm *BindingManager) listBindings(w http.ResponseWriter, r *http.Request) {
	bm.mu.Lock()
	result := make([]*BindingInfo, 0, len(bm.bindings))
	for _, b := range bm.bindings {
		result = append(result, b)
	}
	bm.mu.Unlock()
	render.JSON(w, r, result)
}

type createBindingRequest struct {
	Tag        string             `json:"tag"`
	ListenPort uint16             `json:"listen_port"`
	Outbound   stdjson.RawMessage `json:"outbound"`
}

func (bm *BindingManager) createBinding(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("failed to read body"))
		return
	}

	var req createBindingRequest
	if err := stdjson.Unmarshal(body, &req); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid JSON: "+err.Error()))
		return
	}
	if req.Tag == "" || req.ListenPort == 0 || len(req.Outbound) == 0 {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("tag, listen_port, and outbound are required"))
		return
	}

	bm.mu.Lock()
	if _, exists := bm.bindings[req.Tag]; exists {
		bm.mu.Unlock()
		render.Status(r, http.StatusConflict)
		render.JSON(w, r, newError("binding already exists: "+req.Tag))
		return
	}
	bm.mu.Unlock()

	// Parse outbound options using the context with registries
	var outboundOpt option.Outbound
	if err := json.UnmarshalContext(bm.server.ctx, req.Outbound, &outboundOpt); err != nil {
		render.Status(r, http.StatusBadRequest)
		render.JSON(w, r, newError("invalid outbound config: "+err.Error()))
		return
	}

	outboundTag := "bind-out-" + req.Tag
	inboundTag := "bind-in-" + req.Tag

	// Create outbound
	if err := bm.server.outbound.Create(
		bm.server.ctx, bm.server.router, bm.logger,
		outboundTag, outboundOpt.Type, outboundOpt.Options,
	); err != nil {
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("failed to create outbound: "+err.Error()))
		return
	}

	// Create inbound (mixed HTTP+SOCKS5 on 127.0.0.1:listen_port)
	inboundJSON := fmt.Sprintf(`{"type":"mixed","listen":"127.0.0.1","listen_port":%d}`, req.ListenPort)
	var inboundOpt option.Inbound
	if err := json.UnmarshalContext(bm.server.ctx, []byte(inboundJSON), &inboundOpt); err != nil {
		// Rollback: remove outbound
		bm.server.outbound.Remove(outboundTag)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("failed to parse inbound config: "+err.Error()))
		return
	}

	inboundMgr := service.FromContext[adapter.InboundManager](bm.server.ctx)
	if err := inboundMgr.Create(
		bm.server.ctx, bm.server.router, bm.logger,
		inboundTag, inboundOpt.Type, inboundOpt.Options,
	); err != nil {
		// Rollback: remove outbound
		bm.server.outbound.Remove(outboundTag)
		render.Status(r, http.StatusInternalServerError)
		render.JSON(w, r, newError("failed to create inbound: "+err.Error()))
		return
	}

	// Bind inbound → outbound in router
	bm.server.router.BindInboundOutbound(inboundTag, outboundTag)

	binding := &BindingInfo{
		Tag:         req.Tag,
		InboundTag:  inboundTag,
		OutboundTag: outboundTag,
		ListenPort:  req.ListenPort,
	}
	bm.mu.Lock()
	bm.bindings[req.Tag] = binding
	bm.mu.Unlock()

	bm.logger.Info("created binding: ", req.Tag, " (port ", req.ListenPort, " → ", outboundOpt.Type, ")")
	render.Status(r, http.StatusCreated)
	render.JSON(w, r, binding)
}

func (bm *BindingManager) deleteBinding(w http.ResponseWriter, r *http.Request) {
	tag := chi.URLParam(r, "tag")

	bm.mu.Lock()
	binding, exists := bm.bindings[tag]
	if !exists {
		bm.mu.Unlock()
		render.Status(r, http.StatusNotFound)
		render.JSON(w, r, newError("binding not found: "+tag))
		return
	}
	delete(bm.bindings, tag)
	bm.mu.Unlock()

	// Unbind route
	bm.server.router.UnbindInbound(binding.InboundTag)

	// Remove inbound first (stops listening)
	inboundMgr := service.FromContext[adapter.InboundManager](bm.server.ctx)
	if err := inboundMgr.Remove(binding.InboundTag); err != nil {
		bm.logger.Warn("failed to remove inbound ", binding.InboundTag, ": ", err)
	}

	// Remove outbound
	if err := bm.server.outbound.Remove(binding.OutboundTag); err != nil {
		bm.logger.Warn("failed to remove outbound ", binding.OutboundTag, ": ", err)
	}

	bm.logger.Info("deleted binding: ", tag)
	render.NoContent(w, r)
}
