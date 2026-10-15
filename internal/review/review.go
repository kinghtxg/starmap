// Package review 事件复核闭环（SPEC §5/§6）：
// confirm → Confirmed；false_positive → 自动写白名单（node/ip 维度）+ 事件 FalsePositive；
// defer → Deferred。全部操作 AddAuditLog 留痕。
package review

import (
	"errors"
	"fmt"
	"strconv"

	"starmap/internal/detect"
	"starmap/internal/model"
	"starmap/internal/store"
	"starmap/internal/topology"
)

// 合法复核动作
const (
	ActionConfirm       = "confirm"
	ActionFalsePositive = "false_positive"
	ActionDefer         = "defer"
)

// ErrInvalidAction 非法复核动作
var ErrInvalidAction = errors.New("非法复核动作：仅支持 confirm|false_positive|defer")

// ErrEventNotFound 事件不存在
var ErrEventNotFound = errors.New("事件不存在")

// Reviewer 复核服务
type Reviewer struct {
	Store  *store.Store
	Engine *topology.Engine // 可为 nil（测试可只走存储）
}

// New 创建复核服务。
func New(st *store.Store, eng *topology.Engine) *Reviewer {
	return &Reviewer{Store: st, Engine: eng}
}

// Review 执行复核三操作，返回更新后的事件。
func (r *Reviewer) Review(eventID int64, action, note, reviewer string) (*model.RiskEvent, error) {
	ev, err := r.Store.GetEvent(eventID)
	if err != nil {
		return nil, err
	}
	if ev == nil {
		return nil, ErrEventNotFound
	}
	if reviewer == "" {
		reviewer = "system"
	}

	switch action {
	case ActionConfirm:
		if err := r.Store.UpdateEventStatus(eventID, model.EventStatusConfirmed, note, reviewer); err != nil {
			return nil, err
		}
		r.audit(reviewer, "event_confirm", "event:"+strconv.FormatInt(eventID, 10),
			fmt.Sprintf("确认事件 type=%s node=%d note=%s", ev.Type, ev.NodeID, note))

	case ActionFalsePositive:
		if err := r.Store.UpdateEventStatus(eventID, model.EventStatusFalsePositive, note, reviewer); err != nil {
			return nil, err
		}
		// 自动加白：node 维度 + 节点全部 IP 维度
		wlNote := fmt.Sprintf("复核误报自动加白（事件 #%d）", eventID)
		entries := []model.WhitelistEntry{}
		if r.Engine != nil {
			if n := r.Engine.GetNode(ev.NodeID); n != nil {
				// P0-2：node 维度改用稳定 NodeKey（mac:<mac>|ip:<主 IP>）。
				// NodeKey 跨进程重启不变，避免 node:<自增 ID> 重启后指向无关节点造成静默抑制。
				if n.NodeKey != "" {
					entries = append(entries, model.WhitelistEntry{Kind: "node", Value: n.NodeKey, Note: wlNote})
				}
				// 兼容条目：保留 node:<node_id>。节点现已持久化并按原 ID 恢复，
				// 该 ID 重启后仍指向同一节点，旧 UI/脚本依赖的格式继续有效（匹配端见 detect.matchNodeDimension）。
				entries = append(entries, model.WhitelistEntry{Kind: "node", Value: strconv.FormatInt(ev.NodeID, 10), Note: wlNote})
				for _, ip := range n.IPs {
					entries = append(entries, model.WhitelistEntry{Kind: "ip", Value: ip, Note: wlNote})
				}
				// 误报后节点风险回退
				r.Engine.SetNodeRisk(ev.NodeID, model.RiskNone)
			}
		}
		if len(entries) == 0 {
			// 节点已被清理或未挂载引擎：退化为旧行为，至少保证 node 维度有条目
			entries = append(entries, model.WhitelistEntry{Kind: "node", Value: strconv.FormatInt(ev.NodeID, 10), Note: wlNote})
		}
		for _, w := range entries {
			if _, err := r.Store.CreateWhitelistEntry(&w); err != nil {
				return nil, err
			}
			r.audit(reviewer, "whitelist_create", w.Kind+":"+w.Value, wlNote)
		}
		r.audit(reviewer, "event_false_positive", "event:"+strconv.FormatInt(eventID, 10),
			fmt.Sprintf("误报事件 type=%s node=%d note=%s（已自动加白）", ev.Type, ev.NodeID, note))

	case ActionDefer:
		if err := r.Store.UpdateEventStatus(eventID, model.EventStatusDeferred, note, reviewer); err != nil {
			return nil, err
		}
		r.audit(reviewer, "event_defer", "event:"+strconv.FormatInt(eventID, 10),
			fmt.Sprintf("暂缓事件 type=%s node=%d note=%s", ev.Type, ev.NodeID, note))

	default:
		return nil, ErrInvalidAction
	}

	return r.Store.GetEvent(eventID)
}

// SuppressByWhitelist 白名单新增/更新后：已有 pending 事件命中 → 自动 false_positive（§5）。
// 返回被抑制的事件数。
func (r *Reviewer) SuppressByWhitelist(entry model.WhitelistEntry, actor string) (int, error) {
	pending, err := r.Store.ListEvents(model.EventStatusPending, "")
	if err != nil {
		return 0, err
	}
	suppressed := 0
	for i := range pending {
		ev := &pending[i]
		var node *model.Node
		if r.Engine != nil {
			node = r.Engine.GetNode(ev.NodeID)
		}
		if !detect.MatchWhitelist(entry, ev, node) {
			continue
		}
		note := fmt.Sprintf("白名单 %s:%s 命中，自动置为误报", entry.Kind, entry.Value)
		if err := r.Store.UpdateEventStatus(ev.ID, model.EventStatusFalsePositive, note, actor); err != nil {
			return suppressed, err
		}
		if r.Engine != nil {
			r.Engine.SetNodeRisk(ev.NodeID, model.RiskNone)
		}
		r.audit(actor, "event_auto_false_positive", "event:"+strconv.FormatInt(ev.ID, 10), note)
		suppressed++
	}
	return suppressed, nil
}

func (r *Reviewer) audit(actor, action, target, detail string) {
	_, _ = r.Store.AddAuditLog(&model.AuditLog{Actor: actor, Action: action, Target: target, Detail: detail})
}

// Audit 暴露审计写入（API 层其他动作复用）。
func (r *Reviewer) Audit(actor, action, target, detail string) {
	r.audit(actor, action, target, detail)
}
