// main.go — Hyperledger Fabric 2.x chaincode for tamper-proof security event logging
// Implements: LogSecurityEvent, GetEvent, VerifyEvent, QueryEventHistory, GetEventCount

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ── Data model ────────────────────────────────────────────────────────────────

// SecurityEvent is the on-chain record. Full payload lives in IPFS.
type SecurityEvent struct {
	EventID        string  `json:"event_id"`
	Timestamp      string  `json:"timestamp"`
	AssetID        string  `json:"asset_id"`
	Severity       string  `json:"severity"`
	AttackCategory string  `json:"attack_category"`
	ConfidenceScore float64 `json:"confidence_score"`
	ModelVersion   string  `json:"model_version"`
	PayloadHash    string  `json:"payload_hash"`   // SHA-256 of full IPFS payload
	IPFSCID        string  `json:"ipfs_cid"`
	AgentID        string  `json:"agent_id"`       // X.509 CN of detection agent
	AgentSignature string  `json:"agent_signature"` // ECDSA hex signature
	TxID           string  `json:"tx_id"`           // set at commit time
	BlockNumber    uint64  `json:"block_number"`    // set at commit time
}

// VerificationResult is returned by VerifyEvent.
type VerificationResult struct {
	EventID       string `json:"event_id"`
	IsValid       bool   `json:"is_valid"`
	StoredHash    string `json:"stored_hash"`
	ProvidedHash  string `json:"provided_hash"`
	VerifiedAt    string `json:"verified_at"`
	FailureReason string `json:"failure_reason,omitempty"`
}

// ── Contract ──────────────────────────────────────────────────────────────────

type SecurityLoggerContract struct {
	contractapi.Contract
}

// ── LogSecurityEvent ─────────────────────────────────────────────────────────

// LogSecurityEvent writes a new security event to the ledger.
// eventJSON is the full SecurityEvent JSON (minus tx_id/block_number).
// payloadJSON is the raw off-chain payload whose SHA-256 is verified against
// the payload_hash field before committing.
func (c *SecurityLoggerContract) LogSecurityEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	eventJSON string,
	payloadJSON string,
) error {
	if eventID == "" {
		return fmt.Errorf("event_id must not be empty")
	}

	// Reject duplicate events.
	existing, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return fmt.Errorf("ledger read failed for %s: %w", eventID, err)
	}
	if existing != nil {
		return fmt.Errorf("event %s already exists", eventID)
	}

	// Deserialise the event record.
	var event SecurityEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return fmt.Errorf("invalid event JSON: %w", err)
	}

	// Verify the payload hash.
	actualHash := sha256Hex(payloadJSON)
	if actualHash != event.PayloadHash {
		return fmt.Errorf(
			"payload hash mismatch: got %s, expected %s", actualHash, event.PayloadHash,
		)
	}

	// Stamp transaction context.
	event.TxID = ctx.GetStub().GetTxID()

	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal failed: %w", err)
	}

	if err := ctx.GetStub().PutState(eventID, data); err != nil {
		return fmt.Errorf("PutState failed: %w", err)
	}

	// Emit composite event for event-driven consumers.
	ctx.GetStub().SetEvent("SecurityEventLogged", data)
	return nil
}

// ── GetEvent ─────────────────────────────────────────────────────────────────

func (c *SecurityLoggerContract) GetEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
) (*SecurityEvent, error) {
	data, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("ledger read failed: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("event %s not found", eventID)
	}
	var event SecurityEvent
	if err := json.Unmarshal(data, &event); err != nil {
		return nil, fmt.Errorf("unmarshal failed: %w", err)
	}
	return &event, nil
}

// ── VerifyEvent ──────────────────────────────────────────────────────────────

// VerifyEvent checks whether the provided payloadJSON hashes to the value
// stored on-chain, returning a VerificationResult.
func (c *SecurityLoggerContract) VerifyEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	payloadJSON string,
) (*VerificationResult, error) {
	event, err := c.GetEvent(ctx, eventID)
	if err != nil {
		return nil, err
	}

	providedHash := sha256Hex(payloadJSON)
	isValid := providedHash == event.PayloadHash

	result := &VerificationResult{
		EventID:      eventID,
		IsValid:      isValid,
		StoredHash:   event.PayloadHash,
		ProvidedHash: providedHash,
		VerifiedAt:   time.Now().UTC().Format(time.RFC3339),
	}
	if !isValid {
		result.FailureReason = "SHA-256 hash mismatch — payload may have been tampered with"
	}
	return result, nil
}

// ── QueryEventHistory ────────────────────────────────────────────────────────

// QueryEventHistory returns a paginated, ordered set of events matching the
// optional assetID and time window filters.
// An empty assetID matches all assets.
func (c *SecurityLoggerContract) QueryEventHistory(
	ctx contractapi.TransactionContextInterface,
	assetID string,
	fromTime string,
	toTime string,
) (string, error) {
	// Build CouchDB selector.
	selector := map[string]interface{}{}
	if assetID != "" {
		selector["asset_id"] = assetID
	}
	if fromTime != "" || toTime != "" {
		timeRange := map[string]string{}
		if fromTime != "" {
			timeRange["$gte"] = fromTime
		}
		if toTime != "" {
			timeRange["$lte"] = toTime
		}
		selector["timestamp"] = timeRange
	}

	query := map[string]interface{}{
		"selector": selector,
		"sort":     []map[string]string{{"timestamp": "asc"}},
		"limit":    1000,
	}
	queryBytes, _ := json.Marshal(query)

	iterator, err := ctx.GetStub().GetQueryResult(string(queryBytes))
	if err != nil {
		return "", fmt.Errorf("rich query failed: %w", err)
	}
	defer iterator.Close()

	events := []SecurityEvent{}
	for iterator.HasNext() {
		item, err := iterator.Next()
		if err != nil {
			return "", fmt.Errorf("iterator error: %w", err)
		}
		var ev SecurityEvent
		if err := json.Unmarshal(item.Value, &ev); err != nil {
			continue
		}
		events = append(events, ev)
	}

	result := map[string]interface{}{
		"events":      events,
		"total_count": len(events),
		"asset_id":    assetID,
		"from_time":   fromTime,
		"to_time":     toTime,
	}
	out, err := json.Marshal(result)
	if err != nil {
		return "", fmt.Errorf("marshal result failed: %w", err)
	}
	return string(out), nil
}

// ── GetEventCount ────────────────────────────────────────────────────────────

func (c *SecurityLoggerContract) GetEventCount(
	ctx contractapi.TransactionContextInterface,
	assetID string,
) (int, error) {
	resultStr, err := c.QueryEventHistory(ctx, assetID, "", "")
	if err != nil {
		return 0, err
	}
	var result map[string]interface{}
	if err := json.Unmarshal([]byte(resultStr), &result); err != nil {
		return 0, err
	}
	count, _ := result["total_count"].(float64)
	return int(count), nil
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func sha256Hex(s string) string {
	h := sha256.New()
	h.Write([]byte(s))
	return fmt.Sprintf("%x", h.Sum(nil))
}

// ── Entrypoint ────────────────────────────────────────────────────────────────

func main() {
	cc, err := contractapi.NewChaincode(&SecurityLoggerContract{})
	if err != nil {
		log.Panicf("Failed to create chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("Failed to start chaincode: %v", err)
	}
}
