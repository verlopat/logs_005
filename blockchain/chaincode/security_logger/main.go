// main.go — Hyperledger Fabric Chaincode for Tamper-Proof Security Event Logging
// Objective 2: Blockchain-Based Security Event Logging Architecture
// Research: Blockchain-Enabled Cloud Anomaly Detection System
//
// Contract functions:
//   - LogSecurityEvent   : writes SHA-256 hash + metadata to ledger
//   - VerifyEvent        : verifies integrity of a stored event against its hash
//   - QueryEventHistory  : retrieves full ordered audit trail for an asset/window
//   - GetEvent           : retrieves a single event record by ID
//   - QueryEventsByAsset : rich CouchDB query — all events for a specific asset
//   - QueryEventsBySeverity : rich query — all events above a severity threshold
//   - GetEventCount      : returns total number of logged events

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"log"
	"sort"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

// ── Data Structures ───────────────────────────────────────────────────────────

// SecurityEvent is the on-chain record. Full payload lives in IPFS;
// only the hash + metadata is stored here to keep on-chain footprint < 1KB.
type SecurityEvent struct {
	EventID          string  `json:"event_id"`           // unique UUID from detection agent
	Timestamp        string  `json:"timestamp"`          // ISO-8601 UTC
	AssetID          string  `json:"asset_id"`           // affected cloud resource ID
	Severity         string  `json:"severity"`           // CRITICAL / HIGH / MEDIUM / LOW
	AttackCategory   string  `json:"attack_category"`    // DDoS / InsiderThreat / PrivEsc / PortScan / Normal
	ConfidenceScore  float64 `json:"confidence_score"`   // 0.0 – 1.0 from ML model
	ModelVersion     string  `json:"model_version"`      // e.g. "v1.3.2-cnn-lstm-transformer"
	PayloadHash      string  `json:"payload_hash"`       // SHA-256 of full event JSON (off-chain)
	IPFSCID          string  `json:"ipfs_cid"`           // IPFS content ID of full payload
	AgentID          string  `json:"agent_id"`           // detection agent identity (X.509 CN)
	AgentSignature   string  `json:"agent_signature"`    // ECDSA signature (hex) of payload hash
	DocType          string  `json:"doc_type"`           // always "SecurityEvent" — for CouchDB queries
	TxID             string  `json:"tx_id"`              // Fabric transaction ID (set on commit)
	BlockNumber      uint64  `json:"block_number"`       // populated post-commit via event listener
}

// VerificationResult is returned by VerifyEvent.
type VerificationResult struct {
	EventID       string `json:"event_id"`
	IsValid       bool   `json:"is_valid"`
	StoredHash    string `json:"stored_hash"`
	ComputedHash  string `json:"computed_hash"`
	VerifiedAt    string `json:"verified_at"`
	Message       string `json:"message"`
}

// AuditTrail is returned by QueryEventHistory.
type AuditTrail struct {
	TotalEvents int              `json:"total_events"`
	FromTime    string           `json:"from_time"`
	ToTime      string           `json:"to_time"`
	AssetID     string           `json:"asset_id"`
	Events      []*SecurityEvent `json:"events"`
}

// EventCountResult is returned by GetEventCount.
type EventCountResult struct {
	Total     int    `json:"total"`
	AssetID   string `json:"asset_id,omitempty"`
	QueriedAt string `json:"queried_at"`
}

// ── Chaincode Contract ────────────────────────────────────────────────────────

// SecurityLoggerContract implements the Fabric smart contract.
type SecurityLoggerContract struct {
	contractapi.Contract
}

// ── 1. LogSecurityEvent ───────────────────────────────────────────────────────
// Writes a cryptographic hash of the event payload + metadata to the ledger.
// Only authenticated detection agents (enforced by Fabric MSP policy) can invoke.
//
// Parameters:
//   eventID        — unique identifier (UUID v4 recommended)
//   eventJSON      — full SecurityEvent JSON string from detection agent
//   payloadToHash  — canonical JSON string of the raw event payload (pre-IPFS)
//
// Returns: transaction ID on success.
func (c *SecurityLoggerContract) LogSecurityEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	eventJSON string,
	payloadToHash string,
) (string, error) {

	// ── Access control: only peers with CloudSecOrgMSP client role may write
	clientMSPID, err := ctx.GetClientIdentity().GetMSPID()
	if err != nil {
		return "", fmt.Errorf("failed to get client MSPID: %w", err)
	}
	if clientMSPID != "CloudSecOrgMSP" {
		return "", fmt.Errorf("access denied: only CloudSecOrgMSP clients may log events, got %s", clientMSPID)
	}

	// ── Idempotency: reject duplicate event IDs
	existing, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return "", fmt.Errorf("failed to read state for event %s: %w", eventID, err)
	}
	if existing != nil {
		return "", fmt.Errorf("event %s already exists on ledger — duplicate rejected", eventID)
	}

	// ── Parse incoming event
	var event SecurityEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return "", fmt.Errorf("invalid event JSON: %w", err)
	}

	// ── Validate required fields
	if event.EventID == "" || event.AssetID == "" || event.Severity == "" {
		return "", fmt.Errorf("missing required fields: event_id, asset_id, severity are mandatory")
	}
	if event.EventID != eventID {
		return "", fmt.Errorf("event_id mismatch: parameter %s != body %s", eventID, event.EventID)
	}

	// ── Compute SHA-256 hash of the raw payload
	hash := sha256.Sum256([]byte(payloadToHash))
	computedHash := fmt.Sprintf("%x", hash)

	// ── If agent provided a hash, verify it matches
	if event.PayloadHash != "" && event.PayloadHash != computedHash {
		return "", fmt.Errorf(
			"payload hash mismatch: agent supplied %s, computed %s — event rejected",
			event.PayloadHash, computedHash,
		)
	}
	event.PayloadHash = computedHash

	// ── Stamp with Fabric metadata
	event.DocType = "SecurityEvent"
	event.TxID = ctx.GetStub().GetTxID()

	// ── Timestamp: use chaincode timestamp (deterministic across peers)
	txTimestamp, err := ctx.GetStub().GetTxTimestamp()
	if err != nil {
		return "", fmt.Errorf("failed to get tx timestamp: %w", err)
	}
	if event.Timestamp == "" {
		event.Timestamp = time.Unix(txTimestamp.Seconds, int64(txTimestamp.Nanos)).UTC().Format(time.RFC3339Nano)
	}

	// ── Serialise and persist to world state
	eventBytes, err := json.Marshal(event)
	if err != nil {
		return "", fmt.Errorf("failed to serialise event: %w", err)
	}
	if err := ctx.GetStub().PutState(eventID, eventBytes); err != nil {
		return "", fmt.Errorf("failed to write event to ledger: %w", err)
	}

	// ── Composite key index: asset_id → event_id (enables QueryEventsByAsset)
	assetIndexKey, err := ctx.GetStub().CreateCompositeKey("asset~event", []string{event.AssetID, eventID})
	if err != nil {
		return "", fmt.Errorf("failed to create asset composite key: %w", err)
	}
	if err := ctx.GetStub().PutState(assetIndexKey, []byte{0x00}); err != nil {
		return "", fmt.Errorf("failed to write asset index: %w", err)
	}

	// ── Composite key index: severity → event_id (enables QueryEventsBySeverity)
	severityIndexKey, err := ctx.GetStub().CreateCompositeKey("severity~event", []string{event.Severity, eventID})
	if err != nil {
		return "", fmt.Errorf("failed to create severity composite key: %w", err)
	}
	if err := ctx.GetStub().PutState(severityIndexKey, []byte{0x00}); err != nil {
		return "", fmt.Errorf("failed to write severity index: %w", err)
	}

	// ── Emit Fabric event for off-chain listeners (Python SDK)
	if err := ctx.GetStub().SetEvent("SecurityEventLogged", eventBytes); err != nil {
		log.Printf("WARNING: failed to set chaincode event: %v", err)
	}

	return ctx.GetStub().GetTxID(), nil
}

// ── 2. VerifyEvent ────────────────────────────────────────────────────────────
// Verifies the integrity of a stored event by recomputing its SHA-256 hash
// and comparing it against the stored PayloadHash.
//
// Parameters:
//   eventID       — event to verify
//   payloadToHash — the raw payload JSON (fetched from IPFS by the caller)
//
// Returns: VerificationResult JSON.
func (c *SecurityLoggerContract) VerifyEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
	payloadToHash string,
) (*VerificationResult, error) {

	// ── Fetch stored record
	eventBytes, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read event %s: %w", eventID, err)
	}
	if eventBytes == nil {
		return nil, fmt.Errorf("event %s not found on ledger", eventID)
	}

	var event SecurityEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		return nil, fmt.Errorf("failed to deserialise event: %w", err)
	}

	// ── Recompute hash from provided payload
	hash := sha256.Sum256([]byte(payloadToHash))
	computedHash := fmt.Sprintf("%x", hash)

	// ── Compare
	isValid := computedHash == event.PayloadHash
	message := "INTEGRITY VERIFIED: payload hash matches ledger record"
	if !isValid {
		message = fmt.Sprintf(
			"INTEGRITY VIOLATION: computed hash %s does not match stored hash %s",
			computedHash, event.PayloadHash,
		)
	}

	return &VerificationResult{
		EventID:      eventID,
		IsValid:      isValid,
		StoredHash:   event.PayloadHash,
		ComputedHash: computedHash,
		VerifiedAt:   time.Now().UTC().Format(time.RFC3339),
		Message:      message,
	}, nil
}

// ── 3. QueryEventHistory ──────────────────────────────────────────────────────
// Retrieves the complete, ordered audit trail for a specified asset over a
// specified time window. Uses Fabric's GetHistoryForKey for immutable history.
//
// Parameters:
//   assetID   — cloud resource identifier (empty string = all assets)
//   fromTime  — ISO-8601 UTC start (inclusive), empty = no lower bound
//   toTime    — ISO-8601 UTC end   (inclusive), empty = no upper bound
//
// Returns: AuditTrail JSON.
func (c *SecurityLoggerContract) QueryEventHistory(
	ctx contractapi.TransactionContextInterface,
	assetID string,
	fromTime string,
	toTime string,
) (*AuditTrail, error) {

	var fromT, toT time.Time
	var hasFrom, hasTo bool

	if fromTime != "" {
		var err error
		fromT, err = time.Parse(time.RFC3339, fromTime)
		if err != nil {
			return nil, fmt.Errorf("invalid fromTime format (use RFC3339): %w", err)
		}
		hasFrom = true
	}
	if toTime != "" {
		var err error
		toT, err = time.Parse(time.RFC3339, toTime)
		if err != nil {
			return nil, fmt.Errorf("invalid toTime format (use RFC3339): %w", err)
		}
		hasTo = true
	}

	var events []*SecurityEvent

	if assetID != "" {
		// ── Targeted query: use composite key index for the specific asset
		resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("asset~event", []string{assetID})
		if err != nil {
			return nil, fmt.Errorf("failed to query asset index for %s: %w", assetID, err)
		}
		defer resultsIterator.Close()

		for resultsIterator.HasNext() {
			responseRange, err := resultsIterator.Next()
			if err != nil {
				return nil, fmt.Errorf("iterator error: %w", err)
			}
			_, compositeKeyParts, err := ctx.GetStub().SplitCompositeKey(responseRange.Key)
			if err != nil || len(compositeKeyParts) < 2 {
				continue
			}
			eid := compositeKeyParts[1]
			eventBytes, err := ctx.GetStub().GetState(eid)
			if err != nil || eventBytes == nil {
				continue
			}
			var ev SecurityEvent
			if err := json.Unmarshal(eventBytes, &ev); err != nil {
				continue
			}
			// Time filter
			if hasFrom || hasTo {
				evTime, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
				if err != nil {
					evTime, _ = time.Parse(time.RFC3339, ev.Timestamp)
				}
				if hasFrom && evTime.Before(fromT) {
					continue
				}
				if hasTo && evTime.After(toT) {
					continue
				}
			}
			evCopy := ev
			events = append(events, &evCopy)
		}
	} else {
		// ── Broad query: iterate entire world state (use range query)
		// NOTE: In production, use CouchDB rich queries for large datasets.
		resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
		if err != nil {
			return nil, fmt.Errorf("failed to get state range: %w", err)
		}
		defer resultsIterator.Close()

		for resultsIterator.HasNext() {
			response, err := resultsIterator.Next()
			if err != nil {
				return nil, fmt.Errorf("iterator error: %w", err)
			}
			var ev SecurityEvent
			if err := json.Unmarshal(response.Value, &ev); err != nil {
				continue // skip non-SecurityEvent entries (index keys etc.)
			}
			if ev.DocType != "SecurityEvent" {
				continue
			}
			if hasFrom || hasTo {
				evTime, err := time.Parse(time.RFC3339Nano, ev.Timestamp)
				if err != nil {
					evTime, _ = time.Parse(time.RFC3339, ev.Timestamp)
				}
				if hasFrom && evTime.Before(fromT) {
					continue
				}
				if hasTo && evTime.After(toT) {
					continue
				}
			}
			evCopy := ev
			events = append(events, &evCopy)
		}
	}

	// ── Sort by timestamp ascending (chronological audit trail)
	sort.Slice(events, func(i, j int) bool {
		ti, _ := time.Parse(time.RFC3339Nano, events[i].Timestamp)
		tj, _ := time.Parse(time.RFC3339Nano, events[j].Timestamp)
		return ti.Before(tj)
	})

	return &AuditTrail{
		TotalEvents: len(events),
		FromTime:    fromTime,
		ToTime:      toTime,
		AssetID:     assetID,
		Events:      events,
	}, nil
}

// ── 4. GetEvent ───────────────────────────────────────────────────────────────
// Retrieves a single event record from the ledger by its ID.
func (c *SecurityLoggerContract) GetEvent(
	ctx contractapi.TransactionContextInterface,
	eventID string,
) (*SecurityEvent, error) {

	eventBytes, err := ctx.GetStub().GetState(eventID)
	if err != nil {
		return nil, fmt.Errorf("failed to read event %s: %w", eventID, err)
	}
	if eventBytes == nil {
		return nil, fmt.Errorf("event %s not found", eventID)
	}
	var event SecurityEvent
	if err := json.Unmarshal(eventBytes, &event); err != nil {
		return nil, fmt.Errorf("failed to deserialise event: %w", err)
	}
	return &event, nil
}

// ── 5. QueryEventsByAsset ─────────────────────────────────────────────────────
// CouchDB rich query: returns all events for a specific asset ID.
// Requires CouchDB state database (configured in docker-compose).
func (c *SecurityLoggerContract) QueryEventsByAsset(
	ctx contractapi.TransactionContextInterface,
	assetID string,
) ([]*SecurityEvent, error) {

	queryString := fmt.Sprintf(
		`{"selector":{"doc_type":"SecurityEvent","asset_id":"%s"},"sort":[{"timestamp":"asc"}]}`,
		assetID,
	)
	return executeRichQuery(ctx, queryString)
}

// ── 6. QueryEventsBySeverity ──────────────────────────────────────────────────
// CouchDB rich query: returns all events matching a given severity level.
func (c *SecurityLoggerContract) QueryEventsBySeverity(
	ctx contractapi.TransactionContextInterface,
	severity string,
) ([]*SecurityEvent, error) {

	queryString := fmt.Sprintf(
		`{"selector":{"doc_type":"SecurityEvent","severity":"%s"},"sort":[{"timestamp":"desc"}]}`,
		severity,
	)
	return executeRichQuery(ctx, queryString)
}

// ── 7. GetEventCount ──────────────────────────────────────────────────────────
// Returns the total number of SecurityEvents on the ledger.
// Optionally scoped to a specific assetID.
func (c *SecurityLoggerContract) GetEventCount(
	ctx contractapi.TransactionContextInterface,
	assetID string,
) (*EventCountResult, error) {

	var count int

	if assetID != "" {
		resultsIterator, err := ctx.GetStub().GetStateByPartialCompositeKey("asset~event", []string{assetID})
		if err != nil {
			return nil, fmt.Errorf("failed to count events for asset %s: %w", assetID, err)
		}
		defer resultsIterator.Close()
		for resultsIterator.HasNext() {
			if _, err := resultsIterator.Next(); err != nil {
				break
			}
			count++
		}
	} else {
		queryString := `{"selector":{"doc_type":"SecurityEvent"},"fields":["event_id"]}`
		events, err := executeRichQuery(ctx, queryString)
		if err != nil {
			return nil, err
		}
		count = len(events)
	}

	return &EventCountResult{
		Total:     count,
		AssetID:   assetID,
		QueriedAt: time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// ── Helper: executeRichQuery ──────────────────────────────────────────────────
// Executes a CouchDB rich query and returns a slice of SecurityEvent pointers.
func executeRichQuery(
	ctx contractapi.TransactionContextInterface,
	queryString string,
) ([]*SecurityEvent, error) {

	resultsIterator, err := ctx.GetStub().GetQueryResult(queryString)
	if err != nil {
		return nil, fmt.Errorf("rich query failed: %w", err)
	}
	defer resultsIterator.Close()

	var events []*SecurityEvent
	for resultsIterator.HasNext() {
		response, err := resultsIterator.Next()
		if err != nil {
			return nil, fmt.Errorf("iterator error: %w", err)
		}
		var ev SecurityEvent
		if err := json.Unmarshal(response.Value, &ev); err != nil {
			continue
		}
		evCopy := ev
		events = append(events, &evCopy)
	}
	return events, nil
}

// ── Entry Point ───────────────────────────────────────────────────────────────

func main() {
	cc, err := contractapi.NewChaincode(&SecurityLoggerContract{})
	if err != nil {
		log.Panicf("Error creating SecurityLogger chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("Error starting SecurityLogger chaincode: %v", err)
	}
}
