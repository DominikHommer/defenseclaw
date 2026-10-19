package manager

import "testing"

// The heartbeat's last-applied emergency sequence must reach the device record
// so operators can confirm a kill switch was applied (GET /devices/{id}).
func TestProcessHeartbeatRecordsLastEmergencySeq(t *testing.T) {
	fm := New(nil)
	fm.RegisterDevice(1, 1, 42, "sbc", "1.0.0", 1, 0xFF)
	if !fm.ProcessHeartbeat(1, 1, 42, &Heartbeat{DeviceID: 42, PolicyVersion: 1, LastEmergencySeq: 7}) {
		t.Fatal("heartbeat rejected")
	}
	dev, ok := fm.GetDevice(ComposeID(1, 1, 42))
	if !ok {
		t.Fatal("device missing")
	}
	if dev.LastEmergencySeq != 7 {
		t.Fatalf("LastEmergencySeq = %d, want 7", dev.LastEmergencySeq)
	}
}
