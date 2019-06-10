extern crate civic_sip as civic;
use civic::{CivicSip, CivicSipConfig};
use Option::None;

/// The following variables are fake one
/// In order to execute the test, you have to register a Civic Application

// This is the AC (Authorized Code) returned by CIVIC Frontend app
// AC are encoded as a JWT token
const AC_JWT: &'static str = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJqdGkiOiIyMDU1MmE2Yy03Nzc3LTQ5ZTAtOWNkYy1kNTU3ZjgwM2Q1ZjUiLCJpYXQiOjE1NjAxMjM3NzEuOTMsImV4cCI6MTU2MDEyNTU3MS45MywiaXNzIjoiY2l2aWMtc2lwLWhvc3RlZC1zZXJ2aWNlIiwiYXVkIjoiaHR0cHM6Ly9hcGkuY2l2aWMuY29tL3NpcC8iLCJzdWIiOiJhYmNfeHh4eDAiLCJkYXRhIjp7ImNvZGVUb2tlbiI6ImQ4OTYwYWU3LWRkY2EtNGEwOS1hNDFlLWRhMDk4NDY2ZDNhZiJ9fQ.35ZcMDeaKNWKeJ-XKi1kpD1gILaCKccat6aiQw2_-fw";

const CONFIG: CivicSipConfig = CivicSipConfig {
    app_id: "abc_xxxx0", // Application ID from integration portal
    app_secret: "8d93def18dba11b3bc58c38a77746201", // 16bytes hexadecimal Secret related to your Application
    private_key: "ef3e8749ba05f80832be9fcaf7dd20ef392e12b263f0dd1a6ea888e9f97f9680", // 32bytes hexadecimal Private Signing Key related to your Application
    proxy: None, // Enable it for use HTTP/S Proxy
};

fn main() {
    let sip: CivicSip = CivicSip::new(CONFIG, None);
    let data = sip.exchange_code(AC_JWT).unwrap();
    println!("data: {:?}", data);
}
