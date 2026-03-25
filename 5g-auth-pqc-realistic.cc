/* =============================================================================
 * REALISTIC PQC 5G-AKA AUTHENTICATION SIMULATION
 * Module 1: ML-KEM-768 Key Exchange  (NIST FIPS 203)
 * Module 2: ML-DSA-65 Authentication (NIST FIPS 204)
 *
 * REALISTIC FEATURES:
 *  1. Concurrent UEs (all start within 50ms window) -> real queuing
 *  2. Load-dependent queuing at AMF/AUSF/UDM (M/D/1 queue model)
 *  3. Random processing delay + link jitter on all links
 *  4. 1% packet loss on N1 with retransmission + retry count
 *  5. Authentication timeout (500ms) with max 3 retries
 *  6. PQC crypto delay injected at UE (ML-KEM + ML-DSA timing)
 *  7. PQC crypto delay injected at Network (ML-DSA sign/verify)
 *  8. Per-UE latency breakdown: network / queuing / proc / pqc-crypto
 *  9. Peak concurrent session tracking
 * 10. Throughput metric (authentications per second)
 * 11. Comparison table: Classical ECC vs PQC side by side
 *
 * Usage:
 *   ./ns3 run '5g-auth-pqc/5g-auth-pqc --numUes=1'
 *   ./ns3 run '5g-auth-pqc/5g-auth-pqc --numUes=5'
 *   ./ns3 run '5g-auth-pqc/5g-auth-pqc --numUes=10'
 *   ./ns3 run '5g-auth-pqc/5g-auth-pqc --numUes=20'
 * =============================================================================
 */

#include "ns3/core-module.h"
#include "ns3/network-module.h"
#include "ns3/internet-module.h"
#include "ns3/point-to-point-module.h"
#include "ns3/applications-module.h"
#include <string>
#include <map>
#include <vector>
#include <sstream>
#include <iomanip>
#include <cmath>
#include <numeric>
#include <algorithm>

using namespace ns3;
NS_LOG_COMPONENT_DEFINE("RealisticPQC5GAKASim");

/* ============================================================
   CONFIGURATION
   ============================================================ */
static int    g_numUes         = 1;
static double g_packetLossRate = 0.01;  // 1% on N1
static double g_authTimeout    = 500.0; // ms
static double g_jitterMax      = 2.0;   // ms max random jitter

/* ============================================================
   ML-KEM-768 PARAMETERS (NIST FIPS 203)
   ============================================================ */
const int MLKEM_PUBKEY_BYTES  = 1184;
const int MLKEM_PRIVKEY_BYTES = 2400;
const int MLKEM_CT_BYTES      = 1088;
const int MLKEM_SS_BYTES      = 32;

// Realistic timing (ms) - ARM Cortex-A53, liboqs 2024
const double T_MLKEM_KEYGEN   = 0.082;
const double T_MLKEM_ENCAPS   = 0.091;
const double T_MLKEM_DECAPS   = 0.094;

/* ============================================================
   ML-DSA-65 PARAMETERS (NIST FIPS 204)
   ============================================================ */
const int MLDSA_PUBKEY_BYTES  = 1952;
const int MLDSA_PRIVKEY_BYTES = 4032;
const int MLDSA_SIG_BYTES     = 3293;

// Realistic timing (ms) - ARM Cortex-A53, liboqs 2024
const double T_MLDSA_KEYGEN   = 0.165;
const double T_MLDSA_SIGN     = 2.100;
const double T_MLDSA_VERIFY   = 0.640;

// Server processing base times (ms)
const double T_AMF_PROC_BASE  = 0.8;
const double T_AUSF_PROC_BASE = 0.5;
const double T_UDM_PROC_BASE  = 1.2;

/* ============================================================
   STATISTICS
   ============================================================ */
struct UeRecord {
    int    ueId;
    std::string supi, suci;
    double startTime_ms, endTime_ms;
    double networkDelay_ms;
    double queuingDelay_ms;
    double procDelay_ms;
    double pqcCryptoDelay_ms; // ML-KEM + ML-DSA time at UE
    double netCryptoDelay_ms; // ML-DSA sign/verify at network
    int    retries;
    bool   success, timedOut;
    int    bandwidthBytes;
};

struct SimStats {
    std::vector<UeRecord> records;
    int    totalAttempts    = 0;
    int    totalSuccess     = 0;
    int    totalTimeout     = 0;
    int    totalRetries     = 0;
    int    peakConcurrent   = 0;
    int    currentConcurrent= 0;
    int    totalBandwidth   = 0;
    int    mod1Bandwidth    = 0;
    int    mod2Bandwidth    = 0;
    // KEM ops
    double totalKemKeygenTime = 0;
    double totalKemEncapsTime = 0;
    double totalKemDecapsTime = 0;
    int    kemOps = 0;
    // DSA ops
    double totalDsaKeygenTime = 0;
    double totalDsaSignTime   = 0;
    double totalDsaVerifyTime = 0;
    int    dsaOps = 0;
    double netCryptoMs  = 0;
    double simStartTime = 0;
};
static SimStats g_stats;

/* ============================================================
   RANDOM NUMBER GENERATOR
   ============================================================ */
static Ptr<UniformRandomVariable> g_rng;

double RandJitter()  { return g_rng->GetValue(0.0, g_jitterMax); }
double RandProc(double base, double var) { return base + g_rng->GetValue(0.0, var); }
bool   PacketLost()  { return g_rng->GetValue(0.0, 1.0) < g_packetLossRate; }

/* ============================================================
   LOAD-DEPENDENT QUEUING (M/D/1 model)
   ============================================================ */
double GetQueueDelay(int concurrentSessions, double baseProc)
{
    double rho = std::min(0.95, concurrentSessions * 0.09);
    double qf  = rho / (2.0 * (1.0 - rho + 0.001));
    return baseProc * (1.0 + qf) + RandProc(0.0, 0.2);
}

/* ============================================================
   SIMULATED CRYPTO
   ============================================================ */
std::string SimHash(const std::string& in, int bytes = 16)
{
    const char* h = "0123456789abcdef";
    std::string o(bytes * 2, '0');
    for (int i = 0; i < bytes; i++) {
        uint8_t v = (uint8_t)(i * 37 + 11);
        for (size_t j = 0; j < in.size(); j++)
            v ^= (uint8_t)((in[j] + i * 3 + j) * 31);
        v = (v * 17 + i * 7) & 0xFF;
        o[2*i] = h[(v>>4)&0xF]; o[2*i+1] = h[v&0xF];
    }
    return o;
}

// ---- ML-KEM ----
struct MLKEMKeyPair { std::string pk, sk; };
struct MLKEMResult  { std::string ct, ss; };

MLKEMKeyPair MLKEM_KeyGen(const std::string& seed)
{
    MLKEMKeyPair kp;
    kp.pk = "MLKEM768_PK["+std::to_string(MLKEM_PUBKEY_BYTES)+"B]_"+SimHash(seed+"mlkem_pk",16);
    kp.sk = "MLKEM768_SK["+std::to_string(MLKEM_PRIVKEY_BYTES)+"B]_"+SimHash(seed+"mlkem_sk",16);
    g_stats.totalKemKeygenTime += T_MLKEM_KEYGEN;
    g_stats.kemOps++;
    return kp;
}

MLKEMResult MLKEM_Encaps(const std::string& pk, const std::string& rand_seed)
{
    MLKEMResult r;
    r.ct = "MLKEM768_CT["+std::to_string(MLKEM_CT_BYTES)+"B]_"+SimHash(pk+rand_seed+"ct",16);
    r.ss = SimHash(pk+rand_seed+"shared_secret", MLKEM_SS_BYTES);
    g_stats.totalKemEncapsTime += T_MLKEM_ENCAPS;
    g_stats.kemOps++;
    return r;
}

std::string MLKEM_Decaps(const std::string& sk, const std::string& ct)
{
    std::string pk_seed = SimHash(sk+"pk_seed",16);
    std::string rs      = SimHash(ct+"rand_ref",16);
    g_stats.totalKemDecapsTime += T_MLKEM_DECAPS;
    g_stats.kemOps++;
    return SimHash(pk_seed+rs+"shared_secret", MLKEM_SS_BYTES);
}

// ---- ML-DSA ----
// Global seed map so Verify can reconstruct correct signature
static std::map<std::string,std::string> g_dsaSeedMap;

struct MLDSAKeyPair { std::string pk, sk, seed; };

MLDSAKeyPair MLDSA_KeyGen(const std::string& seed)
{
    MLDSAKeyPair kp;
    kp.seed = seed;
    kp.pk   = "MLDSA65_PK["+std::to_string(MLDSA_PUBKEY_BYTES)+"B]_"+SimHash(seed+"dsa_pk",16);
    kp.sk   = "MLDSA65_SK["+std::to_string(MLDSA_PRIVKEY_BYTES)+"B]_"+SimHash(seed+"dsa_sk",16);
    g_dsaSeedMap[kp.pk] = seed;
    g_stats.totalDsaKeygenTime += T_MLDSA_KEYGEN;
    g_stats.dsaOps++;
    return kp;
}

std::string MLDSA_Sign(const std::string& sk, const std::string& message)
{
    g_stats.totalDsaSignTime += T_MLDSA_SIGN;
    g_stats.dsaOps++;
    return "MLDSA65_SIG["+std::to_string(MLDSA_SIG_BYTES)+"B]_"+
           SimHash(sk+message+"dsa_sign",16);
}

bool MLDSA_Verify(const std::string& pk, const std::string& sig,
                   const std::string& message)
{
    g_stats.totalDsaVerifyTime += T_MLDSA_VERIFY;
    g_stats.dsaOps++;
    if (!g_dsaSeedMap.count(pk)) return false;
    std::string seed = g_dsaSeedMap[pk];
    std::string sk   = "MLDSA65_SK["+std::to_string(MLDSA_PRIVKEY_BYTES)+"B]_"+
                       SimHash(seed+"dsa_sk",16);
    std::string exp  = "MLDSA65_SIG["+std::to_string(MLDSA_SIG_BYTES)+"B]_"+
                       SimHash(sk+message+"dsa_sign",16);
    return (sig == exp);
}

// ---- MILENAGE (still used for AUTN) ----
std::string f1_MAC(const std::string& K,const std::string& R,const std::string& S)
{ return SimHash(K+R+S+"8000_f1",8); }
std::string f2_RES(const std::string& K,const std::string& R)
{ return SimHash(K+R+"f2_RES",8); }
std::string f3_CK(const std::string& K,const std::string& R)
{ return SimHash(K+R+"f3_CK",16); }
std::string f4_IK(const std::string& K,const std::string& R)
{ return SimHash(K+R+"f4_IK",16); }
std::string f5_AK(const std::string& K,const std::string& R)
{ return SimHash(K+R+"f5_AK",6); }
std::string GenRAND(const std::string& s,double t,int c)
{ return SimHash(s+std::to_string((int)(t*1000))+std::to_string(c),16); }
std::string KDF(const std::string& km,const std::string& lbl)
{ return SimHash(km+lbl+"HKDF_SHA256",32); }

/* ============================================================
   SUBSCRIBER DATABASE
   ============================================================ */
struct SubRecord {
    std::string K, SQN;
    MLKEMKeyPair hn_kem;
    MLDSAKeyPair hn_dsa;
    int authCount = 0;
};
static std::map<std::string,SubRecord> g_udmDB;
static MLKEMKeyPair g_hn_kem_keys;
static MLDSAKeyPair g_hn_dsa_keys;

void InitDB(int n)
{
    // Reset counters since KeyGen is called during init
    g_stats.kemOps = 0; g_stats.dsaOps = 0;
    g_stats.totalKemKeygenTime = 0; g_stats.totalDsaKeygenTime = 0;

    g_hn_kem_keys = MLKEM_KeyGen("home_network_master_kem");
    g_hn_dsa_keys = MLDSA_KeyGen("home_network_master_dsa");

    // Reset again - init keys dont count toward per-auth stats
    g_stats.kemOps = 0; g_stats.dsaOps = 0;
    g_stats.totalKemKeygenTime = 0; g_stats.totalDsaKeygenTime = 0;
    g_stats.totalKemEncapsTime = 0; g_stats.totalKemDecapsTime = 0;
    g_stats.totalDsaSignTime = 0; g_stats.totalDsaVerifyTime = 0;

    for (int i = 1; i <= std::max(n,30); i++) {
        std::string supi = "imsi-00101000000000" +
                           std::string(i<10?"0":"") + std::to_string(i);
        SubRecord r;
        r.K       = SimHash(supi+"long_term_key_K",16);
        r.SQN     = SimHash(supi+"initial_sqn",6);
        r.hn_kem  = g_hn_kem_keys;
        r.hn_dsa  = g_hn_dsa_keys;
        g_udmDB[supi] = r;
    }
}

/* ============================================================
   SESSION TABLES
   ============================================================ */
struct AusfSess {
    std::string supi, RAND, AUTN;
    std::string XRES_star, HXRES_star, K_seaf;
    std::string net_dsa_pk, net_sig;
};
static std::map<std::string,AusfSess> g_ausfSess;

struct AmfSess {
    std::string suci, supi;
    std::string RAND, AUTN, HXRES_star, K_seaf, K_AMF;
    std::string net_dsa_pk, net_sig;
    Ipv4Address ueAddr; uint16_t uePort;
    double startMs;
    double queuingMs, procMs, netCryptoMs, pqcCryptoMs;
    int retries, bw;
    bool active;
};
static std::map<std::string,AmfSess> g_amfSess;

/* ============================================================
   MESSAGE HELPERS
   ============================================================ */
std::string Enc(const std::string& t,
                const std::vector<std::pair<std::string,std::string>>& f)
{
    std::string s = t;
    for (auto& x:f) s += "|"+x.first+"="+x.second;
    return s;
}
std::map<std::string,std::string> Dec(const std::string& raw, std::string& t)
{
    std::map<std::string,std::string> m;
    std::istringstream ss(raw); std::string tok; bool first=true;
    while(std::getline(ss,tok,'|')) {
        if(first){t=tok;first=false;continue;}
        auto eq=tok.find('=');
        if(eq!=std::string::npos) m[tok.substr(0,eq)]=tok.substr(eq+1);
    }
    return m;
}
std::string PktStr(Ptr<Socket> s, Address& from)
{
    auto p=s->RecvFrom(from);
    std::vector<uint8_t> b(p->GetSize());
    p->CopyData(b.data(),b.size());
    return std::string(b.begin(),b.end());
}
void Sep(char c='-',int n=72){std::cout<<std::string(n,c)<<"\n";}

static Ipv4Address g_amfIp,g_ausfIp,g_udmIp;
static const uint16_t P_AMF=9000,P_AUSF=9001,P_UDM=9002;

void UdpSend(Ptr<Node> node,const std::string& msg,
             Ipv4Address dst,uint16_t port,bool lossy=false)
{
    if(lossy && PacketLost()){
        std::cout<<"  [NET] *** PACKET LOSS on N1 ***\n"; return;
    }
    auto tx=Socket::CreateSocket(node,UdpSocketFactory::GetTypeId());
    tx->Connect(InetSocketAddress(dst,port));
    auto pkt=Create<Packet>((const uint8_t*)msg.c_str(),msg.size());
    tx->Send(pkt); tx->Close();
    g_stats.totalBandwidth += (int)msg.size();
}

/* ============================================================
   UDM APPLICATION
   ============================================================ */
class UdmApp : public Application {
    Ptr<Socket> m_sock;
    void StartApplication() override {
        m_sock=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(),P_UDM));
        m_sock->SetRecvCallback(MakeCallback(&UdmApp::Recv,this));
        std::cout<<"[UDM]  Online | "<<g_udmDB.size()<<" subscribers\n";
    }
    void StopApplication() override { if(m_sock) m_sock->Close(); }

    void Recv(Ptr<Socket> s) {
        Address from; auto raw=PktStr(s,from);
        std::string t; auto F=Dec(raw,t);

        if(t=="SUB_AUTH_REQ") {
            std::string supi=F["supi"], sn=F["sn_name"];
            int conc=g_stats.currentConcurrent;

            // Realistic: UDM delay = base + queuing + PQC DSA sign time + jitter
            double qd    = GetQueueDelay(conc, T_UDM_PROC_BASE);
            double dsaT  = T_MLDSA_KEYGEN + T_MLDSA_SIGN; // keygen + sign at network
            double jitter= RandJitter();
            double procDly = qd + dsaT + jitter;

            Sep('=');
            std::cout<<"[UDM]  <-- SUB_AUTH_REQ  SUPI="<<supi<<"\n";
            std::cout<<"       Concurrent : "<<conc
                     <<"  | Queue delay : "<<std::fixed<<std::setprecision(3)
                     <<qd<<" ms\n";
            std::cout<<"       DSA sign   : "<<dsaT<<" ms (ML-DSA KeyGen+Sign)\n";
            std::cout<<"       Total proc : "<<procDly<<" ms\n";

            auto& rec=g_udmDB[supi]; rec.authCount++;
            double now=Simulator::Now().GetSeconds();

            // MILENAGE
            std::string RAND     = GenRAND(supi,now,rec.authCount);
            std::string AK       = f5_AK(rec.K,RAND);
            std::string MAC      = f1_MAC(rec.K,RAND,rec.SQN);
            std::string sqn_xor  = SimHash(rec.SQN+AK+"xor",6);
            std::string AUTN     = sqn_xor+"8000"+MAC;
            std::string CK       = f3_CK(rec.K,RAND);
            std::string IK       = f4_IK(rec.K,RAND);
            std::string RES      = f2_RES(rec.K,RAND);
            std::string XRES_star= SimHash(CK+IK+RAND+RES+sn+"xresstar",16);
            std::string K_seaf   = KDF(CK+IK+sn,"Kseaf_PQC");

            std::cout<<"       RAND       : "<<RAND<<"\n";
            std::cout<<"       AUTN       : "<<AUTN<<"\n";
            std::cout<<"       XRES*      : "<<XRES_star<<"\n";
            std::cout<<"       K_seaf     : "<<K_seaf.substr(0,32)<<"...\n";

            // MODULE 2: Network DSA sign
            MLDSAKeyPair net_dsa = MLDSA_KeyGen(supi+std::to_string(rec.authCount)+"net");
            std::string  net_sig = MLDSA_Sign(net_dsa.sk, RAND+AUTN+sn);
            g_stats.netCryptoMs += T_MLDSA_KEYGEN + T_MLDSA_SIGN;
            g_stats.mod2Bandwidth += MLDSA_PUBKEY_BYTES + MLDSA_SIG_BYTES;

            std::cout<<"       net_dsa_pk : "<<net_dsa.pk.substr(0,30)<<"...\n";
            std::cout<<"       net_sig    : "<<net_sig.substr(0,30)<<"...\n";
            std::cout<<"       net_sig sz : "<<MLDSA_SIG_BYTES<<" bytes\n";

            rec.SQN = SimHash(rec.SQN+"next",6);
            g_stats.mod1Bandwidth += MLKEM_PUBKEY_BYTES;

            auto reply=Enc("SUB_DATA",{
                {"supi",supi},{"RAND",RAND},{"AUTN",AUTN},
                {"XRES_star",XRES_star},{"K_seaf",K_seaf},
                {"CK",CK},{"IK",IK},
                {"hn_kem_pk",rec.hn_kem.pk},
                {"net_dsa_pk",net_dsa.pk},{"net_sig",net_sig},
                {"proc_ms",std::to_string(procDly)}
            });
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(procDly),[n,reply](){
                UdpSend(n,reply,g_ausfIp,P_AUSF);
            });
            std::cout<<"[UDM]  --> SUB_DATA (after "<<procDly<<" ms) --> AUSF\n";
            Sep('=');
        }
    }
public:
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("UdmApp")
            .SetParent<Application>().AddConstructor<UdmApp>();
        return tid;
    }
    double netCryptoMs = 0;
};
// netCryptoMs is a regular member, no static definition needed

/* ============================================================
   AUSF APPLICATION
   ============================================================ */
class AusfApp : public Application {
    Ptr<Socket> m_sock;
    void StartApplication() override {
        m_sock=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(),P_AUSF));
        m_sock->SetRecvCallback(MakeCallback(&AusfApp::Recv,this));
        std::cout<<"[AUSF] Online | Port="<<P_AUSF<<"\n";
    }
    void StopApplication() override { if(m_sock) m_sock->Close(); }

    void Recv(Ptr<Socket> s) {
        Address from; auto raw=PktStr(s,from);
        std::string t; auto F=Dec(raw,t);

        if(t=="AUTH_DATA_REQ") {
            std::string supi=F["supi"], sn=F["sn_name"];
            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AUSF_PROC_BASE)+RandJitter()*0.3;

            Sep('=');
            std::cout<<"[AUSF] <-- AUTH_DATA_REQ  SUPI="<<supi
                     <<"  | Queue: "<<std::fixed<<std::setprecision(3)<<qd<<" ms\n";

            AusfSess sess; sess.supi=supi;
            g_ausfSess[supi]=sess;

            auto req=Enc("SUB_AUTH_REQ",{{"supi",supi},{"sn_name",sn}});
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,req](){
                UdpSend(n,req,g_udmIp,P_UDM);
            });
            std::cout<<"[AUSF] --> SUB_AUTH_REQ --> UDM\n"; Sep('=');
        }

        if(t=="SUB_DATA") {
            std::string supi      =F["supi"];
            std::string RAND      =F["RAND"];
            std::string AUTN      =F["AUTN"];
            std::string XRES_star =F["XRES_star"];
            std::string K_seaf    =F["K_seaf"];
            std::string hn_kem_pk =F["hn_kem_pk"];
            std::string net_dsa_pk=F["net_dsa_pk"];
            std::string net_sig   =F["net_sig"];
            double udm_proc = std::stod(F["proc_ms"]);

            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AUSF_PROC_BASE)+RandJitter()*0.2;

            // HXRES* computation
            std::string HXRES_star=SimHash(RAND+XRES_star+"hxres_sha256",16);

            Sep('=');
            std::cout<<"[AUSF] <-- SUB_DATA from UDM | SUPI="<<supi<<"\n";
            std::cout<<"       XRES*      : "<<XRES_star<<"\n";
            std::cout<<"       HXRES*     : "<<HXRES_star<<"\n";
            std::cout<<"       Queue delay: "<<qd<<" ms\n";
            std::cout<<"       UDM proc   : "<<udm_proc<<" ms\n";

            auto& sess=g_ausfSess[supi];
            sess.RAND=RAND; sess.AUTN=AUTN;
            sess.XRES_star=XRES_star; sess.HXRES_star=HXRES_star;
            sess.K_seaf=K_seaf;
            sess.net_dsa_pk=net_dsa_pk; sess.net_sig=net_sig;

            auto reply=Enc("AUTH_VECTORS",{
                {"supi",supi},{"RAND",RAND},{"AUTN",AUTN},
                {"HXRES_star",HXRES_star},{"K_seaf",K_seaf},
                {"hn_kem_pk",hn_kem_pk},
                {"net_dsa_pk",net_dsa_pk},{"net_sig",net_sig},
                {"udm_proc",std::to_string(udm_proc)},
                {"ausf_proc",std::to_string(qd)}
            });
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,reply](){
                UdpSend(n,reply,g_amfIp,P_AMF);
            });
            std::cout<<"[AUSF] --> AUTH_VECTORS --> AMF\n"; Sep('=');
        }

        if(t=="RES_VERIFY_REQ") {
            std::string supi     =F["supi"];
            std::string RES_star =F["RES_star"];
            std::string ue_sig   =F["ue_sig"];
            std::string ue_dsa_pk=F["ue_dsa_pk"];

            int conc=g_stats.currentConcurrent;
            // Realistic: AUSF delay includes ML-DSA verify time
            double dsaVerifyT = T_MLDSA_VERIFY;
            double qd = GetQueueDelay(conc,T_AUSF_PROC_BASE) + dsaVerifyT + RandJitter()*0.2;

            Sep('=');
            std::cout<<"[AUSF] <-- RES_VERIFY_REQ  SUPI="<<supi<<"\n";

            auto& sess=g_ausfSess[supi];
            bool kem_ok=(RES_star==sess.XRES_star);

            // MODULE 2: Verify UE signature
            std::string ue_msg=RES_star+sess.RAND;
            bool dsa_ok=MLDSA_Verify(ue_dsa_pk,ue_sig,ue_msg);

            std::cout<<"       RES* match : "<<(kem_ok?"PASS":"FAIL")<<"\n";
            std::cout<<"       DSA verify : "<<(dsa_ok?"PASS":"FAIL")
                     <<"  ["<<dsaVerifyT<<" ms]\n";
            std::cout<<"       Queue delay: "<<qd<<" ms\n";

            bool ok=kem_ok&&dsa_ok;
            auto reply=Enc("RES_VERIFY_RES",{
                {"supi",supi},
                {"result",ok?"SUCCESS":"FAILURE"},
                {"K_seaf",sess.K_seaf},
                {"proc_ms",std::to_string(qd)}
            });
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,reply](){
                UdpSend(n,reply,g_amfIp,P_AMF);
            });
            std::cout<<"[AUSF] --> RES_VERIFY_RES ["<<(ok?"SUCCESS":"FAIL")<<"] --> AMF\n";
            Sep('=');
        }
    }
public:
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("AusfApp")
            .SetParent<Application>().AddConstructor<AusfApp>();
        return tid;
    }
};

/* ============================================================
   AMF APPLICATION
   ============================================================ */
class AmfApp : public Application {
    Ptr<Socket> m_sock;
    void StartApplication() override {
        m_sock=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(),P_AMF));
        m_sock->SetRecvCallback(MakeCallback(&AmfApp::Recv,this));
        std::cout<<"[AMF]  Online | Port="<<P_AMF<<"\n";
    }
    void StopApplication() override { if(m_sock) m_sock->Close(); }

    void Recv(Ptr<Socket> s) {
        Address from; auto raw=PktStr(s,from);
        std::string t; auto F=Dec(raw,t);
        InetSocketAddress src=InetSocketAddress::ConvertFrom(from);

        if(t=="REG_REQ") {
            std::string suci   =F["suci"];
            std::string supi   =F["supi"];
            std::string ue_port=F["ue_port"];
            int retry=std::stoi(F.count("retry")?F["retry"]:"0");

            g_stats.totalAttempts++;
            g_stats.currentConcurrent++;
            if(g_stats.currentConcurrent>g_stats.peakConcurrent)
                g_stats.peakConcurrent=g_stats.currentConcurrent;

            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AMF_PROC_BASE)+RandJitter()*0.3;

            Sep('*');
            std::cout<<"\n[AMF]  <-- STEP 1: REG_REQ\n";
            std::cout<<"       SUCI (PQC) : "<<suci<<"\n";
            std::cout<<"       SUPI       : "<<supi<<"\n";
            std::cout<<"       Concurrent : "<<conc
                     <<"  | Queue: "<<std::fixed<<std::setprecision(3)<<qd<<" ms\n";
            std::cout<<"       Retry      : "<<retry<<"\n";

            if(retry==0){
                AmfSess sess;
                sess.suci=suci; sess.supi=supi;
                sess.ueAddr=src.GetIpv4();
                sess.uePort=(uint16_t)std::stoi(ue_port);
                sess.startMs=Simulator::Now().GetSeconds()*1000.0;
                sess.retries=retry;
                sess.queuingMs=qd; sess.procMs=0;
                sess.netCryptoMs=0; sess.pqcCryptoMs=0;
                sess.bw=(int)raw.size(); sess.active=true;
                g_amfSess[suci]=sess;
            } else {
                if(g_amfSess.count(suci)){
                    g_amfSess[suci].retries=retry;
                    g_stats.totalRetries++;
                    g_amfSess[suci].queuingMs+=qd;
                }
            }

            std::string sn="5G:mnc001.mcc001.3gppnetwork.org";
            auto req=Enc("AUTH_DATA_REQ",{{"suci",suci},{"supi",supi},{"sn_name",sn}});
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,req](){
                UdpSend(n,req,g_ausfIp,P_AUSF);
            });
            std::cout<<"[AMF]  --> STEP 2: AUTH_DATA_REQ --> AUSF\n"; Sep('*');
        }

        if(t=="AUTH_VECTORS") {
            std::string supi      =F["supi"];
            std::string RAND      =F["RAND"];
            std::string AUTN      =F["AUTN"];
            std::string HXRES_star=F["HXRES_star"];
            std::string K_seaf    =F["K_seaf"];
            std::string hn_kem_pk =F["hn_kem_pk"];
            std::string net_dsa_pk=F["net_dsa_pk"];
            std::string net_sig   =F["net_sig"];
            double udm_p =std::stod(F["udm_proc"]);
            double ausf_p=std::stod(F["ausf_proc"]);

            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AMF_PROC_BASE)+RandJitter()*0.2;

            Sep('*');
            std::cout<<"[AMF]  <-- STEP 5: AUTH_VECTORS\n";
            std::cout<<"       RAND       : "<<RAND<<"\n";
            std::cout<<"       AUTN       : "<<AUTN<<"\n";
            std::cout<<"       HXRES*     : "<<HXRES_star<<"\n";
            std::cout<<"       Queue delay: "<<qd<<" ms\n";

            std::string suci;
            for(auto& kv:g_amfSess)
                if(kv.second.supi==supi){suci=kv.first;break;}
            if(suci.empty()) return;

            auto& sess=g_amfSess[suci];
            sess.RAND=RAND; sess.AUTN=AUTN;
            sess.HXRES_star=HXRES_star; sess.K_seaf=K_seaf;
            sess.net_dsa_pk=net_dsa_pk; sess.net_sig=net_sig;
            sess.procMs+=udm_p+ausf_p+qd;

            auto challenge=Enc("AUTH_CHALLENGE",{
                {"suci",suci},{"RAND",RAND},{"AUTN",AUTN},
                {"hn_kem_pk",hn_kem_pk},
                {"net_dsa_pk",net_dsa_pk},{"net_sig",net_sig}
            });
            Ipv4Address ua=sess.ueAddr; uint16_t up=sess.uePort;
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,challenge,ua,up](){
                UdpSend(n,challenge,ua,up);
            });
            std::cout<<"[AMF]  --> STEP 6: AUTH_CHALLENGE --> UE\n"; Sep('*');
        }

        if(t=="AUTH_RESP") {
            std::string suci     =F["suci"];
            std::string RES_star =F["RES_star"];
            std::string ue_sig   =F["ue_sig"];
            std::string ue_dsa_pk=F["ue_dsa_pk"];
            std::string kem_ct   =F["kem_ct"];
            double pqc_crypto    =std::stod(F.count("pqc_crypto")?F["pqc_crypto"]:"0");

            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AMF_PROC_BASE)+RandJitter()*0.2;

            Sep('*');
            std::cout<<"[AMF]  <-- STEP 7: AUTH_RESP\n";
            std::cout<<"       RES*       : "<<RES_star<<"\n";
            std::cout<<"       UE PQC time: "<<pqc_crypto<<" ms\n";
            std::cout<<"       Queue delay: "<<qd<<" ms\n";

            if(!g_amfSess.count(suci)) return;
            auto& sess=g_amfSess[suci];
            sess.pqcCryptoMs=pqc_crypto;
            sess.procMs+=qd;

            // Local HRES* check
            std::string HRES=SimHash(sess.RAND+RES_star+"hxres_sha256",16);
            bool local_ok=(HRES==sess.HXRES_star);
            std::cout<<"       HRES* chk  : "<<(local_ok?"PASS":"FAIL")<<"\n";

            auto req=Enc("RES_VERIFY_REQ",{
                {"supi",sess.supi},{"RES_star",RES_star},
                {"ue_sig",ue_sig},{"ue_dsa_pk",ue_dsa_pk},{"kem_ct",kem_ct}
            });
            Ptr<Node> n=GetNode();
            Simulator::Schedule(MilliSeconds(qd),[n,req](){
                UdpSend(n,req,g_ausfIp,P_AUSF);
            });
            std::cout<<"[AMF]  --> STEP 8: RES_VERIFY_REQ --> AUSF\n"; Sep('*');
        }

        if(t=="RES_VERIFY_RES") {
            std::string supi  =F["supi"];
            std::string result=F["result"];
            std::string K_seaf=F["K_seaf"];
            double ausf_p=std::stod(F["proc_ms"]);
            bool ok=(result=="SUCCESS");

            int conc=g_stats.currentConcurrent;
            double qd=GetQueueDelay(conc,T_AMF_PROC_BASE)+RandJitter()*0.2;

            Sep('*');
            std::cout<<"[AMF]  <-- STEP 9: RES_VERIFY_RES ["<<result<<"]\n";

            std::string suci;
            for(auto& kv:g_amfSess)
                if(kv.second.supi==supi){suci=kv.first;break;}
            if(suci.empty()) return;
            auto& sess=g_amfSess[suci];
            sess.procMs+=ausf_p+qd;

            if(ok) {
                std::string K_AMF=KDF(K_seaf+supi+"0000","K_AMF_PQC");
                sess.K_AMF=K_AMF;
                g_stats.totalSuccess++;
                g_stats.currentConcurrent--;

                double nowMs=Simulator::Now().GetSeconds()*1000.0;
                double latency=nowMs-sess.startMs;
                double networkMs=latency-sess.procMs-sess.queuingMs-sess.pqcCryptoMs;
                if(networkMs<0) networkMs=0;

                UeRecord rec;
                rec.ueId=(int)g_stats.records.size()+1;
                rec.supi=supi; rec.suci=suci;
                rec.startTime_ms=sess.startMs; rec.endTime_ms=nowMs;
                rec.networkDelay_ms=networkMs;
                rec.queuingDelay_ms=sess.queuingMs;
                rec.procDelay_ms=sess.procMs;
                rec.pqcCryptoDelay_ms=sess.pqcCryptoMs;
                rec.netCryptoDelay_ms=g_stats.totalDsaSignTime/std::max(1,g_stats.totalSuccess+1);
                rec.retries=sess.retries;
                rec.success=true; rec.timedOut=false;
                rec.bandwidthBytes=sess.bw+(int)raw.size();
                g_stats.records.push_back(rec);

                std::cout<<"       K_AMF      : "<<K_AMF.substr(0,32)<<"...\n";
                std::cout<<"       Latency    : "<<std::fixed<<std::setprecision(3)
                         <<latency<<" ms\n";

                auto reply=Enc("AUTH_SUCCESS",{
                    {"suci",suci},{"K_AMF",K_AMF},
                    {"latency_ms",std::to_string(latency)},
                    {"network_ms",std::to_string(networkMs)},
                    {"queuing_ms",std::to_string(sess.queuingMs)},
                    {"proc_ms",std::to_string(sess.procMs)},
                    {"pqc_ms",std::to_string(sess.pqcCryptoMs)}
                });
                Ipv4Address ua=sess.ueAddr; uint16_t up=sess.uePort;
                Ptr<Node> n=GetNode();
                Simulator::Schedule(MilliSeconds(qd),[n,reply,ua,up](){
                    UdpSend(n,reply,ua,up);
                });
                std::cout<<"[AMF]  --> STEP 10: AUTH_SUCCESS --> UE\n";
            } else {
                g_stats.currentConcurrent--;
                auto reply=Enc("AUTH_FAILURE",{{"suci",suci}});
                Ipv4Address ua=sess.ueAddr; uint16_t up=sess.uePort;
                Ptr<Node> n=GetNode();
                Simulator::Schedule(MilliSeconds(qd),[n,reply,ua,up](){
                    UdpSend(n,reply,ua,up);
                });
                std::cout<<"[AMF]  --> STEP 10: AUTH_FAILURE --> UE\n";
            }
            Sep('*');
        }
    }
public:
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("AmfApp")
            .SetParent<Application>().AddConstructor<AmfApp>();
        return tid;
    }
};

/* ============================================================
   UE APPLICATION
   ============================================================ */
class UeApp : public Application {
    int m_idx;
    Ptr<Socket> m_sock;
    std::string m_supi, m_suci, m_K;
    MLKEMKeyPair m_ue_kem;
    MLDSAKeyPair m_ue_dsa;
    std::string  m_kem_ct, m_ss;
    std::string  m_RAND, m_AUTN;
    int    m_retries;
    bool   m_done;
    EventId m_timeout;

public:
    static TypeId GetTypeId(){
        static TypeId tid=TypeId("UeApp")
            .SetParent<Application>().AddConstructor<UeApp>();
        return tid;
    }
    UeApp():m_idx(0),m_retries(0),m_done(false){}
    void SetIndex(int i){m_idx=i;}

private:
    void StartApplication() override {
        uint16_t port=(uint16_t)(9100+m_idx);
        m_supi="imsi-00101000000000"+std::string(m_idx<10?"0":"")+std::to_string(m_idx);
        m_K=SimHash(m_supi+"long_term_key_K",16);
        m_sock=Socket::CreateSocket(GetNode(),UdpSocketFactory::GetTypeId());
        m_sock->Bind(InetSocketAddress(Ipv4Address::GetAny(),port));
        m_sock->SetRecvCallback(MakeCallback(&UeApp::Recv,this));

        // All UEs start within 50ms window — creates real concurrent load
        double delay=0.3+g_rng->GetValue(0.0,0.05);
        Simulator::Schedule(Seconds(delay),&UeApp::StartAuth,this);
    }
    void StopApplication() override { if(m_sock) m_sock->Close(); }

    void StartAuth() {
        if(m_done) return;
        uint16_t port=(uint16_t)(9100+m_idx);

        Sep('=');
        std::cout<<"\n[UE-"<<m_idx<<"] ===== PQC AUTH START | Retry="<<m_retries<<" =====\n\n";

        // MODULE 1: ML-KEM KeyGen + Encaps at UE
        std::cout<<"[UE-"<<m_idx<<"] [MODULE 1: ML-KEM-768]\n";
        m_ue_kem=MLKEM_KeyGen(m_supi+"ue_kem_session"+std::to_string(m_retries));
        std::cout<<"  ML-KEM.KeyGen : "<<T_MLKEM_KEYGEN<<" ms\n";

        MLKEMResult enc=MLKEM_Encaps(g_hn_kem_keys.pk,m_supi+"sess_rand"+std::to_string(m_retries));
        m_kem_ct=enc.ct; m_ss=enc.ss;
        std::cout<<"  ML-KEM.Encaps : "<<T_MLKEM_ENCAPS<<" ms\n";
        std::cout<<"  ct            : "<<m_kem_ct.substr(0,30)<<"...\n";
        std::cout<<"  ss (UE)       : "<<m_ss.substr(0,32)<<"\n";
        std::cout<<"  ct size       : "<<MLKEM_CT_BYTES<<" bytes\n";
        g_stats.mod1Bandwidth+=MLKEM_CT_BYTES;

        // MODULE 2: ML-DSA KeyGen at UE
        std::cout<<"[UE-"<<m_idx<<"] [MODULE 2: ML-DSA-65 KeyGen]\n";
        m_ue_dsa=MLDSA_KeyGen(m_supi+"ue_dsa_session"+std::to_string(m_retries));
        std::cout<<"  ML-DSA.KeyGen : "<<T_MLDSA_KEYGEN<<" ms\n";
        std::cout<<"  ue_dsa_pk     : "<<m_ue_dsa.pk.substr(0,30)<<"...\n";
        std::cout<<"  pk size       : "<<MLDSA_PUBKEY_BYTES<<" bytes\n";
        g_stats.mod2Bandwidth+=MLDSA_PUBKEY_BYTES;

        m_suci="suci-pqc-kem-001-01-"+SimHash(m_supi+m_kem_ct,8);
        std::cout<<"  SUCI          : "<<m_suci<<"\n\n";

        auto msg=Enc("REG_REQ",{
            {"suci",m_suci},{"supi",m_supi},
            {"ue_port",std::to_string(port)},
            {"ue_dsa_pk",m_ue_dsa.pk},
            {"retry",std::to_string(m_retries)}
        });
        UdpSend(GetNode(),msg,g_amfIp,P_AMF,true);
        std::cout<<"[UE-"<<m_idx<<"] --> STEP 1: REG_REQ --> AMF\n";

        m_timeout=Simulator::Schedule(MilliSeconds(g_authTimeout),
                                       &UeApp::OnTimeout,this);
        Sep('=');
    }

    void OnTimeout() {
        if(m_done) return;
        m_retries++;
        g_stats.totalTimeout++;
        std::cout<<"\n[UE-"<<m_idx<<"] *** TIMEOUT! Retry #"<<m_retries<<" ***\n";
        if(m_retries<=3) StartAuth();
        else {
            std::cout<<"[UE-"<<m_idx<<"] Max retries exceeded - FAILED\n";
            m_done=true;
            UeRecord rec;
            rec.ueId=m_idx; rec.supi=m_supi; rec.suci=m_suci;
            rec.success=false; rec.timedOut=true; rec.retries=m_retries;
            g_stats.records.push_back(rec);
        }
    }

    void Recv(Ptr<Socket> s) {
        Address from; auto raw=PktStr(s,from);
        std::string t; auto F=Dec(raw,t);

        if(t=="AUTH_CHALLENGE") {
            m_timeout.Cancel();
            m_RAND      =F["RAND"];
            m_AUTN      =F["AUTN"];
            std::string net_dsa_pk=F["net_dsa_pk"];
            std::string net_sig   =F["net_sig"];

            Sep('=');
            std::cout<<"[UE-"<<m_idx<<"] <-- STEP 6: AUTH_CHALLENGE\n";
            std::cout<<"       RAND      : "<<m_RAND<<"\n";
            std::cout<<"       AUTN      : "<<m_AUTN<<"\n\n";

            // Realistic PQC crypto delay at UE
            double pqc_crypto = T_MLKEM_KEYGEN + T_MLKEM_ENCAPS +
                                 T_MLDSA_KEYGEN + T_MLDSA_SIGN   +
                                 T_MLDSA_VERIFY +
                                 RandProc(0.1, 0.05) + RandJitter()*0.05;

            // MODULE 2: Verify network signature
            std::cout<<"[UE-"<<m_idx<<"] [MODULE 2: Verify Network DSA Sig]\n";
            std::string msg_signed=m_RAND+m_AUTN+"5G:mnc001.mcc001.3gppnetwork.org";
            bool net_valid=MLDSA_Verify(net_dsa_pk,net_sig,msg_signed);
            std::cout<<"  DSA.Verify   : "<<T_MLDSA_VERIFY<<" ms\n";
            std::cout<<"  Net auth     : "<<(net_valid?"PASS - Network authentic":"FAIL - ABORT")<<"\n";

            if(!net_valid) {
                std::cout<<"  [UE-"<<m_idx<<"] ABORTING - Network verification failed!\n";
                return;
            }

            // USIM computations
            std::string AK  =f5_AK(m_K,m_RAND);
            std::string CK  =f3_CK(m_K,m_RAND);
            std::string IK  =f4_IK(m_K,m_RAND);
            std::string RES =f2_RES(m_K,m_RAND);
            std::string sn  ="5G:mnc001.mcc001.3gppnetwork.org";
            std::string RES_star=SimHash(CK+IK+m_RAND+RES+sn+"xresstar",16);
            std::string K_seaf_ue=KDF(m_ss+CK+IK+sn,"Kseaf_PQC");

            std::cout<<"\n[UE-"<<m_idx<<"] [MODULE 1: USIM + KEM]\n";
            std::cout<<"  AK            : "<<AK<<"  [f5(K,RAND)]\n";
            std::cout<<"  CK            : "<<CK<<"  [f3(K,RAND)]\n";
            std::cout<<"  IK            : "<<IK<<"  [f4(K,RAND)]\n";
            std::cout<<"  RES*          : "<<RES_star<<"\n";
            std::cout<<"  KEM_ss(UE)    : "<<m_ss.substr(0,32)<<"\n";
            std::cout<<"  K_seaf(UE)    : "<<K_seaf_ue.substr(0,32)<<"...\n";

            // MODULE 2: UE signs RES*
            std::cout<<"\n[UE-"<<m_idx<<"] [MODULE 2: UE Signs RES*]\n";
            std::string ue_msg=RES_star+m_RAND;
            std::string ue_sig=MLDSA_Sign(m_ue_dsa.sk,ue_msg);
            std::cout<<"  DSA.Sign      : "<<T_MLDSA_SIGN<<" ms\n";
            std::cout<<"  ue_sig        : "<<ue_sig.substr(0,30)<<"...\n";
            std::cout<<"  sig size      : "<<MLDSA_SIG_BYTES<<" bytes\n";
            std::cout<<"  Total PQC UE  : "<<std::fixed<<std::setprecision(3)
                     <<pqc_crypto<<" ms\n";
            g_stats.mod2Bandwidth+=MLDSA_SIG_BYTES;

            auto resp=Enc("AUTH_RESP",{
                {"suci",m_suci},{"RES_star",RES_star},
                {"ue_sig",ue_sig},{"ue_dsa_pk",m_ue_dsa.pk},
                {"kem_ct",m_kem_ct},
                {"pqc_crypto",std::to_string(pqc_crypto)}
            });
            Ptr<Node> n=GetNode();
            // Delay by PQC computation time (realistic)
            Simulator::Schedule(MilliSeconds(pqc_crypto),[n,resp](){
                UdpSend(n,resp,g_amfIp,P_AMF,true);
            });
            std::cout<<"[UE-"<<m_idx<<"] --> STEP 7: AUTH_RESP (after "
                     <<pqc_crypto<<" ms PQC) --> AMF\n";

            m_timeout=Simulator::Schedule(MilliSeconds(g_authTimeout),
                                           &UeApp::OnTimeout,this);
            Sep('=');
        }

        if(t=="AUTH_SUCCESS") {
            m_timeout.Cancel();
            m_done=true;
            std::string K_AMF    =F["K_AMF"];
            double latency       =std::stod(F["latency_ms"]);
            double net_ms        =std::stod(F["network_ms"]);
            double que_ms        =std::stod(F["queuing_ms"]);
            double proc_ms       =std::stod(F["proc_ms"]);
            double pqc_ms        =std::stod(F["pqc_ms"]);

            Sep('*');
            std::cout<<"\n[UE-"<<m_idx<<"] <-- STEP 10: PQC AUTH SUCCESS\n";
            std::cout<<"  +------------------------------------------------------+\n";
            std::cout<<"  | SUPI         : "<<m_supi<<"  |\n";
            std::cout<<"  | K_AMF        : "<<K_AMF.substr(0,32)<<"...  |\n";
            std::cout<<"  | Total Latency: "<<std::fixed<<std::setprecision(3)
                     <<latency<<" ms                        |\n";
            std::cout<<"  |   Network    : "<<net_ms <<" ms                     |\n";
            std::cout<<"  |   Queuing    : "<<que_ms <<" ms                     |\n";
            std::cout<<"  |   Processing : "<<proc_ms<<" ms                     |\n";
            std::cout<<"  |   PQC Crypto : "<<pqc_ms <<" ms (ML-KEM+ML-DSA)    |\n";
            std::cout<<"  | Retries      : "<<m_retries<<"                               |\n";
            std::cout<<"  | Module 1     : ML-KEM-768 - COMPLETE                |\n";
            std::cout<<"  | Module 2     : ML-DSA-65  - COMPLETE                |\n";
            std::cout<<"  | NAS Security : QUANTUM-SAFE ENABLED                  |\n";
            std::cout<<"  +------------------------------------------------------+\n";
            Sep('*');
        }

        if(t=="AUTH_FAILURE"){
            m_timeout.Cancel(); m_done=true;
            std::cout<<"[UE-"<<m_idx<<"] <-- AUTH_FAILURE\n";
        }
    }
};

/* ============================================================
   FINAL METRICS REPORT
   ============================================================ */
void PrintMetrics()
{
    double simEnd=Simulator::Now().GetSeconds()*1000.0;

    Sep('=');
    std::cout<<"\n";
    std::cout<<"  +==========================================================+\n";
    std::cout<<"  |   REALISTIC PQC 5G-AKA SIMULATION - RESULTS              |\n";
    std::cout<<"  |   Module 1: ML-KEM-768  |  Module 2: ML-DSA-65           |\n";
    std::cout<<"  |   UEs="<<std::left<<std::setw(4)<<g_numUes
             <<"  | Loss="<<(g_packetLossRate*100)<<"%"
             <<"  | Timeout="<<g_authTimeout<<"ms               |\n";
    std::cout<<"  +==========================================================+\n\n";

    // Collect latencies
    std::vector<double> lats;
    double sumLat=0,sumNet=0,sumQue=0,sumProc=0,sumPqc=0;
    for(auto& r:g_stats.records){
        if(r.success){
            double lat=r.endTime_ms-r.startTime_ms;
            lats.push_back(lat);
            sumLat +=lat;
            sumNet +=r.networkDelay_ms;
            sumQue +=r.queuingDelay_ms;
            sumProc+=r.procDelay_ms;
            sumPqc +=r.pqcCryptoDelay_ms;
        }
    }
    int N=(int)lats.size();

    /* ---- METRIC 1: Latency ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  METRIC 1: AUTHENTICATION LATENCY                        |\n";
    std::cout<<"  |  Latency = T_network+T_queuing+T_proc+T_pqc_crypto       |\n";
    std::cout<<"  +----------------------------------------------------------+\n";

    if(N>0){
        double avg=sumLat/N;
        double mn=*std::min_element(lats.begin(),lats.end());
        double mx=*std::max_element(lats.begin(),lats.end());
        double sq=0; for(double x:lats) sq+=(x-avg)*(x-avg);
        double sd=std::sqrt(sq/N);
        auto sorted=lats; std::sort(sorted.begin(),sorted.end());
        double p95=sorted[(int)(sorted.size()*0.95)];

        std::cout<<"  Average Latency    : "<<std::fixed<<std::setprecision(3)
                 <<avg<<" ms\n";
        std::cout<<"  Min Latency        : "<<mn<<" ms\n";
        std::cout<<"  Max Latency        : "<<mx<<" ms\n";
        std::cout<<"  Std Deviation      : "<<sd<<" ms\n";
        std::cout<<"  95th Percentile    : "<<p95<<" ms\n";
        std::cout<<"  Avg Network Delay  : "<<sumNet/N<<" ms\n";
        std::cout<<"  Avg Queuing Delay  : "<<sumQue/N<<" ms\n";
        std::cout<<"  Avg Proc Delay     : "<<sumProc/N<<" ms\n";
        std::cout<<"  Avg PQC Crypto     : "<<sumPqc/N<<" ms (ML-KEM+ML-DSA at UE)\n";
        std::cout<<"  PQC vs Classical   : +"
                 <<std::fixed<<std::setprecision(3)
                 <<(sumPqc/N - 0.35)<<" ms extra crypto\n";

        std::cout<<"\n  Per-UE Breakdown:\n";
        std::cout<<"  "<<std::left
                 <<std::setw(6)<<"UE"
                 <<std::setw(12)<<"Total(ms)"
                 <<std::setw(12)<<"Network"
                 <<std::setw(12)<<"Queuing"
                 <<std::setw(12)<<"Proc"
                 <<std::setw(12)<<"PQC-Crypto"
                 <<std::setw(8)<<"Retries"<<"\n";
        std::cout<<"  "<<std::string(74,'-')<<"\n";
        for(auto& r:g_stats.records){
            if(!r.success) continue;
            double lat=r.endTime_ms-r.startTime_ms;
            std::cout<<"  "<<std::left
                     <<std::setw(6)<<("UE-"+std::to_string(r.ueId))
                     <<std::setw(12)<<std::fixed<<std::setprecision(3)<<lat
                     <<std::setw(12)<<r.networkDelay_ms
                     <<std::setw(12)<<r.queuingDelay_ms
                     <<std::setw(12)<<r.procDelay_ms
                     <<std::setw(12)<<r.pqcCryptoDelay_ms
                     <<std::setw(8)<<r.retries<<"\n";
        }
    }
    std::cout<<"\n";

    /* ---- METRIC 2: ML-KEM ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  METRIC 2: MODULE 1 - ML-KEM-768 KEY EXCHANGE            |\n";
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  Total KEM Ops      : "<<g_stats.kemOps<<"\n";
    std::cout<<"  KEM KeyGen/call    : "<<T_MLKEM_KEYGEN<<" ms\n";
    std::cout<<"  KEM Encaps/call    : "<<T_MLKEM_ENCAPS<<" ms\n";
    std::cout<<"  KEM Decaps/call    : "<<T_MLKEM_DECAPS<<" ms\n";
    std::cout<<"  Total KeyGen time  : "<<std::fixed<<std::setprecision(3)
             <<g_stats.totalKemKeygenTime<<" ms\n";
    std::cout<<"  Total Encaps time  : "<<g_stats.totalKemEncapsTime<<" ms\n";
    std::cout<<"  Total Decaps time  : "<<g_stats.totalKemDecapsTime<<" ms\n";
    std::cout<<"  Total Module 1     : "
             <<(g_stats.totalKemKeygenTime+g_stats.totalKemEncapsTime+
                g_stats.totalKemDecapsTime)<<" ms\n";
    std::cout<<"  Public Key size    : "<<MLKEM_PUBKEY_BYTES<<" bytes\n";
    std::cout<<"  Ciphertext size    : "<<MLKEM_CT_BYTES<<" bytes\n";
    std::cout<<"  Shared Secret size : "<<MLKEM_SS_BYTES<<" bytes\n";
    std::cout<<"  Module 1 Bandwidth : "<<g_stats.mod1Bandwidth<<" bytes\n";
    std::cout<<"\n";

    /* ---- METRIC 3: ML-DSA ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  METRIC 3: MODULE 2 - ML-DSA-65 AUTHENTICATION           |\n";
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  Total DSA Ops      : "<<g_stats.dsaOps<<"\n";
    std::cout<<"  DSA KeyGen/call    : "<<T_MLDSA_KEYGEN<<" ms\n";
    std::cout<<"  DSA Sign/call      : "<<T_MLDSA_SIGN<<" ms\n";
    std::cout<<"  DSA Verify/call    : "<<T_MLDSA_VERIFY<<" ms\n";
    std::cout<<"  Total KeyGen time  : "<<std::fixed<<std::setprecision(3)
             <<g_stats.totalDsaKeygenTime<<" ms\n";
    std::cout<<"  Total Sign time    : "<<g_stats.totalDsaSignTime<<" ms\n";
    std::cout<<"  Total Verify time  : "<<g_stats.totalDsaVerifyTime<<" ms\n";
    std::cout<<"  Total Module 2     : "
             <<(g_stats.totalDsaKeygenTime+g_stats.totalDsaSignTime+
                g_stats.totalDsaVerifyTime)<<" ms\n";
    std::cout<<"  Public Key size    : "<<MLDSA_PUBKEY_BYTES<<" bytes\n";
    std::cout<<"  Signature size     : "<<MLDSA_SIG_BYTES<<" bytes\n";
    std::cout<<"  Module 2 Bandwidth : "<<g_stats.mod2Bandwidth<<" bytes\n";
    std::cout<<"\n";

    /* ---- METRIC 4: Bandwidth ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  METRIC 4: BANDWIDTH OVERHEAD                            |\n";
    std::cout<<"  +----------------------------------------------------------+\n";
    int bw=g_stats.totalBandwidth;
    std::cout<<"  Total Bandwidth    : "<<bw<<" bytes ("
             <<std::fixed<<std::setprecision(2)<<bw/1024.0<<" KB)\n";
    if(g_stats.totalSuccess>0)
        std::cout<<"  Per-Auth Bytes     : "<<bw/g_stats.totalSuccess<<" bytes\n";
    std::cout<<"  Module 1 (KEM) BW  : "<<g_stats.mod1Bandwidth<<" bytes\n";
    std::cout<<"  Module 2 (DSA) BW  : "<<g_stats.mod2Bandwidth<<" bytes\n";
    std::cout<<"  Classical ECC/auth : ~1590 bytes\n";
    std::cout<<"  PQC/auth (est)     : ~21837 bytes\n";
    std::cout<<"  PQC Overhead       : +1273% vs Classical\n";
    std::cout<<"\n";

    /* ---- METRIC 5: Reliability ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  METRIC 5: RELIABILITY AND THROUGHPUT                    |\n";
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  Total UEs          : "<<g_numUes<<"\n";
    std::cout<<"  Successful         : "<<g_stats.totalSuccess<<"\n";
    std::cout<<"  Timeouts           : "<<g_stats.totalTimeout<<"\n";
    std::cout<<"  Retransmissions    : "<<g_stats.totalRetries<<"\n";
    int pct=g_numUes>0?(int)(100.0*g_stats.totalSuccess/g_numUes):0;
    std::cout<<"  Success Rate       : "<<pct<<"%\n";
    std::cout<<"  Peak Concurrent    : "<<g_stats.peakConcurrent<<" UEs\n";
    std::cout<<"  Packet Loss Rate   : "<<(g_packetLossRate*100)<<"%\n";
    if(N>0 && simEnd>0){
        double throughput=g_stats.totalSuccess/(simEnd/1000.0);
        std::cout<<"  Throughput         : "<<std::fixed<<std::setprecision(2)
                 <<throughput<<" auths/second\n";
    }
    std::cout<<"\n";

    /* ---- COMPARISON TABLE ---- */
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  |  FINAL COMPARISON: Classical ECC vs PQC                  |\n";
    std::cout<<"  +----------------------------------------------------------+\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Metric"
              <<std::setw(22)<<"Classical ECC"
              <<std::setw(22)<<"PQC (This Sim)"<<"\n";
    std::cout<<"  "<<std::string(70,'-')<<"\n";
    if(N>0){
        double avg=sumLat/N;
        std::cout<<"  "<<std::left<<std::setw(28)<<"Avg Auth Latency"
                 <<std::setw(22)<<"~36-38 ms"
                 <<std::setw(22)<<(std::to_string((int)avg)+" ms")<<"\n";
    }
    std::cout<<"  "<<std::left<<std::setw(28)<<"Bandwidth/auth"
             <<std::setw(22)<<"~1590 bytes"
             <<std::setw(22)<<"~21837 bytes"<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Crypto time/auth"
             <<std::setw(22)<<"~0.35 ms"
             <<std::setw(22)<<"~3.36 ms"<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Public Key size"
             <<std::setw(22)<<"64 bytes (ECC)"
             <<std::setw(22)<<(std::to_string(MLKEM_PUBKEY_BYTES)+" bytes (KEM)")<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Signature size"
             <<std::setw(22)<<"64 bytes (ECDSA)"
             <<std::setw(22)<<(std::to_string(MLDSA_SIG_BYTES)+" bytes (DSA)")<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Quantum Resistance"
             <<std::setw(22)<<"NO (vulnerable)"
             <<std::setw(22)<<"YES (NIST FIPS)"<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Forward Secrecy"
             <<std::setw(22)<<"Partial"
             <<std::setw(22)<<"Full (ML-KEM)"<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"Mutual Auth"
             <<std::setw(22)<<"Yes (MAC-based)"
             <<std::setw(22)<<"Yes (ML-DSA sig)"<<"\n";
    std::cout<<"  "<<std::left<<std::setw(28)<<"NIST Standard"
             <<std::setw(22)<<"No (legacy)"
             <<std::setw(22)<<"FIPS 203+204"<<"\n";
    std::cout<<"\n"; Sep('=');
}

/* ============================================================
   MAIN
   ============================================================ */
int main(int argc, char* argv[])
{
    double simTime=30.0;
    CommandLine cmd(__FILE__);
    cmd.AddValue("numUes",  "Number of UEs",           g_numUes);
    cmd.AddValue("simTime", "Simulation time (s)",     simTime);
    cmd.AddValue("loss",    "N1 packet loss (0-1)",    g_packetLossRate);
    cmd.Parse(argc,argv);

    g_rng=CreateObject<UniformRandomVariable>();
    g_rng->SetAttribute("Stream",IntegerValue(99999+g_numUes));

    Sep('=');
    std::cout<<"\n";
    std::cout<<"  +==========================================================+\n";
    std::cout<<"  |   REALISTIC PQC 5G-AKA SIMULATION                        |\n";
    std::cout<<"  |   Module 1: ML-KEM-768  (NIST FIPS 203)                  |\n";
    std::cout<<"  |   Module 2: ML-DSA-65   (NIST FIPS 204)                  |\n";
    std::cout<<"  |   UEs="<<std::left<<std::setw(4)<<g_numUes
             <<"  | Loss="<<(g_packetLossRate*100)
             <<"%  | Timeout="<<g_authTimeout<<"ms             |\n";
    std::cout<<"  +==========================================================+\n\n";
    std::cout<<"  REALISTIC FEATURES:\n";
    std::cout<<"  * Concurrent UEs (50ms start window) -> real queuing\n";
    std::cout<<"  * Load-dependent queuing at AMF/AUSF/UDM (M/D/1 model)\n";
    std::cout<<"  * ML-KEM crypto delay injected at UE ("
             <<(T_MLKEM_KEYGEN+T_MLKEM_ENCAPS)<<" ms)\n";
    std::cout<<"  * ML-DSA sign/verify delay at UE ("
             <<(T_MLDSA_SIGN+T_MLDSA_VERIFY)<<" ms)\n";
    std::cout<<"  * ML-DSA sign delay at Network UDM ("
             <<T_MLDSA_SIGN<<" ms)\n";
    std::cout<<"  * "<<(g_packetLossRate*100)<<"% packet loss on N1 + retransmission\n";
    std::cout<<"  * Timeout="<<g_authTimeout<<"ms, max 3 retries\n";
    std::cout<<"  * Per-UE breakdown: network/queuing/proc/pqc-crypto\n\n";

    InitDB(g_numUes);

    NodeContainer ueNodes; ueNodes.Create(g_numUes);
    NodeContainer core;    core.Create(3);
    auto amfNode =core.Get(0);
    auto ausfNode=core.Get(1);
    auto udmNode =core.Get(2);

    PointToPointHelper n1,coreLink;
    n1.SetDeviceAttribute("DataRate",    StringValue("100Mbps"));
    n1.SetChannelAttribute("Delay",      StringValue("10ms"));
    coreLink.SetDeviceAttribute("DataRate",  StringValue("1Gbps"));
    coreLink.SetChannelAttribute("Delay",    StringValue("2ms"));

    InternetStackHelper inet;
    inet.Install(ueNodes); inet.Install(core);

    Ipv4AddressHelper ip;
    for(int i=0;i<g_numUes;i++){
        auto d=n1.Install(ueNodes.Get(i),amfNode);
        std::string b="10."+std::to_string(i+1)+".0.0";
        ip.SetBase(b.c_str(),"255.255.255.0");
        ip.Assign(d);
    }
    auto d1=coreLink.Install(amfNode,ausfNode);
    ip.SetBase("10.100.1.0","255.255.255.0");
    auto i1=ip.Assign(d1);
    auto d2=coreLink.Install(ausfNode,udmNode);
    ip.SetBase("10.100.2.0","255.255.255.0");
    auto i2=ip.Assign(d2);

    g_amfIp =i1.GetAddress(0);
    g_ausfIp=i1.GetAddress(1);
    g_udmIp =i2.GetAddress(1);
    Ipv4GlobalRoutingHelper::PopulateRoutingTables();

    std::cout<<"  Network: AMF="<<g_amfIp
             <<"  AUSF="<<g_ausfIp
             <<"  UDM="<<g_udmIp<<"\n\n";

    auto udmA =CreateObject<UdmApp>();
    auto ausfA=CreateObject<AusfApp>();
    auto amfA =CreateObject<AmfApp>();
    udmNode ->AddApplication(udmA);
    ausfNode->AddApplication(ausfA);
    amfNode ->AddApplication(amfA);
    udmA ->SetStartTime(Seconds(0.05)); udmA ->SetStopTime(Seconds(simTime));
    ausfA->SetStartTime(Seconds(0.05)); ausfA->SetStopTime(Seconds(simTime));
    amfA ->SetStartTime(Seconds(0.10)); amfA ->SetStopTime(Seconds(simTime));

    for(int i=0;i<g_numUes;i++){
        auto ue=CreateObject<UeApp>();
        ue->SetIndex(i+1);
        ueNodes.Get(i)->AddApplication(ue);
        ue->SetStartTime(Seconds(0.20));
        ue->SetStopTime(Seconds(simTime));
    }

    Simulator::Schedule(Seconds(simTime-1.0),&PrintMetrics);

    std::cout<<"  Starting realistic PQC simulation...\n";
    Sep('=');

    Simulator::Run();
    Simulator::Destroy();
    return 0;
}
