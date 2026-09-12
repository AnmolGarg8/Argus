"""
Argus — Threat Origin Map
3D Geolocation of Flagged Phishing Hosting Infrastructure
Visualizes the physical hosting nodes and inbound attack trajectories
behind messages flagged as BLOCK or FLAG_FOR_REVIEW.
"""

import json
import re
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components

# DEMO DATA — live IP geolocation APIs (e.g. ip-api.com, ipapi.co) require external network calls
# which fail in client-side Pyodide/Stlite browser execution due to sandbox and CORS restrictions.
# This local mock dataset maps representative phishing infrastructure domains to realistic geographic hosting locations.
_MOCK_INFRASTRUCTURE_GEO = {
    "paypa1-security-update.xyz": {
        "city": "Moscow",
        "country": "Russia",
        "lat": 55.7558,
        "lng": 37.6173,
        "isp": "Bulletproof Transit AS4923",
        "asn": "AS4923",
    },
    "micros0ft-online-verify.com": {
        "city": "Bucharest",
        "country": "Romania",
        "lat": 44.4268,
        "lng": 26.1025,
        "isp": "Offshore Cloud SRL",
        "asn": "AS9009",
    },
    "login.micros0ft-online-verify.com": {
        "city": "Bucharest",
        "country": "Romania",
        "lat": 44.4268,
        "lng": 26.1025,
        "isp": "Offshore Cloud SRL",
        "asn": "AS9009",
    },
    "cloud-billing-solutions.info": {
        "city": "Shenzhen",
        "country": "China",
        "lat": 22.5431,
        "lng": 114.0579,
        "isp": "Shenzhen FastNet ISP",
        "asn": "AS4134",
    },
    "vendor-invoice-storage.cloud": {
        "city": "Beijing",
        "country": "China",
        "lat": 39.9042,
        "lng": 116.4074,
        "isp": "China Telecom Dynamic Cloud",
        "asn": "AS4808",
    },
    "acme-internal-support.xyz": {
        "city": "Amsterdam",
        "country": "Netherlands",
        "lat": 52.3676,
        "lng": 4.9041,
        "isp": "HostKey Dedicated B.V.",
        "asn": "AS20000",
    },
    "acme-corp-executive.com": {
        "city": "Frankfurt",
        "country": "Germany",
        "lat": 50.1109,
        "lng": 8.6821,
        "isp": "Equinix Europe Transit",
        "asn": "AS13335",
    },
    "portal-acme-payroll.biz": {
        "city": "Sofia",
        "country": "Bulgaria",
        "lat": 42.6977,
        "lng": 23.3219,
        "isp": "Balkan Host Network",
        "asn": "AS8866",
    },
    "secure-wire-clearing.net": {
        "city": "Lagos",
        "country": "Nigeria",
        "lat": 6.5244,
        "lng": 3.3792,
        "isp": "WestAfrica Fiber Transit",
        "asn": "AS37078",
    },
    "authenticator-sync-mfa.tk": {
        "city": "Kyiv",
        "country": "Ukraine",
        "lat": 50.4501,
        "lng": 30.5234,
        "isp": "EastEuro Stealth VPS",
        "asn": "AS15895",
    },
    "vpn-acme-portal.tk": {
        "city": "Hamburg",
        "country": "Germany",
        "lat": 53.5511,
        "lng": 9.9937,
        "isp": "Hetzner Anonymous Cloud",
        "asn": "AS24940",
    },
    "accounts-google-verify.top": {
        "city": "Taipei",
        "country": "Taiwan",
        "lat": 25.0330,
        "lng": 121.5654,
        "isp": "Formosa Cloud Host",
        "asn": "AS9924",
    },
}

# Fallback pool of realistic international hosting hubs for arbitrary test domains
_FALLBACK_GEO_HUBS = [
    {"city": "Reykjavik", "country": "Iceland", "lat": 64.1466, "lng": -21.9426, "isp": "Nordic Data Hosting AS1982"},
    {"city": "Vilnius", "country": "Lithuania", "lat": 54.6872, "lng": 25.2797, "isp": "Baltic Dedicated Servers AS4821"},
    {"city": "Zurich", "country": "Switzerland", "lat": 47.3769, "lng": 8.5417, "isp": "Alpine Colocation AG AS1283"},
    {"city": "Panama City", "country": "Panama", "lat": 8.9824, "lng": -79.5199, "isp": "Offshore Privacy Hosting AS512"},
    {"city": "Kuala Lumpur", "country": "Malaysia", "lat": 3.1390, "lng": 101.6869, "isp": "ASEAN Fiber Transit AS4788"},
    {"city": "Warsaw", "country": "Poland", "lat": 52.2297, "lng": 21.0122, "isp": "PolHost VPS Solutions AS192"},
    {"city": "Nicosia", "country": "Cyprus", "lat": 35.1856, "lng": 33.3823, "isp": "Levant Offshore Cloud AS844"},
    {"city": "Almaty", "country": "Kazakhstan", "lat": 43.2220, "lng": 76.8512, "isp": "Central Eurasia Telecom AS912"},
]

# Protected corporate enterprise headquarters coordinates (Acme Corp HQ)
PROTECTED_TENANT_HQ = {
    "name": "ACME CORP HQ (PROTECTED TENANT)",
    "city": "New York",
    "country": "United States",
    "lat": 40.7128,
    "lng": -74.0060,
}


def extract_domain(text: str) -> str:
    """Extract canonical domain name from URL or email address."""
    if not text:
        return ""
    text = str(text).strip()
    if "@" in text:
        text = text.split("@")[-1]
    if "://" in text:
        text = text.split("://")[-1]
    text = text.split("/")[0].split(":")[0].strip().lower()
    return text


def get_domain_geolocation(domain_or_url: str) -> dict:
    """
    Map domain to geographic hosting location using local mock dataset.
    Deterministic fallback assigns consistent coordinates to arbitrary domains.
    Zero external network calls required.
    """
    domain = extract_domain(domain_or_url)
    if not domain:
        domain = "unknown-infrastructure.net"

    if domain in _MOCK_INFRASTRUCTURE_GEO:
        geo = dict(_MOCK_INFRASTRUCTURE_GEO[domain])
        geo["domain"] = domain
        return geo

    # Check substring match against known domain keys
    for k, v in _MOCK_INFRASTRUCTURE_GEO.items():
        if k in domain or domain in k:
            geo = dict(v)
            geo["domain"] = domain
            return geo

    # Deterministic fallback hashing for arbitrary domains
    hash_val = sum(ord(c) * (i + 1) for i, c in enumerate(domain))
    hub = _FALLBACK_GEO_HUBS[hash_val % len(_FALLBACK_GEO_HUBS)]
    return {
        "domain": domain,
        "city": hub["city"],
        "country": hub["country"],
        "lat": hub["lat"],
        "lng": hub["lng"],
        "isp": hub["isp"],
        "asn": f"AS{10000 + (hash_val % 50000)}",
    }


def extract_flagged_threat_origins(df_events: pd.DataFrame, custom_test_result: dict = None) -> list[dict]:
    """
    Extract threat origin records from active session events flagged as BLOCK or FLAG_FOR_REVIEW,
    including any active custom test result.
    """
    threats = []
    seen_keys = set()

    # 1. Custom test result if currently flagged
    if custom_test_result and isinstance(custom_test_result, dict):
        v = custom_test_result.get("verdict", "")
        if v in ["BLOCK", "FLAG_FOR_REVIEW"]:
            domain_cand = ""
            details = custom_test_result.get("details", {})
            dom_detail = details.get("domain", {})
            if isinstance(dom_detail, dict):
                domain_cand = dom_detail.get("domain", "")
            if not domain_cand:
                expl = custom_test_result.get("explanation", "")
                m = re.search(r"'(paypa1[^']+|micros0ft[^']+|[a-zA-Z0-9\.\-]+\.[a-z]{2,})'", expl)
                if m:
                    domain_cand = m.group(1)
            if not domain_cand:
                domain_cand = "paypa1-security-update.xyz"

            geo = get_domain_geolocation(domain_cand)
            threats.append({
                "id": "LIVE-INTERACTIVE-TEST",
                "domain": geo["domain"],
                "lat": geo["lat"],
                "lng": geo["lng"],
                "city": geo["city"],
                "country": geo["country"],
                "isp": geo["isp"],
                "verdict": v,
                "score": round(float(custom_test_result.get("composite_score", 95.0)), 1),
                "subject": "Interactive Multi-Layer Test Injection",
                "sender": "Interactive Analyst Console",
                "explanation": custom_test_result.get("explanation", "High-risk indicators triggered across multiple detection engines."),
            })
            seen_keys.add(geo["domain"])

    # 2. Extract flagged items from event stream
    if df_events is not None and not df_events.empty:
        flagged_df = df_events[df_events["verdict"].isin(["BLOCK", "FLAG_FOR_REVIEW"])]
        for _, row in flagged_df.iterrows():
            url_val = str(row.get("url", "")).strip()
            sender_val = str(row.get("sender_id", "")).strip()
            domain_cand = extract_domain(url_val) or extract_domain(sender_val)

            # Skip benign internal domain
            if domain_cand in ["acme-corp.internal", "wiki.acme-corp.internal", "portal.acme-corp.internal", "slack.acme-corp.internal"]:
                continue

            geo = get_domain_geolocation(domain_cand)
            mid = str(row.get("id", "MSG-THREAT"))

            threats.append({
                "id": mid,
                "domain": geo["domain"],
                "lat": geo["lat"],
                "lng": geo["lng"],
                "city": geo["city"],
                "country": geo["country"],
                "isp": geo["isp"],
                "verdict": str(row.get("verdict", "BLOCK")),
                "score": round(float(row.get("risk_score", 85.0)), 1),
                "subject": str(row.get("subject", "Phishing Simulation")),
                "sender": sender_val,
                "explanation": str(row.get("explanation", "Malicious phishing signals detected.")),
            })

    return threats


def render_threat_origin_map(df_events: pd.DataFrame, custom_test_result: dict = None, height: int = 540):
    """
    Renders the 3D Threat Origin Globe using Three.js inside a Streamlit component.
    Displays geographic hosting distribution of all active flagged phishing threats,
    interactive hover telemetry, and inbound attack trajectory arcs.
    """
    threats = extract_flagged_threat_origins(df_events, custom_test_result)
    threats_json = json.dumps(threats)
    hq_json = json.dumps(PROTECTED_TENANT_HQ)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@500;700;800&family=Inter:wght@400;600;700&display=swap" rel="stylesheet">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { 
                background: #000000; 
                overflow: hidden; 
                font-family: 'JetBrains Mono', monospace; 
                color: #FFFFFF;
                user-select: none;
            }
            #globe-container { 
                width: 100vw; 
                height: __HEIGHT__px; 
                position: relative; 
                background: radial-gradient(circle at 50% 50%, #030a16 0%, #000000 85%); 
            }
            
            .hud { 
                position: absolute; 
                pointer-events: none; 
                width: 100%; 
                height: 100%; 
                z-index: 50; 
                padding: 16px 20px; 
            }
            
            .hud-header {
                position: absolute;
                top: 16px;
                left: 20px;
                display: flex;
                flex-direction: column;
                gap: 3px;
            }
            .hud-title {
                font-size: 0.82rem;
                font-weight: 800;
                color: #00D4FF;
                letter-spacing: 2px;
                text-transform: uppercase;
                display: flex;
                align-items: center;
                gap: 8px;
            }
            .hud-subtitle {
                font-size: 0.65rem;
                color: #94A3B8;
                letter-spacing: 1px;
                text-transform: uppercase;
            }

            .intel-card {
                position: absolute;
                top: 16px;
                right: 20px;
                pointer-events: auto;
                width: 330px;
                max-width: 90vw;
                background: rgba(5, 12, 24, 0.88);
                backdrop-filter: blur(8px);
                border: 1px solid rgba(0, 212, 255, 0.35);
                border-left: 3px solid #00D4FF;
                border-radius: 4px;
                padding: 12px 14px;
                font-family: 'Inter', sans-serif;
                box-shadow: 0 10px 25px rgba(0,0,0,0.7);
                transition: all 0.25s ease;
            }
            .intel-card-header {
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.68rem;
                font-weight: 800;
                color: #00D4FF;
                letter-spacing: 1.5px;
                text-transform: uppercase;
                margin-bottom: 6px;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }
            .intel-badge {
                padding: 2px 6px;
                border-radius: 3px;
                font-size: 0.62rem;
                font-weight: 800;
            }
            .badge-block { background: rgba(255, 45, 85, 0.2); color: #FF2D55; border: 1px solid #FF2D55; }
            .badge-flag { background: rgba(245, 158, 11, 0.2); color: #F59E0B; border: 1px solid #F59E0B; }
            .intel-domain {
                font-family: 'JetBrains Mono', monospace;
                font-size: 0.85rem;
                font-weight: 700;
                color: #FFFFFF;
                word-break: break-all;
                margin-bottom: 6px;
            }
            .intel-row {
                font-size: 0.72rem;
                color: #94A3B8;
                margin-bottom: 3px;
                display: flex;
                justify-content: space-between;
            }
            .intel-val {
                color: #E2E8F0;
                font-weight: 600;
                font-family: 'JetBrains Mono', monospace;
            }
            .intel-expl {
                font-size: 0.68rem;
                color: #CBD5E1;
                margin-top: 8px;
                padding-top: 6px;
                border-top: 1px solid rgba(255, 255, 255, 0.1);
                line-height: 1.35;
            }

            .zoom-controls { 
                position: absolute; 
                bottom: 20px; 
                right: 20px; 
                pointer-events: auto; 
                display: flex; 
                flex-direction: column; 
                gap: 6px; 
            }
            .zoom-btn { 
                width: 32px; 
                height: 32px; 
                background: rgba(0, 212, 255, 0.12); 
                border: 1px solid rgba(0, 212, 255, 0.4); 
                color: #00D4FF; 
                font-weight: 800; 
                cursor: pointer; 
                display: flex; 
                align-items: center; 
                justify-content: center;
                border-radius: 4px; 
                font-size: 1.1rem; 
                transition: 0.2s;
                font-family: 'JetBrains Mono', monospace;
            }
            .zoom-btn:hover { 
                background: #00D4FF; 
                color: #000; 
                box-shadow: 0 0 12px rgba(0, 212, 255, 0.6);
            }

            .hud-footer {
                position: absolute;
                bottom: 20px;
                left: 20px;
                display: flex;
                gap: 15px;
                align-items: center;
                font-size: 0.68rem;
                font-family: 'JetBrains Mono', monospace;
            }
            .stat-pill {
                background: rgba(0, 0, 0, 0.75);
                border: 1px solid rgba(255, 255, 255, 0.12);
                border-radius: 3px;
                padding: 4px 10px;
                display: flex;
                align-items: center;
                gap: 6px;
            }
            .dot-red { width: 6px; height: 6px; border-radius: 50%; background: #FF2D55; box-shadow: 0 0 6px #FF2D55; }
            .dot-amber { width: 6px; height: 6px; border-radius: 50%; background: #F59E0B; box-shadow: 0 0 6px #F59E0B; }
            .dot-cyan { width: 6px; height: 6px; border-radius: 50%; background: #00D4FF; box-shadow: 0 0 6px #00D4FF; }
        </style>
    </head>
    <body>
        <div id="globe-container">
            <div class="hud">
                <div class="hud-header">
                    <div class="hud-title">
                        <span style="color:#FF2D55;">●</span> ARGUS // PHISHING INFRASTRUCTURE GEOLOCATION
                    </div>
                    <div class="hud-subtitle">
                        LIVE HOSTING NODES & INBOUND INTERCEPTION TRAJECTORIES
                    </div>
                </div>

                <div class="intel-card" id="intel-panel">
                    <div class="intel-card-header">
                        <span>INFRASTRUCTURE TELEMETRY</span>
                        <span class="intel-badge badge-block" id="card-badge">LIVE MONITOR</span>
                    </div>
                    <div class="intel-domain" id="card-domain">INTERACTIVE GLOBE ACTIVE</div>
                    <div class="intel-row">
                        <span>HOSTING ORIGIN</span>
                        <span class="intel-val" id="card-origin">GLOBAL TELEMETRY</span>
                    </div>
                    <div class="intel-row">
                        <span>HOSTING ISP</span>
                        <span class="intel-val" id="card-isp">MULTI-ASN CLOUD</span>
                    </div>
                    <div class="intel-row">
                        <span>COMPOSITE RISK</span>
                        <span class="intel-val" id="card-risk" style="color:#00D4FF;">INTERCEPTING</span>
                    </div>
                    <div class="intel-expl" id="card-expl">
                        Hover or click any glowing threat pin to inspect hosting telemetry, impersonated domains, and explainable signals.
                    </div>
                </div>

                <div class="hud-footer">
                    <div class="stat-pill">
                        <div class="dot-red"></div>
                        <span>FLAGGED INFRASTRUCTURE: <b id="stat-count">0</b> NODES</span>
                    </div>
                    <div class="stat-pill">
                        <div class="dot-cyan"></div>
                        <span>PROTECTED TENANT: ACME CORP HQ [NYC]</span>
                    </div>
                </div>

                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoom(1)" title="Zoom In">+</button>
                    <button class="zoom-btn" onclick="zoom(-1)" title="Zoom Out">-</button>
                </div>
            </div>
        </div>

        <script>
            const container = document.getElementById('globe-container');
            const threats = __THREATS__;
            const hq = __HQ__;
            const radius = 158;

            let scene, camera, renderer, globeGroup, controls;
            let rotating = true;
            let targetCamPos = null;
            const pins = [];
            const raycaster = new THREE.Raycaster();
            const mouse = new THREE.Vector2();

            document.getElementById('stat-count').innerText = threats.length;

            function init() {
                scene = new THREE.Scene();
                const width = container.clientWidth || window.innerWidth || 1200;
                const height = container.clientHeight || __HEIGHT__;
                
                camera = new THREE.PerspectiveCamera(35, width / height, 1, 3000);
                camera.position.set(0, 80, 560);

                renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
                renderer.setSize(width, height);
                renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 2));
                container.appendChild(renderer.domElement);

                controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
                controls.enablePan = false;
                controls.enableZoom = false; // Prevent page scroll hijack

                globeGroup = new THREE.Group();
                scene.add(globeGroup);

                // Lighting
                scene.add(new THREE.AmbientLight(0xFFFFFF, 0.9));
                const sun = new THREE.DirectionalLight(0x00D4FF, 0.7);
                sun.position.set(5, 3, 5).normalize();
                scene.add(sun);

                createGlobe();
                createStars();
                plotThreatPins();
                plotTrajectories();

                // Mouse interaction for explainable pins
                renderer.domElement.addEventListener('pointermove', onPointerMove, false);
                renderer.domElement.addEventListener('click', onPointerClick, false);
                controls.addEventListener('start', () => { rotating = false; targetCamPos = null; });

                animate();
            }

            function createGlobe() {
                const sphereGeo = new THREE.SphereGeometry(radius, 48, 48);
                
                // Base cyber sphere (dark blue/slate with high specular)
                const baseMat = new THREE.MeshPhongMaterial({
                    color: 0x030B18,
                    emissive: 0x01050C,
                    shininess: 30,
                });
                const baseMesh = new THREE.Mesh(sphereGeo, baseMat);
                globeGroup.add(baseMesh);

                // Neon wireframe overlay for instant cyberpunk aesthetic
                const wireMat = new THREE.MeshBasicMaterial({
                    color: 0x00D4FF,
                    wireframe: true,
                    transparent: true,
                    opacity: 0.18,
                });
                globeGroup.add(new THREE.Mesh(sphereGeo, wireMat));

                // Atmosphere halo glow
                const haloGeo = new THREE.SphereGeometry(radius + 1.5, 48, 48);
                const haloMat = new THREE.MeshBasicMaterial({
                    color: 0x00D4FF,
                    transparent: true,
                    opacity: 0.06,
                });
                globeGroup.add(new THREE.Mesh(haloGeo, haloMat));

                // Asynchronously attempt texture load without blocking
                const loader = new THREE.TextureLoader();
                loader.setCrossOrigin('Anonymous');
                loader.load('https://raw.githubusercontent.com/turban/webgl-earth/master/images/2_no_clouds_4k.jpg', (tex) => {
                    baseMesh.material.map = tex;
                    baseMesh.material.color.setHex(0xFFFFFF);
                    baseMesh.material.needsUpdate = true;
                }, undefined, () => {
                    // Failover gracefully
                    loader.load('https://unpkg.com/three-globe/example/img/earth-blue-marble.jpg', (tex2) => {
                        baseMesh.material.map = tex2;
                        baseMesh.material.color.setHex(0xFFFFFF);
                        baseMesh.material.needsUpdate = true;
                    });
                });
            }

            function createStars() {
                const geo = new THREE.BufferGeometry();
                const pos = new Float32Array(800 * 3);
                for (let i = 0; i < 2400; i++) {
                    pos[i] = (Math.random() - 0.5) * 1600;
                }
                geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
                scene.add(new THREE.Points(geo, new THREE.PointsMaterial({ color: 0x00D4FF, size: 0.8, transparent: true, opacity: 0.4 })));
            }

            function latLonToVector3(lat, lon, R) {
                const phi = (90 - lat) * (Math.PI / 180);
                const theta = (lon + 180) * (Math.PI / 180);
                return new THREE.Vector3(
                    -(R * Math.sin(phi) * Math.cos(theta)),
                    R * Math.cos(phi),
                    R * Math.sin(phi) * Math.sin(theta)
                );
            }

            function plotThreatPins() {
                // 1. Corporate HQ Anchor (NYC)
                const hqPos = latLonToVector3(hq.lat, hq.lng, radius);
                createHqMarker(hqPos);

                // 2. Plot Threat Pins
                threats.forEach((t) => {
                    const pos = latLonToVector3(t.lat, t.lng, radius);
                    const color = t.verdict === 'BLOCK' ? 0xFF2D55 : 0xF59E0B;
                    createThreatPin(pos, color, t);
                });
            }

            function createHqMarker(pos) {
                const group = new THREE.Group();
                const mat = new THREE.MeshBasicMaterial({ color: 0x00D4FF, wireframe: false });
                const head = new THREE.Mesh(new THREE.SphereGeometry(2.5, 16, 16), mat);
                group.add(head);

                const ringGeo = new THREE.RingGeometry(3.5, 4.5, 32);
                const ringMat = new THREE.MeshBasicMaterial({ color: 0x00D4FF, side: THREE.DoubleSide, transparent: true, opacity: 0.8 });
                const ring = new THREE.Mesh(ringGeo, ringMat);
                group.add(ring);

                group.position.copy(pos);
                group.quaternion.setFromUnitVectors(new THREE.Vector3(0, 0, 1), pos.clone().normalize());
                globeGroup.add(group);
            }

            function createThreatPin(pos, colorHex, data) {
                const pinGroup = new THREE.Group();
                const mat = new THREE.MeshPhongMaterial({ 
                    color: colorHex, 
                    emissive: colorHex, 
                    emissiveIntensity: 0.6 
                });

                // Glowing pin head
                const head = new THREE.Mesh(new THREE.SphereGeometry(2.2, 16, 16), mat);
                head.position.y = 5.5;
                pinGroup.add(head);

                // Stem cone pointing to surface
                const cone = new THREE.Mesh(new THREE.ConeGeometry(1.5, 5, 16), mat);
                cone.rotation.x = Math.PI;
                cone.position.y = 2.5;
                pinGroup.add(cone);

                pinGroup.position.copy(pos);
                pinGroup.quaternion.setFromUnitVectors(new THREE.Vector3(0, 1, 0), pos.clone().normalize());
                
                // Attach telemetry data for raycasting
                head.userData = data;
                cone.userData = data;
                pins.push(head);
                pins.push(cone);

                globeGroup.add(pinGroup);
            }

            function plotTrajectories() {
                const hqPos = latLonToVector3(hq.lat, hq.lng, radius);

                threats.forEach((t, idx) => {
                    const startPos = latLonToVector3(t.lat, t.lng, radius);
                    // Elevated mid-point arc
                    const midLat = (t.lat + hq.lat) / 2;
                    const midLng = (t.lng + hq.lng) / 2;
                    const elevation = radius + Math.min(130, Math.max(45, 15 + Math.abs(t.lng - hq.lng) * 0.7));
                    const midPos = latLonToVector3(midLat, midLng, elevation);

                    const curve = new THREE.QuadraticBezierCurve3(startPos, midPos, hqPos);
                    const points = curve.getPoints(40);
                    const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
                    
                    const lineColor = t.verdict === 'BLOCK' ? 0xFF2D55 : 0xF59E0B;
                    const lineMat = new THREE.LineBasicMaterial({
                        color: lineColor,
                        transparent: true,
                        opacity: 0.45,
                    });
                    const line = new THREE.Line(lineGeo, lineMat);
                    globeGroup.add(line);
                });
            }

            function zoom(dir) {
                rotating = false;
                targetCamPos = null;
                const factor = 0.8;
                if (dir > 0) camera.position.multiplyScalar(factor);
                else camera.position.divideScalar(factor);
                
                const dist = camera.position.length();
                if (dist < 190) camera.position.setLength(190);
                if (dist > 1000) camera.position.setLength(1000);
                controls.update();
            }

            function onPointerMove(event) {
                const rect = renderer.domElement.getBoundingClientRect();
                mouse.x = ((event.clientX - rect.left) / rect.width) * 2 - 1;
                mouse.y = -((event.clientY - rect.top) / rect.height) * 2 + 1;
                checkPinIntersection();
            }

            function onPointerClick(event) {
                onPointerMove(event);
            }

            function checkPinIntersection() {
                raycaster.setFromCamera(mouse, camera);
                const intersects = raycaster.intersectObjects(pins);
                if (intersects.length > 0) {
                    const d = intersects[0].object.userData;
                    if (d && d.domain) {
                        rotating = false;
                        updateIntelPanel(d);
                    }
                }
            }

            function updateIntelPanel(d) {
                const badge = document.getElementById('card-badge');
                badge.innerText = d.verdict;
                badge.className = 'intel-badge ' + (d.verdict === 'BLOCK' ? 'badge-block' : 'badge-flag');

                document.getElementById('card-domain').innerText = d.domain;
                document.getElementById('card-origin').innerText = `${d.city}, ${d.country}`;
                document.getElementById('card-isp').innerText = d.isp;
                
                const riskElem = document.getElementById('card-risk');
                riskElem.innerText = `${d.score}/100`;
                riskElem.style.color = d.verdict === 'BLOCK' ? '#FF2D55' : '#F59E0B';

                document.getElementById('card-expl').innerText = d.explanation;
            }

            function animate() {
                requestAnimationFrame(animate);
                if (rotating && globeGroup) {
                    globeGroup.rotation.y += 0.001;
                }
                if (targetCamPos) {
                    camera.position.lerp(targetCamPos, 0.05);
                }
                controls.update();
                renderer.render(scene, camera);
            }

            window.addEventListener('resize', () => {
                const width = container.clientWidth || window.innerWidth;
                const height = container.clientHeight || __HEIGHT__;
                camera.aspect = width / height;
                camera.updateProjectionMatrix();
                renderer.setSize(width, height);
            });

            init();
        </script>
    </body>
    </html>
    """

    final_html = html_template.replace("__HEIGHT__", str(height)).replace("__THREATS__", threats_json).replace("__HQ__", hq_json)
    components.html(final_html, height=height)
