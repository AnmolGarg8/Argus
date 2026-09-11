import streamlit.components.v1 as components
import json

def render_3d_globe(incidents_df, height=550):
    """
    TACTICAL ZOOM GLOBE V11 (FINAL FIX): 
    - Reliable +/- Buttons using Camera Vectors.
    - No Mouse-Wheel Zoom interference.
    - Massive Neon Attack Beams.
    """
    incidents_list = []
    if incidents_df is not None and not incidents_df.empty:
        recent_df = incidents_df.tail(15)
        for idx, row in recent_df.iterrows():
            ip_str = str(row.get('source_ip', '8.8.8.8'))
            incidents_list.append({
                "ip": ip_str,
                "lat": (hash(ip_str)%130 - 65), 
                "lng": (hash(ip_str)%260 - 130),
                "severity": str(row.get('risk_level', 'HIGH'))
            })

    incidents_json = json.dumps(incidents_list)

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        <script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
        <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@800&family=Orbitron:wght@900&display=swap" rel="stylesheet">
        <style>
            * { box-sizing: border-box; margin: 0; padding: 0; }
            body { background: #000; overflow: hidden; font-family: 'JetBrains Mono', monospace; }
            #scene-container { width: 100vw; height: __HEIGHT__px; position: relative; background: #000; }
            
            .hud { position: absolute; pointer-events: none; width: 100%; height: 100%; z-index: 100; padding: 25px; }
            .brand { top: 20px; left: 25px; position: absolute; font-family: 'Orbitron'; font-size: 0.9rem; letter-spacing: 4px; color: #00f0ff; }
            
            .zoom-controls { 
                position: absolute; bottom: 80px; right: 25px; 
                pointer-events: auto; display: flex; flex-direction: column; gap: 8px; 
            }
            .zoom-btn { 
                width: 40px; height: 40px; background: rgba(0, 212, 255, 0.15); 
                border: 2px solid #00f0ff; color: #00f0ff; font-weight: 900; 
                cursor: pointer; display: flex; align-items: center; justify-content: center;
                border-radius: 4px; font-size: 1.2rem; transition: 0.2s;
            }
            .zoom-btn:hover { background: #00f0ff; color: #000; }

            .recon-panel { 
                top: 20px; right: 25px; position: absolute; 
                pointer-events: auto; background: rgba(0, 10, 25, 0.9); border: 2px solid #00f0ff55;
                padding: 15px; width: 250px; border-radius: 4px; border-left: 3px solid #00f0ff;
            }
            input { background: #000; border: 1px solid #00f0ff44; color: #fff; font-size: 0.75rem; width: 100%; padding: 8px; margin-bottom: 8px; outline: none; }
            button.main-btn { width: 100%; background: #00f0ff; color: #000; border: none; padding: 10px; font-weight: 900; cursor: pointer; font-size: 0.7rem; }
            #intel { font-size: 0.6rem; color: #00ffcc; margin-top: 10px; border-top: 1px solid #00f0ff22; padding-top: 10px; line-height: 1.4; display: none; }
        </style>
    </head>
    <body>
        <div id="scene-container">
            <div class="hud">
                <div class="brand">AIRAVAT // <span style="opacity:0.6; color:#fff;">TACTICAL_V11</span></div>
                <div class="recon-panel">
                    <input type="text" id="target-ip" placeholder="INPUT://TARGET_IP">
                    <button class="main-btn" onclick="runTrace()">EXEC_RECON_LOCK</button>
                    <div id="intel"></div>
                </div>
                <div class="zoom-controls">
                    <button class="zoom-btn" onclick="zoom(1)">+</button>
                    <button class="zoom-btn" onclick="zoom(-1)">-</button>
                </div>
            </div>
        </div>

        <script>
            let scene, camera, renderer, globeGroup, clouds, controls;
            let rotating = true, targetCamPos = null;
            const container = document.getElementById('scene-container');
            const incidents = __INCIDENTS__;
            const radius = 158;

            function init() {
                scene = new THREE.Scene();
                camera = new THREE.PerspectiveCamera(35, container.clientWidth / container.clientHeight, 1, 3000);
                camera.position.z = 600;

                renderer = new THREE.WebGLRenderer({ antialias: true, alpha: true });
                renderer.setSize(container.clientWidth, container.clientHeight);
                renderer.setPixelRatio(window.devicePixelRatio);
                container.appendChild(renderer.domElement);

                controls = new THREE.OrbitControls(camera, renderer.domElement);
                controls.enableDamping = true;
                controls.dampingFactor = 0.05;
                controls.enablePan = false;
                controls.enableZoom = false; // Disable mouse wheel to prevent page scroll zoom

                globeGroup = new THREE.Group();
                scene.add(globeGroup);

                scene.add(new THREE.AmbientLight(0xffffff, 1.0)); // Ultra bright as requested
                const sun = new THREE.DirectionalLight(0xffffff, 0.8);
                sun.position.set(5, 3, 5).normalize();
                scene.add(sun);

                createGlobe();
                createStars();
                drawBigVisuals();
                animate();
                
                controls.addEventListener('start', () => { rotating = false; targetCamPos = null; });
            }

            function createGlobe() {
                const loader = new THREE.TextureLoader();
                loader.setCrossOrigin('Anonymous');
                loader.load('https://raw.githubusercontent.com/turban/webgl-earth/master/images/2_no_clouds_4k.jpg', (tex) => {
                    const mat = new THREE.MeshPhongMaterial({ map: tex, shininess: 15 });
                    globeGroup.add(new THREE.Mesh(new THREE.SphereGeometry(radius, 64, 64), mat));
                    loader.load('https://unpkg.com/three-globe/example/img/earth-clouds.png', (cloudTex) => {
                        clouds = new THREE.Mesh(
                            new THREE.SphereGeometry(radius + 2, 64, 64),
                            new THREE.MeshLambertMaterial({ map: cloudTex, transparent: true, opacity: 0.15, blending: THREE.AdditiveBlending })
                        );
                        globeGroup.add(clouds);
                    });
                });
            }

            function createStars() {
                const geo = new THREE.BufferGeometry();
                const pos = new Float32Array(1000 * 3);
                for(let i=0; i<3000; i++) pos[i] = (Math.random() - 0.5) * 1800;
                geo.setAttribute('position', new THREE.BufferAttribute(pos, 3));
                scene.add(new THREE.Points(geo, new THREE.PointsMaterial({ color: 0xffffff, size: 0.8 })));
            }

            function drawBigVisuals() {
                incidents.forEach((inc, idx) => {
                    const startPos = latLonToVector3(inc.lat, inc.lng, radius);
                    createProPin(startPos, inc.severity === 'CRITICAL' ? 0xff0044 : 0x00d4ff);
                    if(idx % 2 === 0) {
                        const midPos = latLonToVector3((inc.lat+28)/2, (inc.lng+77)/2, radius + 140);
                        const endPos = latLonToVector3(28, 77, radius);
                        const curve = new THREE.QuadraticBezierCurve3(startPos, midPos, endPos);
                        const points = curve.getPoints(50);
                        const line = new THREE.Line(new THREE.BufferGeometry().setFromPoints(points), new THREE.LineBasicMaterial({
                            color: inc.severity === 'CRITICAL' ? 0xff3344 : 0x00f0ff,
                            transparent: true, opacity: 0.6
                        }));
                        globeGroup.add(line);
                    }
                });
            }

            function createProPin(pos, color) {
                const pin = new THREE.Group();
                const mat = new THREE.MeshPhongMaterial({ color: color, emissive: color, emissiveIntensity: 0.5 });
                const head = new THREE.Mesh(new THREE.SphereGeometry(1.8, 16, 16), mat);
                head.position.y = 5; pin.add(head);
                const cone = new THREE.Mesh(new THREE.ConeGeometry(1.4, 4, 16), mat);
                cone.rotation.x = Math.PI; cone.position.y = 2; pin.add(cone);
                pin.position.copy(pos);
                pin.quaternion.setFromUnitVectors(new THREE.Vector3(0,1,0), pos.clone().normalize());
                globeGroup.add(pin);
            }

            function zoom(dir) {
                rotating = false;
                targetCamPos = null;
                const factor = 0.8;
                if (dir > 0) camera.position.multiplyScalar(factor);
                else camera.position.divideScalar(factor);
                
                const dist = camera.position.length();
                if(dist < 185) camera.position.setLength(185);
                if(dist > 1100) camera.position.setLength(1100);
                controls.update();
            }

            async function runTrace() {
                const ip = document.getElementById('target-ip').value;
                const intel = document.getElementById('intel');
                if(!ip) return;
                intel.style.display = 'block';
                intel.innerHTML = '> ESTABLISHING_SAT_LINK...<br>> LOCKING_COORDINATES...';
                try {
                    const res = await fetch('https://ipapi.co/' + ip + '/json/');
                    const data = await res.json();
                    if(data.latitude) {
                        setTimeout(() => {
                            intel.innerHTML = `TARGET: ${data.city}<br>ISP: ${data.org || 'UNK'}<br>LOC: [${data.latitude}, ${data.longitude}]`;
                            const pos = latLonToVector3(data.latitude, data.longitude, radius);
                            createProPin(pos, 0xff0044);
                            globeGroup.updateMatrixWorld();
                            const worldTarget = pos.clone().applyMatrix4(globeGroup.matrixWorld);
                            targetCamPos = worldTarget.normalize().multiplyScalar(radius + 120);
                            rotating = false;
                        }, 800);
                    } else { intel.innerText = 'TRACE_ERROR'; }
                } catch(e) { intel.innerText = 'LINK_LOST'; }
            }

            function latLonToVector3(lat, lon, R) {
                const phi = (90 - lat) * (Math.PI / 180);
                const theta = (lon + 180) * (Math.PI / 180);
                return new THREE.Vector3(-(R * Math.sin(phi) * Math.cos(theta)), R * Math.cos(phi), R * Math.sin(phi) * Math.sin(theta));
            }

            function animate() {
                requestAnimationFrame(animate);
                if(rotating && globeGroup) globeGroup.rotation.y += 0.0012;
                if(targetCamPos) camera.position.lerp(targetCamPos, 0.05);
                controls.update();
                renderer.render(scene, camera);
            }
            init();
        </script>
    </body>
    </html>
    """
    
    final_html = html_template.replace("__HEIGHT__", str(height)).replace("__INCIDENTS__", incidents_json)
    components.html(final_html, height=height)
